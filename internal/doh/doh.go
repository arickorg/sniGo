// Package doh implements DoH resolution with primary/fallback/custom endpoints,
// answer caching, stale-while-revalidate and a synthetic HTTPS RR (ECH) lookup.
package doh

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type Answer struct {
	Addresses []net.IP
	ECH       []byte // serialized ECHConfigList from HTTPS RR, if any
	Source    string
	TTL       time.Duration
	Cached    bool
}

type cacheEntry struct {
	answer Answer
	at     time.Time
}

type Resolver struct {
	mu       sync.Mutex
	client   *http.Client
	endpoint []string
	cache    map[string]cacheEntry
	health   map[string]bool
}

func New(primary, fallback string, custom []string) *Resolver {
	endpoints := make([]string, 0, 2+len(custom))
	for _, e := range append(append([]string{primary, fallback}, custom...), "https://doh.pub/dns-query", "https://cloudflare-dns.com/dns-query") {
		if e != "" {
			endpoints = append(endpoints, e)
		}
	}
	// DoH endpoints are expected to be reached directly. Ignoring the ambient
	// HTTP(S)_PROXY avoids routing domestic resolvers back out through an
	// upstream proxy that may not be able to reach them.
	transport := &http.Transport{Proxy: nil}
	return &Resolver{
		client:   &http.Client{Timeout: 6 * time.Second, Transport: transport},
		endpoint: endpoints,
		cache:    map[string]cacheEntry{},
		health:   map[string]bool{},
	}
}

func (r *Resolver) Endpoints() []string { return append([]string(nil), r.endpoint...) }

type dohJSON struct {
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
	Status int `json:"Status"`
}

// Resolve queries A and AAAA, merging results from multiple endpoints. A stale
// cached answer is returned immediately while a refresh runs in the background.
func (r *Resolver) Resolve(ctx context.Context, host string) (Answer, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	key := "A:" + host

	r.mu.Lock()
	if cached, ok := r.cache[key]; ok {
		age := time.Since(cached.at)
		if age < cached.answer.TTL {
			out := cached.answer
			out.Cached = true
			r.mu.Unlock()
			return out, nil
		}
		if age < cached.answer.TTL+12*time.Hour {
			stale := cached.answer
			stale.Cached = true
			r.mu.Unlock()
			go func() { _, _ = r.refresh(context.Background(), host) }()
			return stale, nil
		}
	}
	r.mu.Unlock()

	answer, err := r.refresh(ctx, host)
	if err == nil && len(answer.Addresses) > 0 {
		return answer, nil
	}
	// System resolver as the last resort: DoH is an accelerator, not a hard
	// dependency, and local/test domains must still work.
	ips, sysErr := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if sysErr == nil && len(ips) > 0 {
		return Answer{Addresses: ips, Source: "system", TTL: 60 * time.Second}, nil
	}
	if err != nil {
		return Answer{}, err
	}
	if errors.Is(sysErr, context.Canceled) {
		return Answer{}, sysErr
	}
	return Answer{}, fmt.Errorf("no addresses for %s", host)
}

func (r *Resolver) refresh(ctx context.Context, host string) (Answer, error) {
	endpoints := r.orderedEndpoints()
	type result struct {
		ans Answer
		err error
	}
	ch := make(chan result, len(endpoints)*2)
	launch := func(ep, qtype string) {
		go func() {
			ans, err := r.query(ctx, ep, host, qtype)
			ch <- result{ans, err}
		}()
	}
	for _, ep := range endpoints {
		launch(ep, "A")
		launch(ep, "AAAA")
	}

	merged := Answer{Source: "doh"}
	var firstErr error
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for range endpoints {
		if len(merged.Addresses) > 0 && merged.ECH != nil {
			break
		}
		select {
		case res := <-ch:
			if res.err != nil {
				if firstErr == nil {
					firstErr = res.err
				}
				continue
			}
			for _, ip := range res.ans.Addresses {
				k := ip.String()
				if !seen[k] {
					seen[k] = true
					merged.Addresses = append(merged.Addresses, ip)
				}
			}
			if merged.ECH == nil {
				merged.ECH = res.ans.ECH
			}
			if res.ans.Source != "" {
				merged.Source = res.ans.Source
			}
			if res.ans.TTL > merged.TTL {
				merged.TTL = res.ans.TTL
			}
		case <-deadline:
			goto done
		case <-ctx.Done():
			return merged, ctx.Err()
		}
	}
done:
	if len(merged.Addresses) == 0 {
		return merged, firstErr
	}
	if merged.TTL < 30*time.Second {
		merged.TTL = 30 * time.Second
	}
	r.mu.Lock()
	r.cache["A:"+host] = cacheEntry{answer: merged, at: time.Now()}
	r.mu.Unlock()
	return merged, nil
}

func (r *Resolver) orderedEndpoints() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]string(nil), r.endpoint...)
	sort.SliceStable(out, func(i, j int) bool {
		hi, hj := r.health[out[i]], r.health[out[j]]
		return hi && !hj
	})
	return out
}

func (r *Resolver) query(ctx context.Context, endpoint, host, qtype string) (Answer, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return Answer{}, err
	}
	q := u.Query()
	q.Set("name", host)
	q.Set("type", qtype)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Answer{}, err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := r.client.Do(req)
	if err != nil {
		r.mark(endpoint, false)
		return Answer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		r.mark(endpoint, false)
		return Answer{}, fmt.Errorf("%s returned %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Answer{}, err
	}
	var data dohJSON
	if err := json.Unmarshal(body, &data); err != nil {
		return Answer{}, err
	}
	r.mark(endpoint, true)
	out := Answer{Source: sourceOf(endpoint)}
	for _, a := range data.Answer {
		ttl := time.Duration(a.TTL) * time.Second
		if out.TTL == 0 || ttl < out.TTL {
			out.TTL = ttl
		}
		switch a.Type {
		case 1, 28:
			if ip := net.ParseIP(strings.TrimSuffix(a.Data, ".")); ip != nil {
				out.Addresses = append(out.Addresses, ip)
			}
		case 65: // HTTPS RR
			if ech := parseECHFromHTTPS(a.Data); ech != nil {
				out.ECH = ech
			}
		}
	}
	if data.Status == 0 && len(data.Answer) == 0 {
		out.TTL = 5 * time.Minute
	}
	return out, nil
}

func (r *Resolver) mark(endpoint string, healthy bool) {
	r.mu.Lock()
	r.health[endpoint] = healthy
	r.mu.Unlock()
}

func sourceOf(endpoint string) string {
	s := strings.ToLower(endpoint)
	switch {
	case strings.Contains(s, "cleanbrowsing"):
		return "primary"
	case strings.Contains(s, "applied-privacy"):
		return "fallback"
	case strings.Contains(s, "cloudflare"):
		return "catalog"
	default:
		return "custom"
	}
}

// parseECHFromHTTPS decodes an RFC 9460 presentation-form HTTPS record and
// extracts parameter 5 (ech), whose value is a base64 ECHConfigList.
func parseECHFromHTTPS(record string) []byte {
	fields := strings.Fields(record)
	for i, f := range fields {
		if strings.EqualFold(f, "ech=") && i+1 < len(fields) {
			raw := fields[i+1]
			if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
				return decoded
			}
		}
		if strings.HasPrefix(strings.ToLower(f), "ech=") {
			raw := f[4:]
			if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
				raw = raw[1 : len(raw)-1]
			}
			if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) > 3 {
				// HTTPS RR ech values in DoH JSON are sometimes wrapped with a
				// two-byte key; ECHConfigList itself starts with 0xfe 0x0d.
				if binary.BigEndian.Uint16(decoded[:2]) == 0xfe0d {
					return decoded
				}
				for n := 2; n+4 < len(decoded); n++ {
					if decoded[n] == 0xfe && decoded[n+1] == 0x0d {
						return decoded[n:]
					}
				}
			}
		}
	}
	return nil
}

// RefreshCatalog takes a list of DoH endpoint URLs from the remote catalog.
func (r *Resolver) RefreshCatalog(endpoints []string) {
	if len(endpoints) == 0 {
		return
	}
	newList := append([]string{}, endpoints...)
	for _, ep := range r.endpoint[:2] {
		found := false
		for _, existing := range newList {
			if existing == ep {
				found = true
				break
			}
		}
		if !found {
			newList = append(newList, ep)
		}
	}
	r.mu.Lock()
	r.endpoint = newList
	r.mu.Unlock()
}
