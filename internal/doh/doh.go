// Package doh implements DoH resolution with primary/fallback/custom endpoints,
// answer caching, stale-while-revalidate and a synthetic HTTPS RR (ECH) lookup.
package doh

import (
	"context"
	"encoding/base64"
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

// SharedECHDomain publishes Cloudflare's shared ECHConfigList. CF-fronted
// domains that do not publish their own ECHConfig (www.pixiv.net is the
// canonical example) can still be reached with ECH using this config. This
// mirrors the Rust core's "shared ECH" fallback used by the Pixiv group.
const SharedECHDomain = "cloudflare-ech.com"

const sharedECHTTL = 30 * time.Minute

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

// SharedECH returns Cloudflare's shared ECHConfigList, cached for 30 minutes.
// An expired entry is still served when the live lookup fails, matching the
// Rust core's stale-while-revalidate behaviour for ECH configs.
func (r *Resolver) SharedECH(ctx context.Context) ([]byte, error) {
	return r.echConfig(ctx, SharedECHDomain)
}

// echConfig returns the ECHConfigList published in host's HTTPS RR.
func (r *Resolver) echConfig(ctx context.Context, host string) ([]byte, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	key := "ECH:" + host

	r.mu.Lock()
	if cached, ok := r.cache[key]; ok && len(cached.answer.ECH) > 0 {
		age := time.Since(cached.at)
		fresh := age < sharedECHTTL
		ech := append([]byte(nil), cached.answer.ECH...)
		r.mu.Unlock()
		if fresh {
			return ech, nil
		}
		// Refresh off the critical path; keep serving the stale config.
		go func() {
			fresh, err := r.queryECH(context.Background(), host, r.echEndpoints())
			if err != nil || len(fresh) == 0 {
				return
			}
			r.mu.Lock()
			r.cache[key] = cacheEntry{
				answer: Answer{ECH: fresh, Source: "doh", TTL: sharedECHTTL},
				at:     time.Now(),
			}
			r.mu.Unlock()
		}()
		return ech, nil
	}
	r.mu.Unlock()

	ech, err := r.queryECH(ctx, host, r.echEndpoints())
	if err == nil && len(ech) > 0 {
		r.mu.Lock()
		r.cache[key] = cacheEntry{
			answer: Answer{ECH: ech, Source: "doh", TTL: sharedECHTTL},
			at:     time.Now(),
		}
		r.mu.Unlock()
		return ech, nil
	}
	if err == nil {
		err = fmt.Errorf("no ECHConfig in HTTPS RR for %s", host)
	}
	return nil, err
}

// echEndpoints is the DoH pool used for HTTPS RR lookups. AliDNS is appended
// as an extra fallback because it reliably serves cloudflare-ech.com even
// when the primary pool does not (the same fallback the Rust core uses).
func (r *Resolver) echEndpoints() []string {
	candidates := append(r.orderedEndpoints(), "https://dns.alidns.com/dns-query")
	seen := make(map[string]bool, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, ep := range candidates {
		if ep != "" && !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

// queryECH races the HTTPS RR query across all endpoints and returns the
// first usable ECHConfigList. query() already falls back from the JSON API to
// RFC 8484 wire format, which is essential here: doh.pub and AliDNS both
// reject type=HTTPS over JSON but answer it correctly in wire format.
func (r *Resolver) queryECH(ctx context.Context, host string, endpoints []string) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no DoH endpoints configured")
	}
	type result struct {
		ech []byte
		err error
	}
	ch := make(chan result, len(endpoints))
	for _, ep := range endpoints {
		go func(ep string) {
			ans, err := r.query(ctx, ep, host, "HTTPS")
			if err == nil && len(ans.ECH) > 0 {
				ans.ECH = normalizeECHConfigList(ans.ECH)
			}
			ch <- result{ech: ans.ECH, err: err}
		}(ep)
	}
	var firstErr error
	for range endpoints {
		res := <-ch
		if res.err == nil && len(res.ech) > 0 {
			return res.ech, nil
		}
		if firstErr == nil && res.err != nil {
			firstErr = res.err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("no ECHConfig in HTTPS RR for %s", host)
}

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
	total := len(endpoints) * 3
	ch := make(chan result, total)
	launch := func(ep, qtype string) {
		go func() {
			ans, err := r.query(ctx, ep, host, qtype)
			ch <- result{ans, err}
		}()
	}
	for _, ep := range endpoints {
		launch(ep, "A")
		launch(ep, "AAAA")
		launch(ep, "HTTPS") // RFC 9460 HTTPS RR carries the ECHConfigList
	}

	merged := Answer{Source: "doh"}
	var firstErr error
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for range total {
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

// query tries the JSON API first, then falls back to RFC 8484 wire format.
// Many resolvers (e.g. cloudflare-dns.com) only accept application/dns-message,
// and some JSON APIs reject type=HTTPS while answering the same query in wire
// format. ECHConfig lives in the HTTPS RR, so the fallback is essential.
func (r *Resolver) query(ctx context.Context, endpoint, host, qtype string) (Answer, error) {
	jsonAns, jsonErr := r.queryJSON(ctx, endpoint, host, qtype)
	needWire := jsonErr != nil || (qtype == "HTTPS" && jsonAns.ECH == nil)
	if !needWire {
		return jsonAns, nil
	}
	wireAns, wireErr := r.queryWire(ctx, endpoint, host, qtype)
	if wireErr == nil {
		merged := jsonAns
		if len(merged.Addresses) == 0 {
			merged.Addresses = wireAns.Addresses
		}
		if merged.ECH == nil {
			merged.ECH = wireAns.ECH
		}
		if merged.Source == "" {
			merged.Source = wireAns.Source
		}
		if merged.TTL == 0 {
			merged.TTL = wireAns.TTL
		}
		if len(merged.Addresses) > 0 || merged.ECH != nil {
			r.mark(endpoint, true)
			return merged, nil
		}
	}
	if jsonErr == nil {
		return jsonAns, nil
	}
	if wireErr != nil {
		return Answer{}, wireErr
	}
	return Answer{}, jsonErr
}

func (r *Resolver) queryWire(ctx context.Context, endpoint, host, qtype string) (Answer, error) {
	qt := wireTypeA
	switch qtype {
	case "AAAA":
		qt = wireTypeAAAA
	case "HTTPS":
		qt = wireTypeHTTPS
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return Answer{}, err
	}
	q := u.Query()
	q.Set("dns", base64.RawURLEncoding.EncodeToString(buildWireQuery(host, qt)))
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Answer{}, err
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		r.mark(endpoint, false)
		return Answer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Answer{}, fmt.Errorf("%s wire returned %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Answer{}, err
	}
	ips, ech := parseWireAnswer(body, host)
	return Answer{Addresses: ips, ECH: ech, Source: sourceOf(endpoint), TTL: 5 * time.Minute}, nil
}

func (r *Resolver) queryJSON(ctx context.Context, endpoint, host, qtype string) (Answer, error) {
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
// extracts parameter 5 (ech), whose value is a base64 ECHConfigList. The
// result is always a complete ECHConfigList with the uint16 length prefix
// that crypto/tls requires.
func parseECHFromHTTPS(record string) []byte {
	fields := strings.Fields(record)
	for i, f := range fields {
		var raw string
		switch {
		case strings.EqualFold(f, "ech=") && i+1 < len(fields):
			raw = fields[i+1]
		case strings.HasPrefix(strings.ToLower(f), "ech="):
			raw = f[4:]
		default:
			continue
		}
		raw = strings.Trim(raw, `"`)
		if raw == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(raw)
		}
		if err != nil {
			continue
		}
		if cfg := normalizeECHConfigList(decoded); cfg != nil {
			return cfg
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
