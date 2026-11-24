package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/arick/hakimi-gop/internal/catalog"
	"github.com/arick/hakimi-gop/internal/config"
	"github.com/arick/hakimi-gop/internal/doh"
	"github.com/arick/hakimi-gop/internal/domain"
)

type dialResult struct {
	conn    net.Conn
	ip      net.IP
	mode    string
	latency time.Duration
}

type candidateResult struct {
	ip      net.IP
	latency time.Duration
	err     error
}

type plan struct {
	conn net.Conn
	ip   net.IP
	mode string
}

// Dialer resolves host, probes candidate IPs and tries direct/ECH/fake-SNI in
// the order given by the matched route policy. Successful plans are cached.
type Dialer struct {
	cfg      *config.AppConfig
	resolver *doh.Resolver
	catalog  *catalog.Store
	lastGood map[string]lastGoodEntry
	plans    map[string]planCacheEntry
	mu       sync.Mutex
}

type lastGoodEntry struct {
	ip net.IP
	at time.Time
}

type planCacheEntry struct {
	ip      net.IP
	mode    string
	expires time.Time
}

func NewDialer(cfg *config.AppConfig, resolver *doh.Resolver, store *catalog.Store) *Dialer {
	return &Dialer{
		cfg: cfg, resolver: resolver, catalog: store,
		lastGood: map[string]lastGoodEntry{},
		plans:    map[string]planCacheEntry{},
	}
}

func (d *Dialer) modeAttempts(host string) []config.RouteAttempt {
	g, r, ok := d.cfg.Match(host)
	if !ok {
		return config.AutoRoute().Attempts
	}
	return d.cfg.RouteFor(g, r).Attempts
}

func (d *Dialer) candidates(ctx context.Context, host string) ([]net.IP, doh.Answer, error) {
	var answer doh.Answer
	if domain.IsIPLiteral(host) {
		return []net.IP{net.ParseIP(domain.HostOf(host))}, answer, nil
	}
	answer, err := d.resolver.Resolve(ctx, host)
	var resolved []net.IP
	if err == nil {
		resolved = answer.Addresses
	}
	var catalogIPs []net.IP
	if d.catalog != nil {
		catalogIPs = d.catalog.Get(host)
	}
	d.mu.Lock()
	lg := d.lastGood[host]
	d.mu.Unlock()
	var lastGoodIPs []net.IP
	if time.Since(lg.at) < time.Duration(d.cfg.Advanced.LastGoodDays)*24*time.Hour && lg.ip != nil {
		lastGoodIPs = []net.IP{lg.ip}
	}
	limit := d.cfg.Advanced.MaxCandidatesPerDomain
	if limit <= 0 {
		limit = 8
	}
	ips := catalog.Candidates(lastGoodIPs, catalogIPs, resolved, limit)
	if len(ips) == 0 {
		if err != nil {
			return nil, answer, err
		}
		return nil, answer, fmt.Errorf("no candidate IP for %s", host)
	}
	return ips, answer, nil
}

func (d *Dialer) probe(ctx context.Context, ips []net.IP, port string) []net.IP {
	timeout := time.Duration(d.cfg.Advanced.IPTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	results := make(chan candidateResult, len(ips))
	for _, ip := range ips {
		go func(ip net.IP) {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), timeout)
			latency := time.Since(start)
			if err == nil {
				_ = conn.Close()
			}
			results <- candidateResult{ip: ip, latency: latency, err: err}
		}(ip)
	}
	var good []candidateResult
	for range ips {
		res := <-results
		if res.err == nil {
			good = append(good, res)
		}
	}
	sort.Slice(good, func(i, j int) bool { return good[i].latency < good[j].latency })
	out := make([]net.IP, 0, len(good))
	for _, g := range good {
		out = append(out, g.ip)
	}
	return out
}

// DialTCP connects to host:port without TLS (raw CONNECT tunnel / plain proxy).
func (d *Dialer) DialTCP(ctx context.Context, host, port string) (net.Conn, error) {
	if domain.IsIPLiteral(host) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	ips, _, err := d.candidates(ctx, host)
	if err != nil {
		return nil, err
	}
	ordered := d.probe(ctx, ips, port)
	if len(ordered) == 0 {
		return nil, fmt.Errorf("all candidate IPs failed for %s", host)
	}
	var dialErr error
	for _, ip := range ordered {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			d.remember(host, ip)
			return conn, nil
		}
		dialErr = err
	}
	return nil, dialErr
}

// DialTLS performs the selected TLS strategy and returns a verified connection.
// Verification always uses the ORIGINAL hostname, even for fake SNI or an IP.
func (d *Dialer) DialTLS(ctx context.Context, host, port string, attempts []config.RouteAttempt) (*tls.Conn, net.IP, string, error) {
	if domain.IsIPLiteral(host) {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		if err != nil {
			return nil, nil, "", err
		}
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, nil, "", err
		}
		return tlsConn, net.ParseIP(host), "direct", nil
	}
	ips, answer, err := d.candidates(ctx, host)
	if err != nil {
		return nil, nil, "", err
	}
	ordered := d.probe(ctx, ips, port)
	if len(ordered) == 0 {
		// Probe measures TCP only; keep candidates when the network blocks
		// DialTimeout but allows a real TLS dial.
		ordered = ips
	}
	if len(attempts) == 0 {
		attempts = config.AutoRoute().Attempts
	}
	var lastErr error
	for _, ip := range ordered {
		for _, attempt := range attempts {
			var echConfig []byte
			switch attempt.Mode {
			case "ech":
				if attempt.Ech == "own" {
					echConfig = answer.ECH
				}
				if len(echConfig) == 0 {
					lastErr = fmt.Errorf("no ECHConfig for %s", host)
					continue
				}
			}
			conn, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if dialErr != nil {
				lastErr = dialErr
				continue
			}
			serverName := host
			if attempt.Mode == "sni" {
				candidates := attempt.Sni
				if len(candidates) == 0 {
					candidates = d.cfg.Advanced.FakeSNICandidates
				}
				for _, sni := range candidates {
					if sni != "" {
						serverName = domain.Normalize(sni)
						break
					}
				}
			}
			tlsCfg := &tls.Config{
				ServerName:                     serverName,
				MinVersion:                     tls.VersionTLS12,
				EncryptedClientHelloConfigList: echConfig,
				NextProtos:                     []string{"h2", "http/1.1"},
			}
			// Verify the real domain even when the SNI is disguised.
			verifyName := host
			tlsCfg.InsecureSkipVerify = serverName != host || len(echConfig) > 0
			if tlsCfg.InsecureSkipVerify {
				tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return fmt.Errorf("no certificate from %s", host)
					}
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					roots, err := x509.SystemCertPool()
					if err != nil {
						return err
					}
					if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: verifyName}); err != nil {
						return err
					}
					return nil
				}
			}
			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				lastErr = err
				continue
			}
			d.remember(host, ip)
			d.cachePlan(host, ip, attempt.Mode)
			return tlsConn, ip, attempt.Mode, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable route for %s", host)
	}
	return nil, nil, "", lastErr
}

func (d *Dialer) remember(host string, ip net.IP) {
	d.mu.Lock()
	d.lastGood[host] = lastGoodEntry{ip: ip, at: time.Now()}
	d.mu.Unlock()
}

func (d *Dialer) cachePlan(host string, ip net.IP, mode string) {
	d.mu.Lock()
	d.plans[host] = planCacheEntry{ip: ip, mode: mode, expires: time.Now().Add(time.Duration(d.cfg.Advanced.PlanCacheSecs) * time.Second)}
	d.mu.Unlock()
}

func (d *Dialer) CachedPlan(host string) (net.IP, string, bool) {
	d.mu.Lock()
	p := d.plans[host]
	d.mu.Unlock()
	if p.expires.After(time.Now()) {
		return p.ip, p.mode, true
	}
	return nil, "", false
}
