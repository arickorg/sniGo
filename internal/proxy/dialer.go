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
	tlsOK   bool
	err     error // TCP dial error
	tlsErr  error // TLS handshake error (only when TLS probing is enabled)
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
	// IPs that completed TCP+TLS but failed during the HTTP exchange. They
	// still pass the reachability probes, so without this feedback every retry
	// would pick the same IP again.
	failed map[string]map[string]time.Time
	mu     sync.Mutex
}

// failedIPCooldown mirrors the Rust core's short cooldown for routes that
// fail after a handshake.
const failedIPCooldown = 60 * time.Second

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
		failed:   map[string]map[string]time.Time{},
	}
}

// MarkFailed records an upstream IP that failed after the TLS handshake
// succeeded (for example a connection reset while reading the response). It
// also drops the cached plan/last-good entry for that IP so the next dial does
// not immediately reuse the same route.
func (d *Dialer) MarkFailed(host string, ip net.IP) {
	if ip == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failed == nil {
		d.failed = map[string]map[string]time.Time{}
	}
	byIP := d.failed[host]
	if byIP == nil {
		byIP = map[string]time.Time{}
		d.failed[host] = byIP
	}
	byIP[ip.String()] = time.Now()
	delete(d.plans, host)
	if d.lastGood[host].ip.Equal(ip) {
		delete(d.lastGood, host)
	}
}

// deprioritizeFailed moves recently failed IPs behind healthy candidates.
// They are kept as a last resort: a host with a single reachable IP must still
// be dialable after that IP had one bad response.
func (d *Dialer) deprioritizeFailed(host string, ips []net.IP) []net.IP {
	d.mu.Lock()
	bad := map[string]bool{}
	for ip, at := range d.failed[host] {
		if time.Since(at) < failedIPCooldown {
			bad[ip] = true
		} else {
			delete(d.failed[host], ip)
		}
	}
	d.mu.Unlock()
	if len(bad) == 0 || len(ips) < 2 {
		return ips
	}
	good := make([]net.IP, 0, len(ips))
	fallback := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if bad[ip.String()] {
			fallback = append(fallback, ip)
		} else {
			good = append(good, ip)
		}
	}
	return append(good, fallback...)
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
	// Candidates(catalog, doh, lastGood): pass arguments in the declared
	// order. Previously they were passed as (lastGood, catalog, doh), which
	// inverted the intended priority and put DoH results first.
	ips := catalog.Candidates(catalogIPs, resolved, lastGoodIPs, limit)
	if len(ips) == 0 {
		if err != nil {
			return nil, answer, err
		}
		return nil, answer, fmt.Errorf("no candidate IP for %s", host)
	}
	return ips, answer, nil
}

// probe measures TCP reachability for each candidate, then optionally probes
// TLS on a bounded subset of the fastest ones. TLS-reachable candidates are
// ranked first; TCP-only candidates remain as a fallback so the tunnel still
// works when no IP completes a pre-handshake (e.g. plain HTTP or a network
// that blocks all TLS). Blasting a ClientHello at every candidate can trip
// anti-abuse blocking, so the TLS fan-out is deliberately kept small.
func (d *Dialer) probe(ctx context.Context, ips []net.IP, port, tlsServerName string) []net.IP {
	_ = ctx // probe uses bounded DialTimeout so it cannot hang on a dead IP
	timeout := time.Duration(d.cfg.Advanced.IPTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	tlsTimeout := timeout * 2
	if tlsTimeout < 3*time.Second {
		tlsTimeout = 3 * time.Second
	}

	// Phase 1: cheap, concurrent TCP reachability for all candidates.
	tcpCh := make(chan candidateResult, len(ips))
	for _, ip := range ips {
		go func(ip net.IP) {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), timeout)
			latency := time.Since(start)
			if err == nil {
				_ = conn.Close()
			}
			tcpCh <- candidateResult{ip: ip, latency: latency, err: err}
		}(ip)
	}
	var reachable []candidateResult
	for range ips {
		res := <-tcpCh
		if res.err == nil {
			reachable = append(reachable, res)
		}
	}
	sort.Slice(reachable, func(i, j int) bool { return reachable[i].latency < reachable[j].latency })
	if tlsServerName == "" || len(reachable) == 0 {
		out := make([]net.IP, 0, len(reachable))
		for _, r := range reachable {
			out = append(out, r.ip)
		}
		return out
	}

	// Phase 2: TLS pre-handshake on at most maxTLSProbe fastest candidates.
	const maxTLSProbe = 4
	probeSet := reachable
	if len(probeSet) > maxTLSProbe {
		probeSet = probeSet[:maxTLSProbe]
	}
	results := make(chan candidateResult, len(probeSet))
	for _, base := range probeSet {
		go func(base candidateResult) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(base.ip.String(), port), timeout)
			res := candidateResult{ip: base.ip, latency: base.latency, err: err}
			if err == nil {
				// Identity is verified by the actual client later; this probe only
				// checks whether the IP can complete a TLS handshake at all.
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         tlsServerName,
					InsecureSkipVerify: true, // #nosec G402 - reachability probe only
					MinVersion:         tls.VersionTLS12,
				})
				_ = tlsConn.SetDeadline(time.Now().Add(tlsTimeout))
				if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
					res.tlsErr = handshakeErr
				} else {
					res.tlsOK = true
				}
				_ = conn.Close()
			}
			results <- res
		}(base)
	}
	var tlsGood []candidateResult
	for range probeSet {
		res := <-results
		if res.err == nil && res.tlsOK {
			tlsGood = append(tlsGood, res)
		}
	}
	sort.Slice(tlsGood, func(i, j int) bool { return tlsGood[i].latency < tlsGood[j].latency })

	seen := make(map[string]bool, len(tlsGood))
	out := make([]net.IP, 0, len(reachable))
	for _, r := range tlsGood {
		out = append(out, r.ip)
		seen[r.ip.String()] = true
	}
	for _, r := range reachable {
		if !seen[r.ip.String()] {
			out = append(out, r.ip)
		}
	}
	return out
}

// tlsPort reports whether a raw TCP tunnel to this port is expected to carry
// TLS. Only those ports get a pre-handshake probe; plain HTTP/SSH traffic must
// not have a ClientHello injected by the proxy.
func tlsPort(port string) bool {
	switch port {
	case "443", "8443":
		return true
	}
	return false
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
	sni := ""
	if tlsPort(port) {
		sni = host
	}
	ordered := d.deprioritizeFailed(host, d.probe(ctx, ips, port, sni))
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

// echConfigFor selects the ECHConfigList for an ECH attempt. "own" uses only
// the domain's own HTTPS RR; "shared" (the default, and what the Pixiv group
// uses) falls back to Cloudflare's shared config when the domain publishes no
// ECHConfig of its own. CF-fronted sites such as www.pixiv.net are in the
// latter category, so without the shared fallback every ECH attempt is
// skipped and the route degrades to a plain direct handshake.
func echConfigFor(attempt config.RouteAttempt, own []byte, shared func() []byte) []byte {
	if len(own) > 0 {
		return own
	}
	if attempt.Ech == "own" || shared == nil {
		return nil
	}
	return shared()
}

// buildTLSConfig builds the upstream TLS config. crypto/tls requires
// MinVersion >= TLS 1.3 whenever EncryptedClientHelloConfigList is set;
// leaving it at TLS 1.2 makes every ECH attempt fail before a single byte is
// sent. The ECHConfigList's public name is used for the outer SNI by the
// standard library, so normal certificate verification against the real
// hostname still applies. Fake SNI changes only the outer SNI and therefore
// needs a manual certificate check against the original hostname.
func buildTLSConfig(host, serverName string, ech []byte) *tls.Config {
	minVersion := uint16(tls.VersionTLS12)
	if len(ech) > 0 {
		minVersion = tls.VersionTLS13
	}
	cfg := &tls.Config{
		ServerName:                     serverName,
		MinVersion:                     minVersion,
		EncryptedClientHelloConfigList: ech,
		NextProtos:                     []string{"h2", "http/1.1"},
	}
	if serverName != host {
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
			_, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
			return err
		}
	}
	return cfg
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
	ordered := d.probe(ctx, ips, port, "")
	if len(ordered) == 0 {
		// Probe measures TCP only; keep candidates when the network blocks
		// DialTimeout but allows a real TLS dial.
		ordered = ips
	}
	ordered = d.deprioritizeFailed(host, ordered)
	if len(attempts) == 0 {
		attempts = config.AutoRoute().Attempts
	}
	// Reuse the strategy that worked last time. candidate() already ranks the
	// last-good IP first, but without this the ECH/SNI/direct attempts are
	// replayed from scratch on every new connection, which wastes a shared ECH
	// lookup and a handshake on routes where a later strategy is the winner.
	if _, cachedMode, ok := d.CachedPlan(host); ok && cachedMode != "" {
		attempts = preferAttempt(attempts, cachedMode)
	}
	var lastErr error
	for _, ip := range ordered {
		for _, attempt := range attempts {
			var echConfig []byte
			switch attempt.Mode {
			case "ech":
				var sharedECH func() []byte
				if d.resolver != nil {
					sharedECH = func() []byte {
						shared, err := d.resolver.SharedECH(ctx)
						if err != nil {
							lastErr = err
							return nil
						}
						return shared
					}
				}
				echConfig = echConfigFor(attempt, answer.ECH, sharedECH)
				if len(echConfig) == 0 {
					if lastErr == nil {
						lastErr = fmt.Errorf("no ECHConfig for %s", host)
					}
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
			tlsCfg := buildTLSConfig(host, serverName, echConfig)
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

// preferAttempt moves the first attempt matching mode to the front while
// preserving the order of all other attempts. Returning the original slice
// when there is nothing to move keeps the route policy untouched.
func preferAttempt(attempts []config.RouteAttempt, mode string) []config.RouteAttempt {
	if mode == "" {
		return attempts
	}
	for i, a := range attempts {
		if a.Mode != mode {
			continue
		}
		if i == 0 {
			return attempts
		}
		out := make([]config.RouteAttempt, 0, len(attempts))
		out = append(out, a)
		out = append(out, attempts[:i]...)
		out = append(out, attempts[i+1:]...)
		return out
	}
	return attempts
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
