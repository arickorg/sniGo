package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
	"github.com/arick/hakimi-gop/internal/domain"
	"github.com/arick/hakimi-gop/internal/relay"
)

// forward handles plain proxy requests in absolute-form (http://host/path)
// and writes them back to the raw connection.
func (s *Server) forward(bw *bufio.Writer, req *http.Request) {
	rw := &bufferedResponseWriter{bw: bw}
	s.forwardHTTP(rw, req, "")
	_ = bw.Flush()
}

// forwardHTTP handles a request that already carries a scheme (MITM or plain).
func (s *Server) forwardHTTP(rw http.ResponseWriter, req *http.Request, mitmHost string) {
	ctx := req.Context()
	host := req.URL.Hostname()
	if host == "" {
		host = domain.HostOf(req.Host)
	}
	if host == "" && mitmHost != "" {
		host = mitmHost
	}
	port := req.URL.Port()
	if port == "" {
		if req.URL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	pathAndQuery := req.URL.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	plan := relay.Plan(s.cfg, req.Method, host, pathAndQuery, req.Header, s.health)
	if plan != nil {
		timeoutCtx, cancel := context.WithTimeout(ctx, plan.Timeout)
		resp, err := relay.Execute(timeoutCtx, plan, s.worker, s.localRelayHost(), nil)
		cancel()
		if err == nil && resp.Status < 400 {
			s.copyJSResponse(rw, resp)
			s.health.NoteSuccess(plan.RuleID)
			return
		}
		if err == nil && relay.ShouldFallback(resp.Status) {
			s.health.NoteFailure(plan.RuleID)
		} else if err != nil {
			s.health.NoteFailure(plan.RuleID)
		}
		if !plan.FallbackDirect {
			if err != nil {
				http.Error(rw, "relay failed: "+err.Error(), http.StatusBadGateway)
			} else {
				rw.WriteHeader(resp.Status)
			}
			return
		}
	}

	resp, err := s.sendDirect(ctx, req, host, port, mitmHost)
	if err != nil {
		http.Error(rw, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	s.copyResponse(rw, resp, false)
}

func (s *Server) localRelayHost() string {
	if s.Addr() == nil {
		return ""
	}
	return domain.HostOf(s.Addr().String())
}

// sendDirect forwards a request upstream. A TLS handshake can succeed and the
// upstream can still reset the connection while the HTTP response is being
// read (typical of SNI-filtered hosts). Those failures are retried on the next
// candidate IP; non-idempotent methods are never replayed.
func (s *Server) sendDirect(ctx context.Context, req *http.Request, host, port, mitmHost string) (*http.Response, error) {
	targetURL := *req.URL
	targetURL.Scheme = req.URL.Scheme
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = net.JoinHostPort(host, port)
	}

	maxAttempts := 3
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		maxAttempts = 1 // never replay a request that may have side effects
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var usedIP net.IP
		transport := &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return s.dialer.DialTCP(ctx, h, p)
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				h, p, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				conn, ip, _, err := s.dialer.DialTLS(ctx, h, p, s.dialerMode(h))
				if err == nil {
					usedIP = ip
				}
				return conn, err
			},
			TLSHandshakeTimeout:   12 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			DisableCompression:    true,
			MaxIdleConns:          64,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		}

		urlCopy := targetURL
		outReq := req.Clone(ctx)
		outReq.URL = &urlCopy
		outReq.RequestURI = ""
		outReq.Host = host
		stripHopHeaders(outReq.Header)
		outReq.Header.Set("Host", net.JoinHostPort(host, port))

		client := &http.Client{Transport: transport, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp, err := client.Do(outReq)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		transport.CloseIdleConnections()
		if usedIP == nil {
			break // failed before any upstream connection was established
		}
		s.dialer.MarkFailed(host, usedIP)
	}
	return nil, lastErr
}

func (s *Server) dialerMode(host string) []config.RouteAttempt {
	g, r, ok := s.cfg.Match(host)
	if !ok {
		return config.AutoRoute().Attempts
	}
	return s.cfg.RouteFor(g, r).Attempts
}

func (s *Server) copyJSResponse(rw http.ResponseWriter, resp relay.JSResponse) {
	for k, values := range resp.Headers {
		if isHopHeader(k) {
			continue
		}
		for _, v := range values {
			rw.Header().Add(k, v)
		}
	}
	relay.StripResponseCookies(rw.Header())
	rw.WriteHeader(resp.Status)
	_, _ = rw.Write(resp.Body)
}

func (s *Server) copyResponse(rw http.ResponseWriter, resp *http.Response, thirdParty bool) {
	defer resp.Body.Close()
	for k, values := range resp.Header {
		if isHopHeader(k) {
			continue
		}
		for _, v := range values {
			rw.Header().Add(k, v)
		}
	}
	if thirdParty {
		relay.StripResponseCookies(rw.Header())
	}
	rw.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(rw, resp.Body); err != nil {
		return
	}
}

func stripHopHeaders(h http.Header) {
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(name)
	}
	h.Del("Cookie") // third-party relay must not receive credentials
	h.Del("Authorization")
}

func isHopHeader(name string) bool {
	switch strings.ToLower(name) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
