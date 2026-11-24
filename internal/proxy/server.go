// Package proxy serves the local HTTP proxy: absolute-form forwarding,
// CONNECT tunnels, MITM for enabled groups, and local control endpoints.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arick/hakimi-gop/internal/ca"
	"github.com/arick/hakimi-gop/internal/config"
	"github.com/arick/hakimi-gop/internal/domain"
	"github.com/arick/hakimi-gop/internal/relay"
)

type Server struct {
	cfg       *config.AppConfig
	dialer    *Dialer
	authority *ca.Authority
	health    *relay.Health
	worker    *relay.JSWorker
	paused    *atomic.Bool
	onStop    func()
	onStatus  func() []byte

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	pac      string
}

type Options struct {
	Config    *config.AppConfig
	Dialer    *Dialer
	Authority *ca.Authority
	Worker    *relay.JSWorker
	Paused    *atomic.Bool
	OnStop    func()
	OnStatus  func() []byte
}

func New(opts Options) *Server {
	return &Server{
		cfg: opts.Config, dialer: opts.Dialer, authority: opts.Authority,
		worker: opts.Worker, paused: opts.Paused, onStop: opts.OnStop, onStatus: opts.OnStatus,
		health: relay.NewHealth(), conns: map[net.Conn]struct{}{},
	}
}

func (s *Server) SetPAC(script string) {
	s.mu.Lock()
	s.pac = script
	s.mu.Unlock()
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Listen(bind string, port int) (net.Addr, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	go s.accept(ln)
	return ln.Addr(), nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.mu.Lock()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) accept(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.serveConn(conn)
		}()
	}
}

func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Time{})
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if s.handleRequest(conn, bw, req) {
			return // connection handed off (tunnel or MITM)
		}
		if err := bw.Flush(); err != nil {
			return
		}
		if req.Close || strings.EqualFold(req.Header.Get("Connection"), "close") {
			return
		}
	}
}

// handleRequest returns true when the connection is handed off and the loop
// must stop reading from it.
func (s *Server) handleRequest(conn net.Conn, bw *bufio.Writer, req *http.Request) bool {
	path := req.URL.Path
	if path == "/proxy.pac" || strings.HasPrefix(path, "/hakimi/") || strings.HasPrefix(path, "/pximg") {
		s.localResponse(bw, req)
		return false
	}
	if req.Method == http.MethodConnect {
		s.handleConnect(conn, bw, req)
		return true
	}
	s.forward(bw, req)
	return false
}

func (s *Server) localResponse(bw *bufio.Writer, req *http.Request) {
	write := func(status int, contentType string, body []byte) {
		fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			status, http.StatusText(status), contentType, len(body))
		_, _ = bw.Write(body)
		_ = bw.Flush()
	}
	switch req.URL.Path {
	case "/proxy.pac":
		s.mu.Lock()
		script := s.pac
		s.mu.Unlock()
		write(200, "application/x-ns-proxy-autoconfig", []byte(script))
	case "/hakimi/health":
		write(200, "text/plain", []byte("ok"))
	case "/hakimi/status":
		status := []byte(`{"app":"hakimi-gop","running":true}`)
		if s.onStatus != nil {
			status = s.onStatus()
		}
		write(200, "application/json", status)
	case "/hakimi/pause":
		if req.Method == http.MethodPost && req.Header.Get("x-hakimi-control") == "1" {
			s.paused.Store(true)
		}
		write(200, "text/plain", []byte("paused"))
	case "/hakimi/resume":
		if req.Method == http.MethodPost && req.Header.Get("x-hakimi-control") == "1" {
			s.paused.Store(false)
		}
		write(200, "text/plain", []byte("resumed"))
	case "/hakimi/stop":
		if req.Method == http.MethodPost && req.Header.Get("x-hakimi-control") == "1" {
			write(200, "application/json", []byte(`{"stopping":true}`))
			_ = bw.Flush()
			if s.onStop != nil {
				go s.onStop()
			}
			return
		}
		write(405, "text/plain", []byte("method not allowed"))
	default:
		if strings.HasPrefix(req.URL.Path, "/pximg") && s.worker != nil {
			s.worker.ServeHTTP(&bufferedResponseWriter{bw: bw}, req)
			_ = bw.Flush()
			return
		}
		write(404, "text/plain", []byte("not found"))
	}
}

// bufferedResponseWriter adapts goja worker output to the raw buffered conn.
type bufferedResponseWriter struct {
	bw     *bufio.Writer
	header http.Header
	status int
}

func (w *bufferedResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *bufferedResponseWriter) WriteHeader(status int) { w.status = status }

func (w *bufferedResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	fmt.Fprintf(w.bw, "HTTP/1.1 %d %s\r\n", w.status, http.StatusText(w.status))
	for k, values := range w.header {
		for _, v := range values {
			fmt.Fprintf(w.bw, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(w.bw, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	return w.bw.Write(body)
}

func (s *Server) handleConnect(conn net.Conn, bw *bufio.Writer, req *http.Request) {
	host, port, err := splitAuthority(req.Host)
	if err != nil {
		writeSimple(bw, 400, "bad CONNECT authority")
		return
	}
	ctx := req.Context()

	upstream, _, shouldMITM := s.decideMITM(host)
	if shouldMITM {
		cfg, err := s.authority.TLSConfig(host)
		if err != nil {
			writeSimple(bw, 502, "certificate error: "+err.Error())
			return
		}
		writeSimple(bw, 200, "") // tunnel established
		_ = bw.Flush()
		tlsConn := tls.Server(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		s.serveMITM(tlsConn, host, cfg.NextProtos)
		return
	}

	target, err := s.dialer.DialTCP(ctx, host, port)
	if err != nil {
		writeSimple(bw, 502, "upstream dial failed: "+err.Error())
		return
	}
	writeSimple(bw, 200, "")
	_ = bw.Flush()
	bridge(conn, target)
	_ = upstream
}

func (s *Server) decideMITM(host string) (string, string, bool) {
	if domain.IsIPLiteral(host) || s.paused.Load() || s.authority == nil || !s.authority.Trusted() {
		return "", "", false
	}
	g, r, ok := s.cfg.Match(host)
	if !ok || s.cfg.RouteFor(g, r).DirectOnly() {
		return "", "", false
	}
	_, attempts := g.ID, s.cfg.RouteFor(g, r).Attempts
	return g.ID, "", len(attempts) > 0
}

func splitAuthority(authority string) (string, string, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return "", "", err
	}
	if port == "" {
		port = "443"
	}
	return domain.Normalize(host), port, nil
}

func writeSimple(bw *bufio.Writer, status int, message string) {
	fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(message), message)
}

func bridge(client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := src.(*tls.Conn); ok {
			_ = closer.CloseWrite()
		} else if tc, ok := src.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}
	go pipe(client, upstream)
	go pipe(upstream, client)
	wg.Wait()
}

// serveMITM serves decrypted requests from the browser over the local TLS
// connection. Each request goes through the same forward/relay path.
func (s *Server) serveMITM(tlsConn *tls.Conn, host string, _ []string) {
	ln := &singleConnListener{conn: tlsConn, done: make(chan struct{})}
	server := &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			req.URL.Scheme = "https"
			if req.URL.Host == "" {
				req.URL.Host = req.Host
			}
			s.forwardHTTP(rw, req, host)
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
	_ = server.Serve(ln)
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn == nil {
		<-l.done
		return nil, io.EOF
	}
	return conn, nil
}
func (l *singleConnListener) Close() error {
	l.once.Do(func() {})
	close(l.done)
	_ = l.conn.Close()
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
