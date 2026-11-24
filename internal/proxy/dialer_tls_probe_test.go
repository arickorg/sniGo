package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/arick/hakimi-gop/internal/config"
)

func testDialer() *Dialer {
	cfg := config.Default()
	return NewDialer(&cfg, nil, nil)
}

// TestProbePrefersTLSReachableIP verifies that a candidate which accepts TCP
// but drops the TLS handshake is ranked below one that completes TLS.
func TestProbePrefersTLSReachableIP(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()
	port := strconv.Itoa(tlsSrv.Listener.Addr().(*net.TCPAddr).Port)

	// Accepts TCP, then closes before any TLS handshake can complete.
	badLn, err := net.Listen("tcp6", net.JoinHostPort("::1", port))
	if err != nil {
		t.Skipf("cannot listen on ::1: %v", err)
	}
	defer badLn.Close()
	go func() {
		for {
			c, e := badLn.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()

	goodIP := net.ParseIP("127.0.0.1")
	badIP := net.ParseIP("::1")
	// Deliberately put the TLS-broken candidate first.
	got := testDialer().probe(context.Background(), []net.IP{badIP, goodIP}, port, "example.com")
	if len(got) != 2 {
		t.Fatalf("probe returned %d IPs, want 2: %v", len(got), got)
	}
	if !got[0].Equal(goodIP) {
		t.Fatalf("first candidate = %s, want TLS-reachable %s (all: %v)", got[0], goodIP, got)
	}
}

// TestProbeKeepsTCPOnlyAsFallback ensures a network where no IP completes the
// pre-handshake still yields candidates, so the SOCKS tunnel stays usable.
func TestProbeKeepsTCPOnlyAsFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	got := testDialer().probe(context.Background(), []net.IP{net.ParseIP("127.0.0.1")}, port, "example.com")
	if len(got) != 1 || !got[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("TCP-only fallback lost: %v", got)
	}
}

func TestTLSPort(t *testing.T) {
	for _, p := range []string{"443", "8443"} {
		if !tlsPort(p) {
			t.Errorf("tlsPort(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"80", "1080", "2080", "22"} {
		if tlsPort(p) {
			t.Errorf("tlsPort(%q) = true, want false", p)
		}
	}
}
