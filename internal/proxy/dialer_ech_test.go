package proxy

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
)

var testECH = []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}

func TestECHConfigForOwnNeverUsesShared(t *testing.T) {
	sharedCalled := false
	shared := func() []byte { sharedCalled = true; return testECH }

	got := echConfigFor(config.RouteAttempt{Mode: "ech", Ech: "own"}, testECH, shared)
	if !bytes.Equal(got, testECH) {
		t.Fatalf("own config = %x, want %x", got, testECH)
	}
	if got := echConfigFor(config.RouteAttempt{Mode: "ech", Ech: "own"}, nil, shared); len(got) != 0 {
		t.Fatalf("own with no HTTPS RR must not fall back, got %x", got)
	}
	if sharedCalled {
		t.Fatal("shared ECH must not be queried for ech=own")
	}
}

func TestECHConfigForSharedFallsBack(t *testing.T) {
	sharedCfg := []byte{0x00, 0x06, 0xfe, 0x0d, 0x09, 0x08, 0x07, 0x06}
	shared := func() []byte { return sharedCfg }

	// Pixiv publishes no ECHConfig of its own: the shared config must be used.
	if got := echConfigFor(config.RouteAttempt{Mode: "ech", Ech: "shared"}, nil, shared); !bytes.Equal(got, sharedCfg) {
		t.Fatalf("shared fallback = %x, want %x", got, sharedCfg)
	}
	// An omitted source defaults to shared (Rust's EchSource::Shared default).
	if got := echConfigFor(config.RouteAttempt{Mode: "ech"}, nil, shared); !bytes.Equal(got, sharedCfg) {
		t.Fatalf("default source = %x, want shared %x", got, sharedCfg)
	}
	// A domain-owned config wins over the shared one.
	own := []byte{0x00, 0x06, 0xfe, 0x0d, 0x01, 0x01, 0x01, 0x01}
	if got := echConfigFor(config.RouteAttempt{Mode: "ech", Ech: "shared"}, own, shared); !bytes.Equal(got, own) {
		t.Fatalf("own config should win, got %x want %x", got, own)
	}
	if got := echConfigFor(config.RouteAttempt{Mode: "ech"}, nil, nil); len(got) != 0 {
		t.Fatalf("no shared provider should yield no config, got %x", got)
	}
}

func TestBuildTLSConfigRequiresTLS13ForECH(t *testing.T) {
	cfg := buildTLSConfig("www.pixiv.net", "www.pixiv.net", testECH)
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %#x, want TLS1.3 (crypto/tls rejects ECH with TLS1.2)", cfg.MinVersion)
	}
	if !bytes.Equal(cfg.EncryptedClientHelloConfigList, testECH) {
		t.Fatalf("ECHConfigList = %x, want %x", cfg.EncryptedClientHelloConfigList, testECH)
	}
	if cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil {
		t.Fatal("ECH keeps the real ServerName; standard certificate verification must apply")
	}

	plain := buildTLSConfig("example.com", "example.com", nil)
	if plain.MinVersion != tls.VersionTLS12 {
		t.Fatalf("plain MinVersion = %#x, want TLS1.2", plain.MinVersion)
	}
	if plain.InsecureSkipVerify {
		t.Fatal("direct route must verify certificates normally")
	}
}

func TestMarkFailedDeprioritizesIP(t *testing.T) {
	d := testDialer()
	host := "www.pixiv.net"
	a := net.ParseIP("210.140.139.155")
	b := net.ParseIP("172.64.145.17")
	c := net.ParseIP("210.140.139.161")

	d.remember(host, a)
	d.cachePlan(host, a, "ech")
	d.MarkFailed(host, a)
	if _, _, ok := d.CachedPlan(host); ok {
		t.Fatal("a failed route must not stay in the plan cache")
	}

	ordered := d.deprioritizeFailed(host, []net.IP{a, b, c})
	if len(ordered) != 3 || !ordered[0].Equal(b) || !ordered[1].Equal(c) || !ordered[2].Equal(a) {
		t.Fatalf("deprioritizeFailed = %v, want healthy IPs first then the failed one", ordered)
	}
	// A failed IP is a last resort, not removed: single-candidate hosts still work.
	if only := d.deprioritizeFailed(host, []net.IP{a}); len(only) != 1 || !only[0].Equal(a) {
		t.Fatalf("single failed candidate = %v, want it kept", only)
	}
	// Failures are scoped per host.
	if other := d.deprioritizeFailed("other.example", []net.IP{a, b}); !other[0].Equal(a) {
		t.Fatalf("unrelated host was affected: %v", other)
	}

	// Expired failures are forgotten and the original order is restored.
	d.failed[host][a.String()] = time.Now().Add(-2 * failedIPCooldown)
	if expired := d.deprioritizeFailed(host, []net.IP{a, b}); !expired[0].Equal(a) || len(d.failed[host]) != 0 {
		t.Fatalf("expired failure was not cleared: %v, cache=%v", expired, d.failed[host])
	}
}

func TestPreferAttemptReusesCachedStrategy(t *testing.T) {
	attempts := []config.RouteAttempt{
		{Mode: "ech", Ech: "shared"},
		{Mode: "direct"},
	}
	got := preferAttempt(attempts, "direct")
	if got[0].Mode != "direct" || got[1].Mode != "ech" {
		t.Fatalf("preferAttempt(direct) = %+v, want direct first", got)
	}
	if attempts[0].Mode != "ech" {
		t.Fatal("preferAttempt must not mutate the configured route")
	}
	if same := preferAttempt(attempts, "ech"); same[0].Mode != "ech" || len(same) != 2 {
		t.Fatalf("already-first strategy should be unchanged, got %+v", same)
	}
	if absent := preferAttempt(attempts, "sni"); absent[0].Mode != "ech" || len(absent) != 2 {
		t.Fatalf("unknown strategy should be unchanged, got %+v", absent)
	}

	three := []config.RouteAttempt{{Mode: "direct"}, {Mode: "sni"}, {Mode: "ech"}}
	reordered := preferAttempt(three, "ech")
	want := []string{"ech", "direct", "sni"}
	for i, mode := range want {
		if reordered[i].Mode != mode {
			t.Fatalf("preferAttempt order = %+v, want %v", reordered, want)
		}
	}
}

func TestBuildTLSConfigFakeSNIVerifiesRealHost(t *testing.T) {
	cfg := buildTLSConfig("www.pixiv.net", "www.bing.com", nil)
	if !cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate == nil {
		t.Fatal("fake SNI requires a manual certificate check against the real host")
	}
	if err := cfg.VerifyPeerCertificate(nil, nil); err == nil {
		t.Fatal("empty certificate chain must be rejected")
	}
}
