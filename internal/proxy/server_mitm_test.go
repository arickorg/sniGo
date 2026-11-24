package proxy

import (
	"sync/atomic"
	"testing"

	"github.com/arick/hakimi-gop/internal/ca"
	"github.com/arick/hakimi-gop/internal/config"
)

func TestDecideMITMUsesPersistedSwitch(t *testing.T) {
	// Even when the CA probe reports trusted, the switch alone decides.
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "1")
	authority, err := ca.LoadOrCreate(config.NewPaths(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if !authority.Trusted() {
		t.Fatal("test setup: CA should be trusted")
	}
	cfg := config.Default()
	paused := &atomic.Bool{}
	s := New(Options{Config: &cfg, Authority: authority, Paused: paused})
	if s.MITMEnabled() {
		t.Fatal("MITM must be disabled when Options.MITMEnabled is false")
	}
	if _, _, ok := s.decideMITM("www.pixiv.net"); ok {
		t.Fatal("CONNECT must not be intercepted while the switch is off")
	}

	s.SetMITM(true)
	if _, _, ok := s.decideMITM("www.pixiv.net"); !ok {
		t.Fatal("a routed group must be intercepted when the switch is on")
	}
	for _, host := range []string{"127.0.0.1", "example.com"} {
		if _, _, ok := s.decideMITM(host); ok {
			t.Fatalf("%s must not be intercepted", host)
		}
	}
	paused.Store(true)
	if _, _, ok := s.decideMITM("www.pixiv.net"); ok {
		t.Fatal("paused proxy must not intercept")
	}
	paused.Store(false)
	s.SetMITM(false)
	if _, _, ok := s.decideMITM("www.pixiv.net"); ok {
		t.Fatal("turning the switch off must stop interception")
	}
}
