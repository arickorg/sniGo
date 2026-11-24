package cli

import (
	"testing"

	"github.com/arick/hakimi-gop/internal/config"
)

func TestSetPathMitmAcceptsBooleanAndString(t *testing.T) {
	cfg := config.Default()
	if err := setPath(&cfg, "proxy.mitm", true); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Mitm != config.MitmOn {
		t.Fatalf("proxy.mitm after `set ... true` = %q, want on", cfg.Proxy.Mitm)
	}
	value, err := getPath(&cfg, "proxy.mitm")
	if err != nil || value != "on" {
		t.Fatalf("getPath = %v, %v; want on", value, err)
	}
	if err := setPath(&cfg, "proxy.mitm", "off"); err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Mitm != config.MitmOff {
		t.Fatalf("proxy.mitm after `set ... off` = %q, want off", cfg.Proxy.Mitm)
	}
}

func TestSetPathMitmRejectsUnknownMode(t *testing.T) {
	cfg := config.Default()
	if err := setPath(&cfg, "proxy.mitm", "bogus"); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
	if cfg.Proxy.Mitm != config.MitmAuto {
		t.Fatalf("invalid value changed config to %q", cfg.Proxy.Mitm)
	}
}
