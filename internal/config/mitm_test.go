package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestMitmModeEnabled(t *testing.T) {
	cases := []struct {
		mode    MitmMode
		trusted bool
		want    bool
	}{
		{MitmAuto, false, false},
		{MitmAuto, true, true},
		{MitmOn, false, true},
		{MitmOn, true, true},
		{MitmOff, false, false},
		{MitmOff, true, false},
		{MitmMode(""), true, true},       // empty means auto
		{MitmMode("legacy"), true, true}, // unknown in-memory value falls back to auto
	}
	for _, c := range cases {
		if got := c.mode.Enabled(c.trusted); got != c.want {
			t.Fatalf("%q.Enabled(%v) = %v, want %v", c.mode, c.trusted, got, c.want)
		}
	}
}

func TestParseMitmMode(t *testing.T) {
	cases := []struct {
		in   any
		want MitmMode
	}{
		{"on", MitmOn}, {" ON ", MitmOn}, {"true", MitmOn}, {"1", MitmOn},
		{"yes", MitmOn}, {"enabled", MitmOn}, {"forced", MitmOn},
		{true, MitmOn}, {float64(1), MitmOn}, {json.Number("1"), MitmOn},
		{"off", MitmOff}, {"FALSE", MitmOff}, {"0", MitmOff},
		{"no", MitmOff}, {"disabled", MitmOff},
		{false, MitmOff}, {float64(0), MitmOff},
		{"auto", MitmAuto}, {"", MitmAuto}, {" Auto ", MitmAuto}, {nil, MitmAuto},
		{MitmOn, MitmOn},
	}
	for _, c := range cases {
		got, err := ParseMitmMode(c.in)
		if err != nil {
			t.Fatalf("ParseMitmMode(%v): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseMitmMode(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseMitmMode("bogus"); err == nil {
		t.Fatal("expected an error for an unknown mode")
	}
	if _, err := ParseMitmMode(float64(7)); err == nil {
		t.Fatal("expected an error for an unsupported number")
	}
}

func TestMitmModeJSON(t *testing.T) {
	for raw, want := range map[string]MitmMode{
		`"on"`: MitmOn, `true`: MitmOn, `"1"`: MitmOn,
		`"off"`: MitmOff, `false`: MitmOff, `"AUTO"`: MitmAuto, `null`: MitmAuto,
	} {
		var got MitmMode
		if err := json.Unmarshal([]byte(raw), &got); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		if got != want {
			t.Fatalf("unmarshal %s = %q, want %q", raw, got, want)
		}
	}
	var bad MitmMode
	if err := json.Unmarshal([]byte(`"bogus"`), &bad); err == nil {
		t.Fatal("expected an error for an invalid config value")
	}
	b, err := json.Marshal(MitmOn)
	if err != nil || string(b) != `"on"` {
		t.Fatalf("marshal MitmOn = %s, %v; want \"on\"", b, err)
	}
}

func TestConfigMitmDefaultAndPersistence(t *testing.T) {
	paths := NewPaths(t.TempDir())
	cfg, err := LoadOrCreate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.Mitm != MitmAuto {
		t.Fatalf("default proxy.mitm = %q, want auto", cfg.Proxy.Mitm)
	}

	// A legacy config.json without the field must keep the original behaviour.
	if err := os.WriteFile(paths.ConfigFile(), []byte(`{"proxy":{"port":9443}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy, err := LoadOrCreate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Proxy.Mitm != MitmAuto || legacy.Proxy.Port != 9443 {
		t.Fatalf("legacy config = %+v", legacy.Proxy)
	}

	legacy.Proxy.Mitm = MitmOn
	if err := Save(paths, legacy); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"mitm": "on"`) {
		t.Fatalf("saved config is missing mitm:\n%s", raw)
	}
	reloaded, err := LoadOrCreate(paths)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Proxy.Mitm != MitmOn {
		t.Fatalf("reloaded proxy.mitm = %q, want on", reloaded.Proxy.Mitm)
	}
}
