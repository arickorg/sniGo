package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MitmMode is the persisted proxy.mitm setting. "auto" keeps the original
// behaviour (intercept only when the root CA is trusted by the OS, or when
// HAKIMI_GOP_ASSUME_CA=1 forces it), "on" always intercepts, "off" never
// intercepts even if the CA is trusted.
type MitmMode string

const (
	MitmAuto MitmMode = "auto"
	MitmOn   MitmMode = "on"
	MitmOff  MitmMode = "off"
)

func normalizeMitm(s string) (MitmMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return MitmAuto, true
	case "on", "true", "1", "yes", "enabled", "force", "forced":
		return MitmOn, true
	case "off", "false", "0", "no", "disabled", "none":
		return MitmOff, true
	}
	return MitmAuto, false
}

// Normalize tolerates legacy/unknown values by falling back to auto. It is
// used on values already in memory; parsing external input should use
// ParseMitmMode so typos are reported.
func (m MitmMode) Normalize() MitmMode {
	v, ok := normalizeMitm(string(m))
	if !ok {
		return MitmAuto
	}
	return v
}

// Enabled resolves the mode against OS/forced CA trust. Explicit on/off wins
// over both the trust probe and the legacy environment variable.
func (m MitmMode) Enabled(trusted bool) bool {
	switch m.Normalize() {
	case MitmOn:
		return true
	case MitmOff:
		return false
	default:
		return trusted
	}
}

// ParseMitmMode accepts the JSON/CLI representations of the setting: a mode
// string (with common aliases), a boolean, 1/0, or null (auto).
func ParseMitmMode(v any) (MitmMode, error) {
	switch x := v.(type) {
	case nil:
		return MitmAuto, nil
	case MitmMode:
		return x.Normalize(), nil
	case string:
		m, ok := normalizeMitm(x)
		if !ok {
			return MitmAuto, fmt.Errorf("invalid proxy.mitm %q (want auto|on|off)", x)
		}
		return m, nil
	case bool:
		if x {
			return MitmOn, nil
		}
		return MitmOff, nil
	case float64:
		if x == 1 {
			return MitmOn, nil
		}
		if x == 0 {
			return MitmOff, nil
		}
	case json.Number:
		if x.String() == "1" {
			return MitmOn, nil
		}
		if x.String() == "0" {
			return MitmOff, nil
		}
	}
	return MitmAuto, fmt.Errorf("invalid proxy.mitm value %v (want auto|on|off)", v)
}

// UnmarshalJSON lets an existing config.json keep using booleans while new
// files are written as the canonical auto|on|off strings.
func (m *MitmMode) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	mode, err := ParseMitmMode(v)
	if err != nil {
		return err
	}
	*m = mode
	return nil
}
