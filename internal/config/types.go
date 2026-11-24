// Package config mirrors hakimi's config.json schema (camelCase keys).
// Defaults match the Rust core so the same config file remains meaningful.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const SchemaVersion = 7

type AppConfig struct {
	Doh            DohConfig      `json:"doh"`
	Catalogs       CatalogsConfig `json:"catalogs"`
	Proxy          ProxyConfig    `json:"proxy"`
	Groups         []GroupConfig  `json:"groups"`
	CatalogVersion int            `json:"catalogVersion"`
	Advanced       AdvancedConfig `json:"advanced"`
	Log            LogConfig      `json:"log"`
	SchemaVersion  int            `json:"schemaVersion"`
}

type DohConfig struct {
	Primary  string   `json:"primary"`
	Fallback string   `json:"fallback"`
	Custom   []string `json:"custom"`
}

type CatalogsConfig struct {
	IP              string   `json:"ip"`
	Doh             string   `json:"doh"`
	IPMirrors       []string `json:"ipMirrors"`
	DohMirrors      []string `json:"dohMirrors"`
	SignatureURL    *string  `json:"signatureUrl,omitempty"`
	SignaturePubKey *string  `json:"signaturePublicKey,omitempty"`
	TimeoutSecs     int      `json:"timeoutSecs"`
}

type ProxyConfig struct {
	Mode     string `json:"mode"` // pac | http | off
	Port     int    `json:"port"`
	Bind     string `json:"bind"`
	Takeover bool   `json:"takeover"`
	// SocksPort enables the SOCKS5 listener. 0 disables it. Rust has no
	// SOCKS5; this is the Go port's addition requested by the user.
	SocksPort int `json:"socksPort"`
}

type GroupConfig struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Domains      []DomainRule `json:"domains"`
	Enabled      bool         `json:"enabled"`
	Homepage     *string      `json:"homepage,omitempty"`
	DefaultRoute RoutePolicy  `json:"defaultRoute"`
}

type DomainRule struct {
	Pattern string       `json:"pattern"`
	Route   *RoutePolicy `json:"route,omitempty"`
}

type RouteAttempt struct {
	Mode string   `json:"mode"` // direct | ech | sni
	Ech  string   `json:"ech,omitempty"`
	Sni  []string `json:"sni,omitempty"`
}

type RoutePolicy struct {
	Attempts []RouteAttempt `json:"attempts"`
}

type AdvancedConfig struct {
	FakeSNICandidates      []string         `json:"fakeSniCandidates"`
	MaxCandidatesPerDomain int              `json:"maxCandidatesPerDomain"`
	IPTimeoutMs            int              `json:"ipTimeoutMs"`
	LastGoodDays           int              `json:"lastGoodDays"`
	PlanCacheSecs          int              `json:"planCacheSecs"`
	ImageRelays            []ImageRelayRule `json:"imageRelays"`
	// LocalRelay makes the built-in /pximg endpoint use the repository's
	// workers/pximg-relay/index.js instead of a remote Cloudflare Worker.
	LocalRelay        bool   `json:"localRelay"`
	RelayWorkerJSPath string `json:"relayWorkerJsPath,omitempty"`
}

type ImageRelayRule struct {
	ID             string   `json:"id"`
	Enabled        bool     `json:"enabled"`
	Hosts          []string `json:"hosts"`
	Paths          []string `json:"paths"`
	Base           string   `json:"base"`
	Referer        string   `json:"referer,omitempty"`
	UserAgent      string   `json:"userAgent,omitempty"`
	FallbackDirect bool     `json:"fallbackDirect"`
	TimeoutMs      int      `json:"timeoutMs"`
}

type LogConfig struct {
	Level  string `json:"level,omitempty"`
	Format string `json:"format,omitempty"`
}

func AutoRoute() RoutePolicy {
	return RoutePolicy{Attempts: []RouteAttempt{
		{Mode: "direct"},
		{Mode: "ech", Ech: "own"},
		{Mode: "sni"},
	}}
}

func DirectRoute() RoutePolicy {
	return RoutePolicy{Attempts: []RouteAttempt{{Mode: "direct"}}}
}

func SNIRoute(hosts ...string) RoutePolicy {
	return RoutePolicy{Attempts: []RouteAttempt{{Mode: "sni", Sni: hosts}, {Mode: "direct"}}}
}

func EchSharedRoute() RoutePolicy {
	return RoutePolicy{Attempts: []RouteAttempt{{Mode: "ech", Ech: "shared"}, {Mode: "direct"}}}
}

func (p RoutePolicy) DirectOnly() bool {
	if len(p.Attempts) == 0 {
		return false
	}
	for _, a := range p.Attempts {
		if a.Mode != "direct" {
			return false
		}
	}
	return true
}

func (p RoutePolicy) Label() string {
	parts := make([]string, 0, len(p.Attempts))
	for _, a := range p.Attempts {
		switch a.Mode {
		case "sni":
			parts = append(parts, "sni("+strings.Join(a.Sni, ",")+")")
		case "ech":
			parts = append(parts, "ech:"+a.Ech)
		default:
			parts = append(parts, a.Mode)
		}
	}
	return strings.Join(parts, ">")
}

// Default returns the built-in configuration. Built-in groups are a faithful
// subset of the Rust defaults: the domains and route presets that matter for
// interception and selection.
func Default() AppConfig {
	localBase := "http://127.0.0.1:8443/pximg"
	return AppConfig{
		Doh: DohConfig{
			Primary:  "https://doh.pub/dns-query",
			Fallback: "https://cloudflare-dns.com/dns-query",
			Custom:   []string{"https://223.5.5.5/dns-query"},
		},
		Catalogs: CatalogsConfig{
			IP:          "https://gitee.com/mom09/hakimi/raw/master/ips.json",
			Doh:         "https://gitee.com/mom09/hakimi/raw/master/doh.json",
			IPMirrors:   []string{},
			DohMirrors:  []string{},
			TimeoutSecs: 5,
		},
		Proxy:  ProxyConfig{Mode: "pac", Port: 8443, Bind: "127.0.0.1", Takeover: true, SocksPort: 1080},
		Groups: defaultGroups(),
		Advanced: AdvancedConfig{
			FakeSNICandidates:      []string{"www.bing.com"},
			MaxCandidatesPerDomain: 8,
			IPTimeoutMs:            2000,
			LastGoodDays:           7,
			PlanCacheSecs:          600,
			ImageRelays: []ImageRelayRule{{
				ID: "pixiv", Enabled: true,
				Hosts:          []string{"i.pximg.net"},
				Paths:          []string{"/img-original/", "/img-master/"},
				Base:           localBase,
				Referer:        "https://www.pixiv.net/",
				UserAgent:      "Piku/3.7.0",
				FallbackDirect: true,
				TimeoutMs:      5000,
			}},
			LocalRelay: true,
		},
		Log:           LogConfig{Level: "info", Format: "text"},
		SchemaVersion: SchemaVersion,
	}
}

func defaultGroups() []GroupConfig {
	auto, direct := AutoRoute(), DirectRoute()
	sni := SNIRoute()
	ech := EchSharedRoute()
	rule := func(pattern string, route RoutePolicy) DomainRule {
		r := route
		return DomainRule{Pattern: pattern, Route: &r}
	}
	plain := func(pattern string) DomainRule { return DomainRule{Pattern: pattern} }
	groups := []GroupConfig{
		{ID: "github", Name: "GitHub", Enabled: true, DefaultRoute: sni,
			Domains: []DomainRule{plain("github.com"), plain("api.github.com"), rule("gist.github.com", SNIRoute("api.github.com")), plain("codeload.github.com"), plain("raw.githubusercontent.com"), plain("*.githubusercontent.com"), plain("*.githubassets.com")}},
		{ID: "pixiv", Name: "Pixiv", Enabled: true, DefaultRoute: ech,
			Domains: []DomainRule{rule("pixiv.net", ech), rule("www.pixiv.net", ech), rule("*.pixiv.net", ech), plain("i.pximg.net"), plain("s.pximg.net"), plain("booth.pximg.net"), plain("*.pximg.net")}},
		{ID: "ao3", Name: "AO3", Enabled: true, DefaultRoute: SNIRoute("", "archiveofourown.org."),
			Domains: []DomainRule{plain("archiveofourown.org"), plain("www.archiveofourown.org"), plain("*.archiveofourown.org")}},
		{ID: "eh", Name: "E-Hentai", Enabled: true, DefaultRoute: sni,
			Domains: []DomainRule{plain("e-hentai.org"), rule("exhentai.org", ech), plain("*.e-hentai.org"), rule("*.exhentai.org", ech), plain("ehgt.org"), plain("*.ehgt.org")}},
		{ID: "hitomi", Name: "Hitomi", Enabled: true, DefaultRoute: auto,
			Domains: []DomainRule{plain("hitomi.la"), plain("*.hitomi.la"), plain("ltn.gold-usergeneratedcontent.net"), plain("*.gold-usergeneratedcontent.net")}},
		{ID: "hanime", Name: "Hanime", Enabled: true, DefaultRoute: auto,
			Domains: []DomainRule{plain("hanime.tv"), plain("www.hanime.tv"), plain("*.hanime.tv")}},
		{ID: "steam", Name: "Steam", Enabled: true, DefaultRoute: sni,
			Domains: []DomainRule{plain("store.steampowered.com"), plain("steamcommunity.com"), plain("*.steamcommunity.com"), plain("*.steampowered.com"), plain("*.steamstatic.com"), plain("steamcdn-a.akamaihd.net")}},
		{ID: "poipiku", Name: "Poipiku", Enabled: true, DefaultRoute: direct,
			Domains: []DomainRule{rule("poipiku.com", SNIRoute("")), plain("img.poipiku.com"), plain("cdn.poipiku.com"), plain("*.poipiku.com")}},
		{ID: "hf", Name: "Hugging Face", Enabled: true, DefaultRoute: SNIRoute("huggingface.co.", "www.huggingface.co."),
			Domains: []DomainRule{plain("huggingface.co"), plain("www.huggingface.co"), plain("*.huggingface.co"), rule("*.hf.co", direct)}},
		{ID: "x-com", Name: "X-beta", Enabled: true, DefaultRoute: auto,
			Domains: []DomainRule{plain("x.com"), plain("*.x.com"), plain("t.co"), plain("*.twimg.com")}},
		{ID: "google", Name: "Google", Enabled: true, DefaultRoute: SNIRoute("www.google.com.", "www.google.com.hk."),
			Domains: []DomainRule{rule("www.google.com", SNIRoute("www.google.com.")), rule("www.google.com.hk", SNIRoute("www.google.com.hk."))}},
	}
	return groups
}

func (c *AppConfig) EnabledGroups() []GroupConfig {
	out := make([]GroupConfig, 0, len(c.Groups))
	for _, g := range c.Groups {
		if g.Enabled {
			out = append(out, g)
		}
	}
	return out
}

// Match returns the first enabled group and domain rule matching host.
func (c *AppConfig) Match(host string) (GroupConfig, DomainRule, bool) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, g := range c.Groups {
		if !g.Enabled {
			continue
		}
		for _, r := range g.Domains {
			if matchPattern(r.Pattern, host) {
				return g, r, true
			}
		}
	}
	return GroupConfig{}, DomainRule{}, false
}

func matchPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix) && host[len(host)-len(suffix)-1] == '.'
	}
	return host == pattern
}

func (c *AppConfig) RouteFor(g GroupConfig, r DomainRule) RoutePolicy {
	if r.Route != nil && len(r.Route.Attempts) > 0 {
		return *r.Route
	}
	if len(g.DefaultRoute.Attempts) > 0 {
		return g.DefaultRoute
	}
	return AutoRoute()
}

func (c *AppConfig) Group(id string) (GroupConfig, bool) {
	for _, g := range c.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return GroupConfig{}, false
}

func (c *AppConfig) SetGroup(g GroupConfig) {
	for i := range c.Groups {
		if c.Groups[i].ID == g.ID {
			c.Groups[i] = g
			return
		}
	}
	c.Groups = append(c.Groups, g)
}

func (c *AppConfig) RemoveGroup(id string) bool {
	for i, g := range c.Groups {
		if g.ID == id {
			c.Groups = append(c.Groups[:i], c.Groups[i+1:]...)
			return true
		}
	}
	return false
}

type Paths struct{ Root string }

func NewPaths(root string) Paths {
	if root == "" {
		root = defaultRoot()
	}
	return Paths{Root: root}
}

func defaultRoot() string {
	if v := os.Getenv("HAKIMI_GOP_DATA_DIR"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".hakimi-gop")
	}
	return ".hakimi-gop"
}

func (p Paths) ConfigFile() string { return filepath.Join(p.Root, "config.json") }
func (p Paths) CAFile() string     { return filepath.Join(p.Root, "ca", "ca.pem") }
func (p Paths) CAKey() string      { return filepath.Join(p.Root, "ca", "key.pem") }
func (p Paths) CacheFile() string  { return filepath.Join(p.Root, "cache", "state.json") }
func (p Paths) LogFile() string    { return filepath.Join(p.Root, "logs", "hakimi.log") }
func (p Paths) PIDFile() string    { return filepath.Join(p.Root, "hakimi.pid") }

func (p Paths) Ensure() error {
	for _, dir := range []string{p.Root, filepath.Join(p.Root, "ca"), filepath.Join(p.Root, "cache"), filepath.Join(p.Root, "logs"), filepath.Join(p.Root, "state")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// LoadOrCreate overlays the on-disk JSON onto defaults, preserving the
// "only changed values" behaviour of the Rust config.
func LoadOrCreate(p Paths) (*AppConfig, error) {
	if err := p.Ensure(); err != nil {
		return nil, err
	}
	cfg := Default()
	raw, err := os.ReadFile(p.ConfigFile())
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := Save(p, &cfg); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config.json: %w", err)
	}
	return &cfg, nil
}

func Save(p Paths, cfg *AppConfig) error {
	if err := p.Ensure(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := p.ConfigFile() + ".tmp"
	data := append(raw, '\n')
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.ConfigFile()); err == nil {
		return nil
	}
	// Some sandboxed/perm-restricted directories deny rename(2) even though
	// plain writes are allowed. Fall back to an in-place write there.
	if err := os.WriteFile(p.ConfigFile(), data, 0o600); err != nil {
		return err
	}
	return os.Remove(tmp)
}
