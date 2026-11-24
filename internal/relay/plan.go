package relay

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
)

const (
	failuresBeforeCooldown = 3
	cooldown               = 60 * time.Second
)

type RelayPlan struct {
	RuleID         string
	Target         string
	Headers        http.Header
	Timeout        time.Duration
	FallbackDirect bool
	Parked         bool
}

type Health struct {
	mu     sync.Mutex
	states map[string]*entry
}

type entry struct {
	failures int
	until    time.Time
}

func NewHealth() *Health { return &Health{states: map[string]*entry{}} }

func (h *Health) IsParked(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.states[id]
	return e != nil && time.Now().Before(e.until)
}

func (h *Health) NoteSuccess(id string) {
	h.mu.Lock()
	delete(h.states, id)
	h.mu.Unlock()
}

func (h *Health) NoteFailure(id string) {
	h.mu.Lock()
	e := h.states[id]
	if e == nil {
		e = &entry{}
		h.states[id] = e
	}
	e.failures++
	if e.failures >= failuresBeforeCooldown {
		e.failures = 0
		e.until = time.Now().Add(cooldown)
	}
	h.mu.Unlock()
}

// Plan applies the same rule semantics as Rust's relay::plan: GET/HEAD only,
// hosts AND paths must match, first matching rule wins, parked rules opt out
// when fallbackDirect is enabled.
func Plan(cfg *config.AppConfig, method, host, pathAndQuery string, headers http.Header, health *Health) *RelayPlan {
	if method != http.MethodGet && method != http.MethodHead {
		return nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var rule *config.ImageRelayRule
	for i := range cfg.Advanced.ImageRelays {
		r := &cfg.Advanced.ImageRelays[i]
		if !r.Enabled {
			continue
		}
		hostMatch := false
		for _, pattern := range r.Hosts {
			if matchHost(pattern, host) {
				hostMatch = true
				break
			}
		}
		if !hostMatch {
			continue
		}
		path := pathAndQuery
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		pathMatch := len(r.Paths) == 0
		for _, prefix := range r.Paths {
			if strings.HasPrefix(path, prefix) {
				pathMatch = true
				break
			}
		}
		if pathMatch {
			rule = r
			break
		}
	}
	if rule == nil {
		return nil
	}
	parked := health.IsParked(rule.ID)
	if parked && rule.FallbackDirect {
		return nil
	}
	base := strings.TrimRight(rule.Base, "/")
	if base == "" {
		return nil
	}
	target := base + ensureLeadingSlash(pathAndQuery)
	if _, err := url.Parse(target); err != nil {
		return nil
	}
	out := clone(headers)
	stripCredentials(out)
	if u, err := url.Parse(target); err == nil {
		out.Set("Host", u.Host)
	}
	if rule.Referer != "" {
		out.Set("Referer", rule.Referer)
	}
	if rule.UserAgent != "" {
		out.Set("User-Agent", rule.UserAgent)
	}
	timeout := time.Duration(rule.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &RelayPlan{
		RuleID: rule.ID, Target: target, Headers: out, Timeout: timeout,
		FallbackDirect: rule.FallbackDirect, Parked: parked,
	}
}

func matchHost(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix) && host[len(host)-len(suffix)-1] == '.'
	}
	return host == pattern
}

func ensureLeadingSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

func clone(src http.Header) http.Header {
	out := http.Header{}
	for k, values := range src {
		out[k] = append([]string(nil), values...)
	}
	return out
}

func stripCredentials(h http.Header) {
	h.Del("Cookie")
	h.Del("Authorization")
	h.Del("Proxy-Authorization")
}

func StripResponseCookies(h http.Header) {
	h.Del("Set-Cookie")
	h.Del("Set-Cookie2")
}

// ShouldFallback matches Rust's should_fallback: 403, 429 and 5xx.
func ShouldFallback(status int) bool {
	return status == 403 || status == 429 || (status >= 500 && status < 600)
}

// Execute runs the plan. When the target points at this process's local
// endpoint, it calls the JS worker in-process; otherwise it performs a normal
// HTTP request to the configured (possibly remote) relay base.
func Execute(ctx context.Context, plan *RelayPlan, worker *JSWorker, localBaseHost string, client *http.Client) (JSResponse, error) {
	u, err := url.Parse(plan.Target)
	if err != nil {
		return JSResponse{}, err
	}
	hostOnly := u.Hostname()
	if worker != nil && strings.EqualFold(hostOnly, localBaseHost) {
		return worker.Fetch(ctx, http.MethodGet, plan.Target, plan.Headers)
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, plan.Target, nil)
	if err != nil {
		return JSResponse{}, err
	}
	req.Header = plan.Headers
	resp, err := client.Do(req)
	if err != nil {
		return JSResponse{}, err
	}
	defer resp.Body.Close()
	body := make([]byte, 0)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if readErr != nil {
			break
		}
	}
	return JSResponse{Status: resp.StatusCode, Headers: clone(resp.Header), Body: body}, nil
}
