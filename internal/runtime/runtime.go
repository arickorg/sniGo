// Package runtime wires configuration, resolvers, CA, the JS relay worker,
// HTTP proxy and SOCKS5 server into one lifecycle, like HakimiRuntime.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/arick/hakimi-gop/internal/ca"
	"github.com/arick/hakimi-gop/internal/catalog"
	"github.com/arick/hakimi-gop/internal/config"
	"github.com/arick/hakimi-gop/internal/doh"
	"github.com/arick/hakimi-gop/internal/pac"
	"github.com/arick/hakimi-gop/internal/proxy"
	"github.com/arick/hakimi-gop/internal/relay"
	"github.com/arick/hakimi-gop/internal/socks5"
)

type Runtime struct {
	Paths    config.Paths
	Config   *config.AppConfig
	CA       *ca.Authority
	Resolver *doh.Resolver
	Catalog  *catalog.Store
	Worker   *relay.JSWorker
	Dialer   *proxy.Dialer

	HTTP  *proxy.Server
	SOCKS *socks5.Server

	paused    atomic.Bool
	startedAt time.Time
	started   atomic.Bool
	httpAddr  net.Addr
	socksAddr net.Addr
	stopOnce  chan struct{}
	client    *http.Client
	mitmMu    sync.RWMutex
}

func New(root string) (*Runtime, error) {
	paths := config.NewPaths(root)
	cfg, err := config.LoadOrCreate(paths)
	if err != nil {
		return nil, err
	}
	authority, err := ca.LoadOrCreate(paths)
	if err != nil {
		return nil, err
	}
	sources := []string{cfg.Catalogs.IP}
	sources = append(sources, cfg.Catalogs.IPMirrors...)
	resolver := doh.New(cfg.Doh.Primary, cfg.Doh.Fallback, cfg.Doh.Custom)
	store := catalog.New(paths, sources...)
	workerPath := relay.FindWorkerScript(cfg.Advanced.RelayWorkerJSPath)
	var worker *relay.JSWorker
	if cfg.Advanced.LocalRelay && workerPath != "" {
		worker, err = relay.NewJSWorker(workerPath)
		if err != nil {
			return nil, fmt.Errorf("load relay worker: %w", err)
		}
	}
	dialer := proxy.NewDialer(cfg, resolver, store)
	r := &Runtime{
		Paths: paths, Config: cfg, CA: authority, Resolver: resolver,
		Catalog: store, Worker: worker, Dialer: dialer,
		stopOnce: make(chan struct{}),
		client:   &http.Client{Timeout: 3 * time.Second},
	}
	return r, nil
}

// MITMState resolves the persisted proxy.mitm setting. In auto mode the OS
// trust probe (or HAKIMI_GOP_ASSUME_CA=1) decides; on/off override it.
func (r *Runtime) MITMState() (mode config.MitmMode, enabled, caTrusted bool) {
	r.mitmMu.RLock()
	mode = r.Config.Proxy.Mitm.Normalize()
	r.mitmMu.RUnlock()
	caTrusted = r.CA.Trusted()
	present, _ := r.CA.Status()["present"].(bool)
	return mode, mode.Enabled(caTrusted) && present, caTrusted
}

// ApplyMITM persists a mode and pushes it into a running proxy so switching
// takes effect immediately, without a restart.
func (r *Runtime) ApplyMITM(raw string) (bool, error) {
	mode, err := config.ParseMitmMode(raw)
	if err != nil {
		return false, err
	}
	r.mitmMu.Lock()
	r.Config.Proxy.Mitm = mode
	err = config.Save(r.Paths, r.Config)
	r.mitmMu.Unlock()
	if err != nil {
		return false, err
	}
	_, enabled, _ := r.MITMState()
	if r.HTTP != nil {
		r.HTTP.SetMITM(enabled)
	}
	return enabled, nil
}

func (r *Runtime) Start() error {
	proxyAddr := net.JoinHostPort(r.Config.Proxy.Bind, fmt.Sprint(r.Config.Proxy.Port))
	script := pac.Generate(r.Config, proxyAddr, r.paused.Load())
	_, mitmEnabled, _ := r.MITMState()
	p := proxy.New(proxy.Options{
		Config: r.Config, Dialer: r.Dialer, Authority: r.CA, Worker: r.Worker,
		Paused: &r.paused, MITMEnabled: mitmEnabled,
		OnStop: func() { _ = r.Stop() }, OnMITM: r.ApplyMITM,
		OnStatus: func() []byte {
			raw, _ := json.Marshal(r.StatusJSON())
			return raw
		},
	})
	p.SetPAC(script)
	addr, err := p.Listen(r.Config.Proxy.Bind, r.Config.Proxy.Port)
	if err != nil {
		return fmt.Errorf("listen HTTP proxy: %w", err)
	}
	r.HTTP = p
	r.httpAddr = addr

	if r.Config.Proxy.SocksPort > 0 {
		s := socks5.New(r.Dialer)
		socksAddr, err := s.Listen(r.Config.Proxy.Bind, r.Config.Proxy.SocksPort)
		if err != nil {
			_ = p.Close()
			return fmt.Errorf("listen SOCKS5: %w", err)
		}
		r.SOCKS = s
		r.socksAddr = socksAddr
	}
	r.startedAt = time.Now()
	r.started.Store(true)
	go r.background()
	return nil
}

func (r *Runtime) background() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-r.stopOnce:
			cancel()
		case <-ctx.Done():
		}
	}()
	_ = r.Catalog.Load(ctx, false)
}

func (r *Runtime) Stop() error {
	if !r.started.Load() {
		return nil
	}
	select {
	case <-r.stopOnce:
		return nil
	default:
		close(r.stopOnce)
	}
	r.started.Store(false)
	if r.HTTP != nil {
		_ = r.HTTP.Close()
	}
	if r.SOCKS != nil {
		_ = r.SOCKS.Close()
	}
	return nil
}

func (r *Runtime) Wait() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-r.stopOnce:
	case <-signals:
		_ = r.Stop()
	}
}

func (r *Runtime) Paused() bool { return r.paused.Load() }
func (r *Runtime) Pause() {
	r.paused.Store(true)
	r.refreshPAC()
}
func (r *Runtime) Resume() {
	r.paused.Store(false)
	r.refreshPAC()
}

func (r *Runtime) refreshPAC() {
	if r.HTTP == nil || r.httpAddr == nil {
		return
	}
	script := pac.Generate(r.Config, r.httpAddr.String(), r.paused.Load())
	r.HTTP.SetPAC(script)
}

func (r *Runtime) PACScript() string {
	if r.httpAddr != nil {
		return pac.Generate(r.Config, r.httpAddr.String(), r.paused.Load())
	}
	addr := net.JoinHostPort(r.Config.Proxy.Bind, fmt.Sprint(r.Config.Proxy.Port))
	return pac.Generate(r.Config, addr, false)
}

func (r *Runtime) PACURL() string {
	if r.httpAddr == nil {
		return ""
	}
	return pac.VersionedURL(r.httpAddr, r.PACScript())
}

func (r *Runtime) ProxyURL() string {
	if r.httpAddr == nil {
		return ""
	}
	return "http://" + r.httpAddr.String()
}

func (r *Runtime) SOCKSURL() string {
	if r.socksAddr == nil {
		return ""
	}
	return "socks5://" + r.socksAddr.String()
}

func (r *Runtime) IsRunning() bool { return r.started.Load() }

func (r *Runtime) StatusJSON() map[string]any {
	status := "stopped"
	if r.IsRunning() {
		status = "running"
		if r.Paused() {
			status = "paused"
		}
	}
	mode, mitmEnabled, caTrusted := r.MITMState()
	return map[string]any{
		"app":       "hakimi-gop",
		"version":   "1.0.0",
		"status":    status,
		"startedAt": r.startedAt,
		"paused":    r.Paused(),
		"proxy": map[string]any{
			"running": r.IsRunning(),
			"listen":  r.ProxyURL(),
			"socks":   r.SOCKSURL(),
			"mode":    r.Config.Proxy.Mode,
			"mitm":    mitmEnabled,
			"pacUrl":  r.PACURL(),
		},
		"mitm": map[string]any{
			"mode":      string(mode),
			"enabled":   mitmEnabled,
			"caTrusted": caTrusted,
			"source":    mitmSource(mode, mitmEnabled),
		},
		"ca":      r.CA.Status(),
		"groups":  len(r.Config.Groups),
		"relayJs": r.workerPath(),
		"catalog": map[string]any{"loadedAt": r.Catalog.LoadedAt(), "version": r.Catalog.Version()},
	}
}

func mitmSource(mode config.MitmMode, enabled bool) string {
	switch mode {
	case config.MitmOn:
		return "proxy.mitm=on"
	case config.MitmOff:
		return "proxy.mitm=off"
	}
	if enabled {
		if os.Getenv("HAKIMI_GOP_ASSUME_CA") == "1" {
			return "HAKIMI_GOP_ASSUME_CA=1 (auto)"
		}
		return "system CA trust (auto)"
	}
	return "CA not trusted/available (auto)"
}

func (r *Runtime) workerPath() string {
	if r.Worker == nil {
		return ""
	}
	return r.Worker.Path()
}

func (r *Runtime) WorkerDescription() string {
	if r.Worker == nil {
		return "disabled (localRelay=false or JS file not found)"
	}
	return r.Worker.Path()
}

// Control sends a POST to a running instance's local control endpoint.
func (r *Runtime) Control(action string) error {
	addr := net.JoinHostPort(dialHost(r.Config.Proxy.Bind), fmt.Sprint(r.Config.Proxy.Port))
	url := fmt.Sprintf("http://%s/hakimi/%s", addr, action)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-hakimi-control", "1")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("no reachable instance at %s; start one with `gop serve`", url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s returned %s", action, resp.Status)
	}
	return nil
}

// ControlMITM asks a running instance to persist and apply a new mode. The
// instance writes the config itself so two processes never race on the file.
func (r *Runtime) ControlMITM(mode string) (bool, error) {
	addr := net.JoinHostPort(dialHost(r.Config.Proxy.Bind), fmt.Sprint(r.Config.Proxy.Port))
	endpoint := fmt.Sprintf("http://%s/hakimi/mitm?mode=%s", addr, url.QueryEscape(mode))
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-hakimi-control", "1")
	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("mitm returned %s", resp.Status)
	}
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Enabled, nil
}

// FetchStatus pulls status from a running instance, like Rust's status command.
func (r *Runtime) FetchStatus() (map[string]any, error) {
	addr := net.JoinHostPort(dialHost(r.Config.Proxy.Bind), fmt.Sprint(r.Config.Proxy.Port))
	resp, err := r.client.Get(fmt.Sprintf("http://%s/hakimi/status", addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Runtime) FetchPAC() (string, error) {
	addr := net.JoinHostPort(dialHost(r.Config.Proxy.Bind), fmt.Sprint(r.Config.Proxy.Port))
	url := fmt.Sprintf("http://%s/proxy.pac", addr)
	resp, err := r.client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var buf [65536]byte
	n, _ := resp.Body.Read(buf[:])
	return string(buf[:n]), nil
}

func dialHost(bind string) string {
	switch bind {
	case "0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "[::1]"
	default:
		return bind
	}
}

func PrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
