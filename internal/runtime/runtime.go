// Package runtime wires configuration, resolvers, CA, the JS relay worker,
// HTTP proxy and SOCKS5 server into one lifecycle, like HakimiRuntime.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
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

func (r *Runtime) Start() error {
	proxyAddr := net.JoinHostPort(r.Config.Proxy.Bind, fmt.Sprint(r.Config.Proxy.Port))
	script := pac.Generate(r.Config, proxyAddr, r.paused.Load())
	p := proxy.New(proxy.Options{
		Config: r.Config, Dialer: r.Dialer, Authority: r.CA, Worker: r.Worker,
		Paused: &r.paused, OnStop: func() { _ = r.Stop() },
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
			"pacUrl":  r.PACURL(),
		},
		"ca":      r.CA.Status(),
		"groups":  len(r.Config.Groups),
		"relayJs": r.workerPath(),
		"catalog": map[string]any{"loadedAt": r.Catalog.LoadedAt(), "version": r.Catalog.Version()},
	}
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
