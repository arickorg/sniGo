// Package relay executes workers/pximg-relay/index.js with goja so the Go CLI
// uses the SAME JavaScript file as the Rust project's deployable worker.
//
// The worker is a Cloudflare Worker module: `export default { fetch(request) }`.
// We transform that single export into a global binding and provide minimal
// Request/URL/Headers/Response/fetch shims on top of net/http. The shims are
// written in JavaScript (not Go objects) so object key enumeration behaves
// exactly as the worker expects.
package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// JSResponse is the result of running the worker's fetch handler.
type JSResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// shimSource defines Web-API-like constructors in JavaScript. Headers keys are
// stored in a plain object so enumeration returns only header names.
const shimSource = `
function Headers(init) {
  this._m = Object.create(null);
  if (init instanceof Headers) {
    for (const k of Object.keys(init._m)) this._m[k] = init._m[k];
  } else if (init && typeof init === "object") {
    for (const k of Object.keys(init)) this.set(k, init[k]);
  }
}
Headers.prototype.get = function(n) { const v = this._m[String(n).toLowerCase()]; return v === undefined ? null : v; };
Headers.prototype.set = function(n, v) { this._m[String(n).toLowerCase()] = String(v); };
Headers.prototype.append = function(n, v) {
  const k = String(n).toLowerCase();
  this._m[k] = this._m[k] ? this._m[k] + ", " + String(v) : String(v);
};
Headers.prototype.delete = function(n) { delete this._m[String(n).toLowerCase()]; };
Headers.prototype.has = function(n) { return this._m[String(n).toLowerCase()] !== undefined; };
Headers.prototype.entries = function() { return Object.entries(this._m); };

function URL(input) {
  const s = String(input);
  const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?/.exec(s);
  if (!m) throw new Error("invalid URL: " + s);
  this.protocol = m[1] + ":";
  this.host = m[2];
  const dot = m[2].lastIndexOf(":");
  this.hostname = dot > -1 && m[2].indexOf("]") === -1 ? m[2].slice(0, dot) : m[2];
  this.pathname = m[3] || "/";
  this.search = m[4] || "";
  this.href = s;
}

function Response(body, init) {
  init = init || {};
  this.status = init.status === undefined ? 200 : Number(init.status);
  this.ok = this.status >= 200 && this.status < 300;
  this.headers = new Headers(init.headers);
  this.body = body;
}
function makeHeaders(init) { return new Headers(init); }
function makeResponse(status, headers, body) { return new Response(body, {status: status, headers: headers}); }
`

// JSWorker holds the compiled program. goja runtimes are not thread-safe, so
// calls are serialized by a mutex.
type JSWorker struct {
	source    string
	path      string
	client    *http.Client
	mu        sync.Mutex // guards fetchHook + cache only, never held across fetch
	fetchHook func(*http.Request) (*http.Response, error)
	cache     map[string]cachedResponse
}

type cachedResponse struct {
	resp JSResponse
	at   time.Time
	ttl  time.Duration
}

// FindWorkerScript resolves the JS file: explicit path, then the sibling
// workers/pximg-relay/index.js in the repository, then common cwd variants.
func FindWorkerScript(explicit string) string {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	}
	candidates = append(candidates,
		"../workers/pximg-relay/index.js",
		"workers/pximg-relay/index.js",
		"../../workers/pximg-relay/index.js",
	)
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			abs, _ := filepathAbs(c)
			return abs
		}
	}
	return ""
}

func filepathAbs(p string) (string, error) {
	if strings.HasPrefix(p, "/") {
		return p, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return p, err
	}
	return cwd + "/" + p, nil
}

func NewJSWorker(path string) (*JSWorker, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read worker JS %s: %w", path, err)
	}
	return &JSWorker{
		source: transformModule(string(raw)),
		path:   path,
		client: &http.Client{Timeout: 30 * time.Second},
		cache:  map[string]cachedResponse{},
	}, nil
}

func (w *JSWorker) Path() string { return w.path }

func (w *JSWorker) SetFetchHook(hook func(*http.Request) (*http.Response, error)) {
	w.mu.Lock()
	w.fetchHook = hook
	w.mu.Unlock()
}

// transformModule rewrites the single ESM export used by the worker. It is
// intentionally narrow: a broad ESM loader would need a module resolver and
// would obscure that this is exactly the checked-in file.
func transformModule(source string) string {
	s := strings.Replace(source, "export default", "globalThis.__worker =", 1)
	return s + `
if (typeof globalThis.__worker === "undefined") { throw new Error("worker has no default export"); }
`
}

// Fetch runs `default.fetch(request)` and waits for the returned Promise.
func (w *JSWorker) Fetch(ctx context.Context, method, requestURL string, headers http.Header) (JSResponse, error) {
	// Each call gets its own goja runtime, so calls are independent. The mutex
	// only protects the hook and cache, never held across a network fetch.
	rt := goja.New()
	if _, err := rt.RunString(shimSource); err != nil {
		return JSResponse{}, fmt.Errorf("install shims: %w", err)
	}
	rt.Set("fetch", w.jsFetch(rt, ctx))
	if _, err := rt.RunString(w.source); err != nil {
		return JSResponse{}, fmt.Errorf("run worker JS: %w", err)
	}
	worker := rt.Get("__worker").ToObject(rt)
	fetchFn, ok := goja.AssertFunction(worker.Get("fetch"))
	if !ok {
		return JSResponse{}, errors.New("worker.fetch is not a function")
	}

	req := rt.NewObject()
	req.Set("url", requestURL)
	req.Set("method", method)
	req.Set("headers", headersToJS(rt, headers))

	value, err := fetchFn(goja.Undefined(), req)
	if err != nil {
		return JSResponse{}, err
	}
	if promise, ok := value.Export().(*goja.Promise); ok {
		for promise.State() == goja.PromiseStatePending {
			select {
			case <-ctx.Done():
				return JSResponse{}, ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
		if promise.State() == goja.PromiseStateRejected {
			return JSResponse{}, fmt.Errorf("worker rejected: %v", promise.Result())
		}
		value = promise.Result()
	}
	return responseFromValue(rt, value)
}

func headersToJS(rt *goja.Runtime, src http.Header) goja.Value {
	init := rt.NewObject()
	if src != nil {
		for k, values := range src {
			if len(values) > 0 {
				init.Set(strings.ToLower(k), values[0])
			}
		}
	}
	_ = rt.Set("__init", init)
	v, err := rt.RunString("makeHeaders(__init)")
	if err != nil {
		return goja.Undefined()
	}
	return v
}

func responseFromValue(rt *goja.Runtime, value goja.Value) (JSResponse, error) {
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return JSResponse{}, errors.New("worker returned no response")
	}
	obj := value.ToObject(rt)
	status := 200
	if s := obj.Get("status"); goja.IsNumber(s) {
		status = int(s.ToInteger())
	}
	out := JSResponse{Status: status, Headers: http.Header{}}
	if h := obj.Get("headers"); h != nil && !goja.IsUndefined(h) && !goja.IsNull(h) {
		if entries, ok := goja.AssertFunction(h.ToObject(rt).Get("entries")); ok {
			v, err := entries(h)
			if err == nil {
				if arr, ok := v.Export().([]interface{}); ok {
					for _, item := range arr {
						pair, ok := item.([]interface{})
						if ok && len(pair) == 2 {
							out.Headers.Set(fmt.Sprint(pair[0]), fmt.Sprint(pair[1]))
						}
					}
				}
			}
		}
	}
	if body := obj.Get("body"); body != nil && !goja.IsUndefined(body) && !goja.IsNull(body) {
		switch v := body.Export().(type) {
		case []byte:
			out.Body = v
		case string:
			out.Body = []byte(v)
		}
	}
	return out, nil
}

// jsFetch implements the worker's upstream fetch and the cf cache hints.
func (w *JSWorker) jsFetch(rt *goja.Runtime, ctx context.Context) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		target := call.Argument(0).String()
		method := http.MethodGet
		h := http.Header{}
		var cacheTTL time.Duration
		if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) {
			init := call.Argument(1).ToObject(rt)
			if m := init.Get("method"); goja.IsString(m) && m.String() != "" {
				method = strings.ToUpper(m.String())
			}
			if hv := init.Get("headers"); hv != nil && !goja.IsUndefined(hv) && !goja.IsNull(hv) {
				h = headerFromJS(rt, hv)
			}
			if cf := init.Get("cf"); cf != nil && !goja.IsUndefined(cf) && !goja.IsNull(cf) {
				if obj := cf.ToObject(rt); obj != nil {
					if ttl := obj.Get("cacheTtl"); goja.IsNumber(ttl) {
						cacheTTL = time.Duration(ttl.ToInteger()) * time.Second
					}
				}
			}
		}

		cacheKey := method + " " + target + " " + h.Get("Range") + " " + h.Get("User-Agent")
		if cacheTTL > 0 {
			w.mu.Lock()
			hit, ok := w.cache[cacheKey]
			w.mu.Unlock()
			if ok && time.Since(hit.at) < hit.ttl {
				copied := cloneHeaders(hit.resp.Headers)
				copied.Set("cf-cache-status", "HIT")
				return responseToJS(rt, JSResponse{Status: hit.resp.Status, Headers: copied, Body: hit.resp.Body})
			}
		}

		req, err := http.NewRequestWithContext(ctx, method, target, nil)
		if err != nil {
			panic(rt.ToValue(err.Error()))
		}
		req.Header = h
		var resp *http.Response
		w.mu.Lock()
		hook := w.fetchHook
		w.mu.Unlock()
		if hook != nil {
			resp, err = hook(req)
		} else {
			resp, err = w.client.Do(req)
		}
		if err != nil {
			panic(rt.ToValue("fetch failed: " + err.Error()))
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		if err != nil {
			panic(rt.ToValue("read body: " + err.Error()))
		}
		out := JSResponse{Status: resp.StatusCode, Headers: cloneHeaders(resp.Header), Body: body}
		if cacheTTL > 0 {
			w.mu.Lock()
			w.cache[cacheKey] = cachedResponse{resp: out, at: time.Now(), ttl: cacheTTL}
			w.mu.Unlock()
			out.Headers.Set("cf-cache-status", "MISS")
		}
		return responseToJS(rt, out)
	}
}

func headerFromJS(rt *goja.Runtime, value goja.Value) http.Header {
	out := http.Header{}
	obj := value.ToObject(rt)
	if entries, ok := goja.AssertFunction(obj.Get("entries")); ok {
		v, err := entries(value)
		if err == nil {
			if arr, ok := v.Export().([]interface{}); ok {
				for _, item := range arr {
					if pair, ok := item.([]interface{}); ok && len(pair) == 2 {
						out.Set(fmt.Sprint(pair[0]), fmt.Sprint(pair[1]))
					}
				}
			}
			return out
		}
	}
	for _, key := range obj.Keys() {
		v := obj.Get(key)
		if v != nil && !goja.IsUndefined(v) && !goja.IsNull(v) {
			out.Set(key, v.String())
		}
	}
	return out
}

func responseToJS(rt *goja.Runtime, resp JSResponse) goja.Value {
	headers := headersToJS(rt, resp.Headers)
	_ = rt.Set("__header", headers)
	_ = rt.Set("__status", resp.Status)
	_ = rt.Set("__body", resp.Body)
	v, err := rt.RunString("makeResponse(__status, __header, __body)")
	if err != nil {
		return goja.Undefined()
	}
	return v
}

func cloneHeaders(src http.Header) http.Header {
	out := http.Header{}
	for k, values := range src {
		for _, v := range values {
			out.Add(k, v)
		}
	}
	return out
}

// ServeHTTP exposes the worker as an HTTP handler, so a relay base URL can
// point at this process instead of a public Cloudflare Worker.
// workerFetchTimeout bounds a single relay request. /pximg is served from a
// raw connection whose request context carries no deadline, so an unreachable
// upstream (e.g. i.pximg.net being blocked) would otherwise hold that
// connection open indefinitely instead of returning a 502.
var workerFetchTimeout = 15 * time.Second

func (w *JSWorker) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	target := req.URL.String()
	if !strings.Contains(target, "://") {
		scheme := "http"
		if req.TLS != nil {
			scheme = "https"
		}
		host := req.Host
		if host == "" && req.URL.Host != "" {
			host = req.URL.Host
		}
		if host == "" {
			host = "localhost"
		}
		target = scheme + "://" + host + target
	}
	ctx, cancel := context.WithTimeout(req.Context(), workerFetchTimeout)
	defer cancel()
	out, err := w.Fetch(ctx, req.Method, target, req.Header)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	for k, values := range out.Headers {
		for _, v := range values {
			rw.Header().Add(k, v)
		}
	}
	rw.WriteHeader(out.Status)
	if req.Method != http.MethodHead {
		_, _ = io.Copy(rw, bytes.NewReader(out.Body))
	}
}
