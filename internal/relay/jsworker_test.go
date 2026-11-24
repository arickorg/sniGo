package relay

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// workerJSFromRepo locates the SAME checked-in JS file used by the Rust repo.
func workerJSFromRepo(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	// gop/internal/relay -> repository root
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "workers", "pximg-relay", "index.js")
	if _, err := osStat(path); err != nil {
		t.Fatalf("worker JS not found at %s: %v", path, err)
	}
	return path
}

func osStat(path string) (os.FileInfo, error) { return os.Stat(path) }

func TestJSWorkerUsesRepositoryFile(t *testing.T) {
	path := workerJSFromRepo(t)
	w, err := NewJSWorker(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readFile(t, path), `const ORIGIN = "https://i.pximg.net";`) {
		t.Fatal("unexpected worker source")
	}

	var seen *http.Request
	w.SetFetchHook(func(req *http.Request) (*http.Response, error) {
		seen = req
		return &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"image/jpeg"},
				"Set-Cookie":   []string{"secret=1"},
			},
			Body: io.NopCloser(strings.NewReader("JPEGDATA")),
		}, nil
	})

	headers := http.Header{}
	headers.Set("Range", "bytes=0-99")
	headers.Set("Cookie", "session=secret")
	headers.Set("User-Agent", "TestAgent/1.0")

	resp, err := w.Fetch(context.Background(), http.MethodGet, "https://example.workers.dev/pximg/img-original/a.jpg?x=1", headers)
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("fetch was not called")
	}
	if seen.URL.String() != "https://i.pximg.net/img-original/a.jpg?x=1" {
		t.Fatalf("wrong origin URL: %s", seen.URL.String())
	}
	if seen.Header.Get("Referer") != "https://www.pixiv.net/" {
		t.Fatalf("wrong referer: %q", seen.Header.Get("Referer"))
	}
	if seen.Header.Get("User-Agent") != "TestAgent/1.0" {
		t.Fatalf("wrong UA: %q", seen.Header.Get("User-Agent"))
	}
	if seen.Header.Get("Range") != "bytes=0-99" {
		t.Fatalf("range not passed through: %q", seen.Header.Get("Range"))
	}
	if seen.Header.Get("Cookie") != "" {
		t.Fatal("worker should not forward Cookie")
	}
	if string(resp.Body) != "JPEGDATA" {
		t.Fatalf("wrong body: %q", resp.Body)
	}
	if resp.Headers.Get("Set-Cookie") != "" {
		t.Fatal("worker must strip Set-Cookie")
	}
	if resp.Headers.Get("Cache-Control") != "public, max-age=604800, immutable" {
		t.Fatalf("missing cache-control: %q", resp.Headers.Get("Cache-Control"))
	}
	if resp.Headers.Get("cf-cache-status") != "MISS" {
		t.Fatalf("missing cf status: %v", resp.Headers)
	}
}

func TestJSWorkerRejectsWrongPathAndMethod(t *testing.T) {
	w, err := NewJSWorker(workerJSFromRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := w.Fetch(context.Background(), http.MethodGet, "https://x/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 404 {
		t.Fatalf("expected 404, got %d", resp.Status)
	}
	resp, err = w.Fetch(context.Background(), http.MethodPost, "https://x/pximg/a.jpg", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 405 {
		t.Fatalf("expected 405, got %d", resp.Status)
	}
}

// TestServeHTTPBoundsSlowUpstream guards against /pximg hanging forever when
// the upstream image host is unreachable: the raw CONNECT-side request has no
// deadline of its own, so JSWorker.ServeHTTP must supply one.
func TestServeHTTPBoundsSlowUpstream(t *testing.T) {
	w, err := NewJSWorker(workerJSFromRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	original := workerFetchTimeout
	workerFetchTimeout = 120 * time.Millisecond
	defer func() { workerFetchTimeout = original }()

	w.SetFetchHook(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8443/pximg/img-master/a.jpg", nil)
	rw := httptest.NewRecorder()
	start := time.Now()
	w.ServeHTTP(rw, req)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("relay request took %s, expected the fetch timeout to bound it", elapsed)
	}
	if rw.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 on a timed-out upstream", rw.Code)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
