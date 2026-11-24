// Package catalog loads the remote IP directory with mirrors and on-disk cache.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Store struct {
	mu        sync.RWMutex
	client    *http.Client
	sources   []string
	cacheFile string
	entries   map[string][]net.IP
	loadedAt  time.Time
	version   int
}

type document struct {
	Version int                 `json:"version"`
	IPs     map[string][]string `json:"ips"`
	Domains map[string][]string `json:"domains"`
}

func New(paths interface{ CacheFile() string }, sources ...string) *Store {
	return &Store{
		client:    &http.Client{Timeout: 6 * time.Second},
		sources:   sources,
		cacheFile: filepath.Join(filepath.Dir(paths.CacheFile()), "catalog-ip.json"),
		entries:   map[string][]net.IP{},
	}
}

func (s *Store) Get(host string) []net.IP {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]net.IP(nil), s.entries[host]...)
	return out
}

func (s *Store) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func (s *Store) LoadedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

func (s *Store) Load(ctx context.Context, force bool) error {
	if !force && time.Since(s.LoadedAt()) < 6*time.Hour {
		if len(s.Get("github.com")) > 0 {
			return nil
		}
	}
	if raw, err := os.ReadFile(s.cacheFile); err == nil {
		if doc, err := decode(raw); err == nil {
			s.apply(doc)
			return nil
		}
	}
	var lastErr error
	for _, src := range s.sources {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "hakimi-gop/1.0")
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != 200 {
			lastErr = fmt.Errorf("%s: status %d", src, resp.StatusCode)
			continue
		}
		doc, err := decode(body)
		if err != nil {
			lastErr = err
			continue
		}
		s.apply(doc)
		_ = os.WriteFile(s.cacheFile, body, 0o600)
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no IP catalog sources configured")
}

func decode(raw []byte) (document, error) {
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, err
	}
	if len(doc.IPs) == 0 && len(doc.Domains) == 0 {
		return doc, fmt.Errorf("empty catalog")
	}
	return doc, nil
}

func (s *Store) apply(doc document) {
	entries := make(map[string][]net.IP, len(doc.IPs)+len(doc.Domains))
	add := func(host, value string) {
		if ip := net.ParseIP(value); ip != nil {
			entries[host] = append(entries[host], ip)
		}
	}
	for host, ips := range doc.IPs {
		for _, ip := range ips {
			add(host, ip)
		}
	}
	for host, ips := range doc.Domains {
		for _, ip := range ips {
			add(host, ip)
		}
	}
	s.mu.Lock()
	s.entries = entries
	s.version = doc.Version
	s.loadedAt = time.Now()
	s.mu.Unlock()
}

// Candidates merges catalog, DoH and last-good addresses, de-duplicated and
// capped at limit, with catalog entries first as the project's default.
func Candidates(catalog []net.IP, doh []net.IP, lastGood []net.IP, limit int) []net.IP {
	seen := map[string]bool{}
	out := make([]net.IP, 0, limit)
	for _, group := range [][]net.IP{lastGood, catalog, doh} {
		for _, ip := range group {
			if seen[ip.String()] {
				continue
			}
			seen[ip.String()] = true
			out = append(out, ip)
			if len(out) >= limit {
				return out
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
