package doh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// wireHTTPSResponse builds a RFC 8484 response with one HTTPS RR carrying a
// complete ECHConfigList in SvcParam 5.
func wireHTTPSResponse(host string, echList []byte) []byte {
	rdata := []byte{0x00, 0x01, 0x00} // priority=1, target=root
	rdata = append(rdata, 0x00, 0x05, byte(len(echList)>>8), byte(len(echList)))
	rdata = append(rdata, echList...)

	msg := buildWireQuery(host, wireTypeHTTPS)
	msg[2] |= 0x80 // QR: this is a response
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, encodeTestName(host)...)
	msg = append(msg, 0, 65, 0, 1, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

// TestQueryECHFallsBackToWireFormat covers the real-world case behind the
// Pixiv fix: domestic DoH endpoints reject type=HTTPS over the JSON API but
// answer it with application/dns-message.
func TestQueryECHFallsBackToWireFormat(t *testing.T) {
	echList := []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}
	msg := wireHTTPSResponse(SharedECHDomain, echList)
	var jsonCalls, wireCalls atomic.Int32

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Query().Get("dns") == "" {
			jsonCalls.Add(1)
			http.Error(w, "JSON API does not support type=HTTPS", http.StatusBadRequest)
			return
		}
		wireCalls.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(msg)
	}))
	defer ts.Close()

	r := &Resolver{
		client:   ts.Client(),
		endpoint: []string{ts.URL},
		cache:    map[string]cacheEntry{},
		health:   map[string]bool{},
	}
	got, err := r.queryECH(context.Background(), SharedECHDomain, []string{ts.URL})
	if err != nil {
		t.Fatalf("queryECH: %v", err)
	}
	if !bytes.Equal(got, echList) {
		t.Fatalf("ECHConfigList = %x, want %x", got, echList)
	}
	if jsonCalls.Load() == 0 || wireCalls.Load() == 0 {
		t.Fatalf("expected JSON attempt + wire fallback, got json=%d wire=%d", jsonCalls.Load(), wireCalls.Load())
	}
}

func TestSharedECHServesFromCache(t *testing.T) {
	cached := []byte{0x00, 0x06, 0xfe, 0x0d, 0x09, 0x08, 0x07, 0x06}
	var calls atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected network call", http.StatusBadRequest)
	}))
	defer ts.Close()

	r := &Resolver{
		client:   ts.Client(),
		endpoint: []string{ts.URL},
		cache: map[string]cacheEntry{
			"ECH:" + SharedECHDomain: {
				answer: Answer{ECH: cached, Source: "doh", TTL: sharedECHTTL},
				at:     time.Now(),
			},
		},
		health: map[string]bool{},
	}
	got, err := r.SharedECH(context.Background())
	if err != nil {
		t.Fatalf("SharedECH: %v", err)
	}
	if !bytes.Equal(got, cached) {
		t.Fatalf("SharedECH = %x, want cached %x", got, cached)
	}
	if calls.Load() != 0 {
		t.Fatalf("fresh cache should avoid any DoH request, got %d calls", calls.Load())
	}
}

func TestECHEndpointsIncludeAliDNSFallback(t *testing.T) {
	r := &Resolver{
		endpoint: []string{"https://doh.pub/dns-query", "https://doh.pub/dns-query", "https://223.5.5.5/dns-query"},
		health:   map[string]bool{},
	}
	eps := r.echEndpoints()
	seen := map[string]bool{}
	for _, ep := range eps {
		if seen[ep] {
			t.Fatalf("duplicate endpoint %q in %v", ep, eps)
		}
		seen[ep] = true
	}
	if !seen["https://dns.alidns.com/dns-query"] {
		t.Fatalf("AliDNS fallback missing: %v", eps)
	}
	if !seen["https://doh.pub/dns-query"] {
		t.Fatalf("configured endpoint missing: %v", eps)
	}
}

// Real ECHConfigList published by cloudflare-ech.com (SvcParam 5, 71 bytes).
// Captured from doh.pub's RFC 8484 HTTPS RR answer; keeping the exact bytes
// guards the parser against subtle ECHConfigList framing mistakes.
var realSharedECH = []byte{
	0x00, 0x45, 0xfe, 0x0d, 0x00, 0x41, 0x3e, 0x00, 0x20, 0x00, 0x20,
	0x13, 0x47, 0x20, 0xc1, 0xd7, 0x32, 0x44, 0xb3, 0xf6, 0xaf, 0xe2,
	0xed, 0xd0, 0xdb, 0xec, 0x9d, 0x76, 0x64, 0x77, 0xf2, 0x15, 0x76,
	0x54, 0x96, 0x89, 0x26, 0xb3, 0xfc, 0x5c, 0x2c, 0x81, 0x68, 0x00,
	0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x12, 0x63, 0x6c, 0x6f, 0x75,
	0x64, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x65, 0x63, 0x68, 0x2e,
	0x63, 0x6f, 0x6d, 0x00, 0x00,
}

// TestHTTPSParamWithRealSharedECH verifies that SvcParam 5 is found among
// several other params and returned as a complete ECHConfigList.
func TestHTTPSParamWithRealSharedECH(t *testing.T) {
	if !validECHConfigList(realSharedECH) {
		t.Fatalf("fixture is not a valid ECHConfigList (len=%d)", len(realSharedECH))
	}
	rdata := []byte{0x00, 0x01, 0x00}                                                 // priority=1, target=root
	rdata = append(rdata, 0x00, 0x01, 0x00, 0x06, 0x02, 'h', '3', 0x02, 'h', '2')     // alpn
	rdata = append(rdata, 0x00, 0x04, 0x00, 0x08, 104, 18, 10, 118, 104, 18, 11, 118) // ipv4hint
	rdata = append(rdata, 0x00, 0x05, byte(len(realSharedECH)>>8), byte(len(realSharedECH)))
	rdata = append(rdata, realSharedECH...)

	msg := wireHTTPSResponseWithRdata(SharedECHDomain, rdata)
	_, ech := parseWireAnswer(msg, SharedECHDomain)
	if !bytes.Equal(ech, realSharedECH) {
		t.Fatalf("ECHConfigList = %x, want %x", ech, realSharedECH)
	}
}

func wireHTTPSResponseWithRdata(host string, rdata []byte) []byte {
	msg := buildWireQuery(host, wireTypeHTTPS)
	msg[2] |= 0x80
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, encodeTestName(host)...)
	msg = append(msg, 0, 65, 0, 1, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata)))
	msg = append(msg, rdata...)
	return msg
}

func TestParseECHFromHTTPSQuotedValue(t *testing.T) {
	bare := []byte{0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}
	record := `1 . alpn="h2,h3" ech="` + base64.StdEncoding.EncodeToString(bare) + `"`
	got := parseECHFromHTTPS(record)
	if !validECHConfigList(got) {
		t.Fatalf("parseECHFromHTTPS(quoted) = %x, want valid ECHConfigList", got)
	}
	if !bytes.Equal(got[2:], bare) {
		t.Fatalf("ECHConfig payload = %x, want %x", got[2:], bare)
	}
}
