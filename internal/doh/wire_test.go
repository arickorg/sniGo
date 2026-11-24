package doh

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// TestParseWireAnswerWithECH builds a minimal DNS response carrying an HTTPS
// RR with an ECH SvcParam (key 5), plus an A record, and verifies both are read.
func TestParseWireAnswerWithECH(t *testing.T) {
	name := "www.pixiv.net"
	msg := buildWireQuery(name, wireTypeHTTPS)

	// One question, two answers.
	binary.BigEndian.PutUint16(msg[6:8], 2)
	answerName := encodeTestName(name)

	// A record: 210.140.139.155
	a := append([]byte(nil), answerName...)
	a = append(a, byte(wireTypeA>>8), byte(wireTypeA), 0, 1, 0, 0, 0, 30, 0, 4)
	a = append(a, 210, 140, 139, 155)
	msg = append(msg, a...)

	// HTTPS RR: priority=1, target=root, SvcParam 5 (ech) carrying a
	// complete ECHConfigList (uint16 length prefix + ECHConfig 0xfe0d...).
	ech := []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}
	https := append([]byte(nil), answerName...)
	https = append(https, byte(wireTypeHTTPS>>8), byte(wireTypeHTTPS), 0, 1, 0, 0, 0, 30)
	rdata := []byte{0x00, 0x01, 0x00} // priority=1, target=root
	rdata = append(rdata, 0x00, 0x05, byte(len(ech)>>8), byte(len(ech)))
	rdata = append(rdata, ech...)
	https = append(https, byte(len(rdata)>>8), byte(len(rdata)))
	https = append(https, rdata...)
	msg = append(msg, https...)

	ips, gotECH := parseWireAnswer(msg, name)
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("210.140.139.155")) {
		t.Fatalf("addresses = %v, want [210.140.139.155]", ips)
	}
	if len(gotECH) != len(ech) {
		t.Fatalf("ECH length = %d, want %d (got %x)", len(gotECH), len(ech), gotECH)
	}
	for i := range ech {
		if gotECH[i] != ech[i] {
			t.Fatalf("ECH = %x, want %x", gotECH, ech)
		}
	}
	if !validECHConfigList(gotECH) {
		t.Fatalf("parsed ECH %x is not a valid ECHConfigList", gotECH)
	}
}

func TestParseECHFromHTTPSJSON(t *testing.T) {
	// Presentation form emitted by Google/Cloudflare JSON APIs. The base64
	// value is a bare ECHConfig (fe0d...), so the parser must add the
	// ECHConfigList length prefix that crypto/tls requires.
	valid := "1 . alpn=\"h2,h3\" ech=/g0AAQID"
	got := parseECHFromHTTPS(valid)
	if !validECHConfigList(got) {
		t.Fatalf("parseECHFromHTTPS = %x, want a complete ECHConfigList", got)
	}
}

func TestNormalizeECHConfigList(t *testing.T) {
	// Wire-format SvcParam 5 values already carry the prefix and pass through.
	full := []byte{0x00, 0x06, 0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}
	if got := normalizeECHConfigList(full); !validECHConfigList(got) || len(got) != len(full) {
		t.Fatalf("normalize(full) = %x, want unchanged %x", got, full)
	}
	// A bare ECHConfig gets wrapped.
	bare := []byte{0xfe, 0x0d, 0x00, 0x01, 0x02, 0x03}
	if got := normalizeECHConfigList(bare); !validECHConfigList(got) {
		t.Fatalf("normalize(bare) = %x, want valid ECHConfigList", got)
	}
	if got := normalizeECHConfigList([]byte{1, 2, 3}); got != nil {
		t.Fatalf("normalize(garbage) = %x, want nil", got)
	}
}

func encodeTestName(name string) []byte {
	out := []byte{}
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}
