package doh

// Minimal RFC 1035 / RFC 9460 wire codec, enough for A / AAAA / HTTPS (ECH)
// queries against DoH endpoints that only speak application/dns-message.

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	wireTypeA     uint16 = 1
	wireTypeCNAME uint16 = 5
	wireTypeAAAA  uint16 = 28
	wireTypeHTTPS uint16 = 65
)

type wireRecord struct {
	name  string
	rtype uint16
	data  []byte
}

// buildWireQuery builds a standard DNS wire-format query.
func buildWireQuery(name string, qtype uint16) []byte {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], 0x1234) // id
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(buf[4:6], 1)      // one question
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	buf = append(buf, byte(qtype>>8), byte(qtype), 0, 1)
	return buf
}

// decodeName decodes a possibly compressed domain name at offset pos.
func decodeName(msg []byte, pos int) (string, int, error) {
	var labels []string
	jumps := 0
	for {
		if pos >= len(msg) {
			return "", 0, errors.New("dns name out of bounds")
		}
		l := int(msg[pos])
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", 0, errors.New("truncated compression pointer")
			}
			ptr := int(uint16(msg[pos]&0x3f)<<8 | uint16(msg[pos+1]))
			if ptr >= len(msg) {
				return "", 0, errors.New("bad compression target")
			}
			name, _, err := decodeName(msg, ptr)
			return strings.ToLower(strings.Join(append(labels, name), ".")), pos + 2, err
		}
		pos++
		if l == 0 {
			return strings.ToLower(strings.Join(labels, ".")), pos, nil
		}
		if pos+l > len(msg) {
			return "", 0, errors.New("bad label length")
		}
		labels = append(labels, string(msg[pos:pos+l]))
		pos += l
		jumps++
		if jumps > 128 {
			return "", 0, errors.New("too many labels")
		}
	}
}

// parseWireAnswer extracts A/AAAA addresses and the ECHConfigList from an
// RFC9460 HTTPS record, following CNAMEs inside the response.
func parseWireAnswer(msg []byte, host string) ([]net.IP, []byte) {
	if len(msg) < 12 {
		return nil, nil
	}
	questions := int(binary.BigEndian.Uint16(msg[4:6]))
	answers := int(binary.BigEndian.Uint16(msg[6:8]))
	pos := 12
	for i := 0; i < questions; i++ {
		_, next, err := decodeName(msg, pos)
		if err != nil {
			return nil, nil
		}
		pos = next + 4
	}
	var records []wireRecord
	for i := 0; i < answers; i++ {
		name, next, err := decodeName(msg, pos)
		if err != nil {
			return nil, nil
		}
		pos = next
		if pos+10 > len(msg) {
			return nil, nil
		}
		rtype := binary.BigEndian.Uint16(msg[pos : pos+2])
		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(msg) {
			return nil, nil
		}
		records = append(records, wireRecord{name: name, rtype: rtype, data: msg[pos : pos+rdlen]})
		pos += rdlen
	}

	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	current := host
	var ips []net.IP
	var ech []byte
	seen := map[string]bool{}
	for hop := 0; hop < 16; hop++ {
		matched := false
		nextName := ""
		for _, rec := range records {
			if rec.name != current {
				continue
			}
			switch rec.rtype {
			case wireTypeA:
				matched = true
				if len(rec.data) == 4 {
					ip := net.IPv4(rec.data[0], rec.data[1], rec.data[2], rec.data[3])
					if !seen[ip.String()] {
						seen[ip.String()] = true
						ips = append(ips, ip)
					}
				}
			case wireTypeAAAA:
				matched = true
				if len(rec.data) == 16 {
					ip := net.IP(append([]byte(nil), rec.data...))
					if !seen[ip.String()] {
						seen[ip.String()] = true
						ips = append(ips, ip)
					}
				}
			case wireTypeHTTPS:
				matched = true
				if param := httpsECHParam(rec.data); param != nil {
					ech = param
				}
				if target, _, err := decodeName(rec.data, 2); err == nil && target != "" {
					nextName = target
				}
			case wireTypeCNAME:
				matched = true
				if name, _, err := decodeName(rec.data, 0); err == nil {
					nextName = name
				}
			}
		}
		if !matched || nextName == "" || nextName == current {
			break
		}
		current = nextName
	}
	return ips, ech
}

// httpsECHParam extracts SvcParam 5 (ech) from an RFC9460 HTTPS RDATA and
// returns a complete ECHConfigList that crypto/tls can consume.
func httpsECHParam(rdata []byte) []byte {
	if len(rdata) < 3 {
		return nil
	}
	_, pos, err := decodeName(rdata, 2) // skip priority + target name
	if err != nil {
		return nil
	}
	for pos+4 <= len(rdata) {
		key := binary.BigEndian.Uint16(rdata[pos : pos+2])
		ln := int(binary.BigEndian.Uint16(rdata[pos+2 : pos+4]))
		pos += 4
		if pos+ln > len(rdata) {
			return nil
		}
		val := rdata[pos : pos+ln]
		pos += ln
		if key == 5 && len(val) > 3 {
			return normalizeECHConfigList(val)
		}
	}
	return nil
}

// validECHConfigList reports whether b is a serialized ECHConfigList in the
// exact shape crypto/tls expects: a uint16 length prefix covering the rest of
// the buffer, followed by an ECHConfig whose version is 0xfe 0x0d.
func validECHConfigList(b []byte) bool {
	if len(b) < 6 || int(binary.BigEndian.Uint16(b[:2])) != len(b)-2 {
		return false
	}
	return b[2] == 0xfe && b[3] == 0x0d
}

// normalizeECHConfigList wraps a bare ECHConfig with the ECHConfigList length
// prefix. Wire-format SvcParam 5 values already carry the prefix, while DoH
// JSON APIs often return only the inner ECHConfig. crypto/tls rejects the
// latter with "malformed ECHConfigList", even though the bytes are otherwise
// a perfectly good ECHConfig.
func normalizeECHConfigList(b []byte) []byte {
	if validECHConfigList(b) {
		return append([]byte(nil), b...)
	}
	for n := 0; n+4 < len(b); n++ {
		if b[n] == 0xfe && b[n+1] == 0x0d {
			body := b[n:]
			out := make([]byte, len(body)+2)
			binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
			copy(out[2:], body)
			return out
		}
	}
	return nil
}
