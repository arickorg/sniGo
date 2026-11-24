// Package domain implements the same pattern semantics as Rust's domain.rs:
// exact names or a leading *. wildcard that never matches the bare domain.
package domain

import (
	"net"
	"strings"
)

func Normalize(input string) string {
	host := strings.ToLower(strings.TrimSpace(input))
	host = strings.TrimSuffix(host, ".")
	return host
}

func IsIPLiteral(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func Matches(pattern, host string) bool {
	pattern = Normalize(pattern)
	host = Normalize(host)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix) && host[len(host)-len(suffix)-1] == '.'
	}
	return host == pattern
}

func HostOf(authority string) string {
	authority = strings.TrimSpace(authority)
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return Normalize(host)
	}
	if strings.HasPrefix(authority, "[") {
		authority = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
	}
	return Normalize(authority)
}
