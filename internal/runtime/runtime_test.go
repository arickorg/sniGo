package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPACAndProxyAndSOCKS(t *testing.T) {
	rt, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rt.Config.Proxy.Port = freePort(t)
	rt.Config.Proxy.SocksPort = freePort(t)
	rt.Config.Proxy.Mode = "http"
	rt.Config.Advanced.LocalRelay = false // no JS needed for the transport test

	if err := rt.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rt.Stop() }()

	script := rt.PACScript()
	for _, want := range []string{"FindProxyForURL", `"github.com": 1`, "dnsDomainIs(host, wild[i])", fmt.Sprintf("PROXY 127.0.0.1:%d; DIRECT", rt.Config.Proxy.Port)} {
		if !strings.Contains(script, want) {
			t.Fatalf("PAC missing %q:\n%s", want, script)
		}
	}

	// Local origin that answers both HTTP and CONNECT.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		for {
			conn, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := reader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				body := "ORIGIN:" + req.URL.Path
				fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	originAddr := origin.Addr().String()

	// 1. Plain HTTP forward proxy (absolute-form request).
	req, _ := http.NewRequest(http.MethodGet, "http://"+originAddr+"/forward", nil)
	req.Header.Set("Host", originAddr)
	proxyURL, _ := url.Parse(rt.ProxyURL())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTP proxy: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ORIGIN:/forward" {
		t.Fatalf("HTTP proxy body: %q", data)
	}

	// 2. SOCKS5 CONNECT through the same dialer.
	socksURL, _ := url.Parse(rt.SOCKSURL())
	socksClient := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(socksURL)}, Timeout: 5 * time.Second}
	resp, err = socksClient.Get("http://" + originAddr + "/socks")
	if err != nil {
		t.Fatalf("SOCKS5 proxy: %v", err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ORIGIN:/socks" {
		t.Fatalf("SOCKS5 body: %q", data)
	}

	// 3. PAC version URL token looks like the Rust 6-hex form.
	if len(rt.PACURL()) < 8 || !strings.Contains(rt.PACURL(), "?v=") {
		t.Fatalf("bad PAC URL %q", rt.PACURL())
	}
	_ = context.Background()
}
