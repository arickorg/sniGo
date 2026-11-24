package runtime

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
)

func mitmTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rt.Config.Proxy.Port = freePort(t)
	rt.Config.Proxy.SocksPort = 0
	rt.Config.Advanced.LocalRelay = false
	return rt
}

func TestMITMStateModes(t *testing.T) {
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "")
	rt := mitmTestRuntime(t)
	for _, c := range []struct {
		mode config.MitmMode
		want bool
	}{
		{config.MitmAuto, false},
		{config.MitmOn, true},
		{config.MitmOff, false},
	} {
		rt.Config.Proxy.Mitm = c.mode
		_, enabled, _ := rt.MITMState()
		if enabled != c.want {
			t.Fatalf("mode %s enabled = %v, want %v", c.mode, enabled, c.want)
		}
	}
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "1")
	// Legacy env override still works in auto mode, but an explicit off wins.
	rt.Config.Proxy.Mitm = config.MitmAuto
	_, enabled, _ := rt.MITMState()
	if !enabled {
		t.Fatal("auto mode should honour HAKIMI_GOP_ASSUME_CA=1")
	}
	rt.Config.Proxy.Mitm = config.MitmOff
	_, enabled, _ = rt.MITMState()
	if enabled {
		t.Fatal("proxy.mitm=off must override the env override")
	}
}

func TestApplyMITMPersistsAndRejectsInvalid(t *testing.T) {
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "")
	rt := mitmTestRuntime(t)
	enabled, err := rt.ApplyMITM("on")
	if err != nil || !enabled {
		t.Fatalf("ApplyMITM(on) = %v, %v", enabled, err)
	}
	reloaded, err := config.LoadOrCreate(rt.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Proxy.Mitm != config.MitmOn {
		t.Fatalf("persisted proxy.mitm = %q, want on", reloaded.Proxy.Mitm)
	}
	info := rt.StatusJSON()["mitm"].(map[string]any)
	if info["mode"] != "on" || info["enabled"] != true || info["source"] != "proxy.mitm=on" {
		t.Fatalf("status mitm = %v", info)
	}
	if _, err := rt.ApplyMITM("bogus"); err == nil {
		t.Fatal("expected an error for an invalid mode")
	}
	reloaded, _ = config.LoadOrCreate(rt.Paths)
	if reloaded.Proxy.Mitm != config.MitmOn {
		t.Fatal("an invalid mode must not change the config")
	}
}

// bufferedConn keeps bytes already read past the CONNECT response available
// to the TLS handshake.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func mitmConnect(t *testing.T, rt *Runtime) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(rt.Config.Proxy.Port)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT www.pixiv.net:443 HTTP/1.1\r\nHost: www.pixiv.net:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT status = %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	tlsConn := tls.Client(&bufferedConn{Conn: conn, r: br}, &tls.Config{
		ServerName: "www.pixiv.net", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		t.Fatalf("MITM TLS handshake: %v", err)
	}
	return tlsConn
}

func assertIntercepted(t *testing.T, rt *Runtime) {
	t.Helper()
	tlsConn := mitmConnect(t, rt)
	defer tlsConn.Close()
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificate from MITM")
	}
	subject, _ := rt.CA.Status()["subject"].(string)
	if certs[0].Issuer.String() != subject {
		t.Fatalf("certificate issuer = %q, want local CA %q", certs[0].Issuer.String(), subject)
	}
	if certs[0].Subject.CommonName != "www.pixiv.net" {
		t.Fatalf("certificate subject = %q, want www.pixiv.net", certs[0].Subject.CommonName)
	}
}

func TestPersistedMITMInterceptsWithoutEnv(t *testing.T) {
	// No HAKIMI_GOP_ASSUME_CA: config alone must enable interception.
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "")
	rt := mitmTestRuntime(t)
	rt.Config.Proxy.Mitm = config.MitmOn
	if err := config.Save(rt.Paths, rt.Config); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.LoadOrCreate(rt.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Proxy.Mitm != config.MitmOn {
		t.Fatalf("config did not persist: %q", reloaded.Proxy.Mitm)
	}
	if err := rt.Start(); err != nil {
		t.Fatal(err)
	}
	defer rt.Stop()
	if !rt.HTTP.MITMEnabled() {
		t.Fatal("MITM switch is off at startup")
	}
	assertIntercepted(t, rt)
}

func TestControlMITMAppliesImmediately(t *testing.T) {
	// Trust forced by env, but explicit off must win until we switch to on.
	t.Setenv("HAKIMI_GOP_ASSUME_CA", "1")
	rt := mitmTestRuntime(t)
	rt.Config.Proxy.Mitm = config.MitmOff
	if err := rt.Start(); err != nil {
		t.Fatal(err)
	}
	defer rt.Stop()
	if rt.HTTP.MITMEnabled() {
		t.Fatal("proxy.mitm=off should not intercept")
	}

	enabled, err := rt.ControlMITM("true")
	if err != nil || !enabled || !rt.HTTP.MITMEnabled() {
		t.Fatalf("ControlMITM(on) = %v, %v; switch=%v", enabled, err, rt.HTTP.MITMEnabled())
	}
	reloaded, err := config.LoadOrCreate(rt.Paths)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Proxy.Mitm != config.MitmOn {
		t.Fatalf("control endpoint did not persist the mode: %q", reloaded.Proxy.Mitm)
	}
	assertIntercepted(t, rt)

	enabled, err = rt.ControlMITM("off")
	if err != nil || enabled || rt.HTTP.MITMEnabled() {
		t.Fatalf("ControlMITM(off) = %v, %v; switch=%v", enabled, err, rt.HTTP.MITMEnabled())
	}
}
