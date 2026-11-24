// Package cli implements the command surface of the Go port.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arick/hakimi-gop/internal/config"
	"github.com/arick/hakimi-gop/internal/runtime"
)

func Main(args []string) int {
	opts := parseGlobals(args)
	if opts.help || len(opts.rest) == 0 {
		usage()
		return 0
	}
	cmd, rest := opts.rest[0], opts.rest[1:]
	rt, err := runtime.New(opts.dataDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gop:", err)
		return 1
	}

	switch cmd {
	case "serve":
		return serve(rt, rest, opts)
	case "status":
		status, err := rt.FetchStatus()
		if err != nil {
			status = rt.StatusJSON()
		}
		if opts.json {
			_ = runtime.PrintJSON(status)
			return 0
		}
		if status["running"] == true || status["status"] == "running" || status["status"] == "paused" {
			printStatusFrom(status)
		} else {
			printStatus(rt)
		}
		return 0
	case "pac":
		if script, err := rt.FetchPAC(); err == nil && strings.Contains(script, "FindProxyForURL") {
			fmt.Print(script)
		} else {
			fmt.Print(rt.PACScript())
		}
		return 0
	case "env":
		return envCommand(rt, rest, opts.json)
	case "stop", "pause", "resume":
		if err := rt.Control(cmd); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Println(map[string]string{"stop": "stopped", "pause": "paused", "resume": "resumed"}[cmd])
		return 0
	case "config":
		return configCommand(rt, rest, opts.json)
	case "group":
		return groupCommand(rt, rest, opts.json)
	case "ca":
		return caCommand(rt, rest, opts.json)
	case "catalog":
		return catalogCommand(rt, rest, opts.json)
	case "doctor":
		return doctorCommand(rt, rest, opts.json)
	case "version":
		fmt.Println("gop 1.0.0")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "gop: unknown command %q\n", cmd)
		usage()
		return 1
	}
}

type globalOptions struct {
	dataDir string
	json    bool
	help    bool
	rest    []string
}

func parseGlobals(args []string) globalOptions {
	out := globalOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--data-dir":
			if i+1 < len(args) {
				i++
				out.dataDir = args[i]
			}
		case "--json":
			out.json = true
		case "-h", "--help":
			out.help = true
		default:
			out.rest = append(out.rest, args[i])
		}
	}
	if env := os.Getenv("HAKIMI_DATA_DIR"); env != "" && out.dataDir == "" {
		out.dataDir = env
	}
	return out
}

func usage() {
	fmt.Print(`gop - Go port of hakimi's local acceleration proxy

Usage:
  gop serve [--paused] [--no-takeover]   start HTTP + SOCKS5 proxy
  gop stop | pause | resume              control a running instance
  gop status [--json]                    runtime status
  gop pac                                print the PAC script
  gop env [--unset] [--json]             shell proxy variables
  gop config show|path|get PATH|set PATH VALUE
  gop group list|show ID|add ID|rm ID|set ID [--enable|--disable]
  gop ca status|import P12 [PASS]|import-base64 [PASS]|export|regenerate
  gop catalog status|refresh
  gop doctor DOMAIN [--json]
  gop version

Global flags: --data-dir DIR  --json
`)
}

func serve(rt *runtime.Runtime, args []string, opts globalOptions) int {
	paused := false
	noTakeover := false
	portChanged := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--paused":
			paused = true
		case "--no-takeover":
			noTakeover = true
		case "--port":
			if i+1 < len(args) {
				i++
				rt.Config.Proxy.Port, _ = strconv.Atoi(args[i])
				portChanged = true
			}
		case "--socks-port":
			if i+1 < len(args) {
				i++
				rt.Config.Proxy.SocksPort, _ = strconv.Atoi(args[i])
				portChanged = true
			}
		}
	}
	_ = noTakeover // the Go port never writes OS proxy settings by default
	// Persist explicit ports so stop/pause/status can reach this instance.
	if portChanged {
		_ = config.Save(rt.Paths, rt.Config)
	}
	if paused {
		rt.Pause()
	}
	if err := rt.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "gop:", err)
		return 1
	}
	fmt.Println("gop 1.0.0 (" + statusWord(rt) + ")")
	fmt.Printf("proxy:        %s\n", rt.ProxyURL())
	fmt.Printf("socks:        %s\n", rt.SOCKSURL())
	fmt.Printf("pac:          %s\n", rt.PACURL())
	fmt.Printf("data:         %s\n", rt.Paths.Root)
	fmt.Printf("relay worker: %s\n", rt.WorkerDescription())
	fmt.Println("press Ctrl+C to stop")
	rt.Wait()
	fmt.Println("stopped")
	return 0
}

func statusWord(rt *runtime.Runtime) string {
	if !rt.IsRunning() {
		return "stopped"
	}
	if rt.Paused() {
		return "paused"
	}
	return "running"
}

func printStatusFrom(status map[string]any) {
	state, _ := status["status"].(string)
	proxyInfo, _ := status["proxy"].(map[string]any)
	fmt.Printf("gop 1.0.0 — %s\n", state)
	fmt.Printf("proxy:        %v\n", proxyInfo["listen"])
	fmt.Printf("socks:        %v\n", proxyInfo["socks"])
	fmt.Printf("pac:          %v\n", proxyInfo["pacUrl"])
}

func printStatus(rt *runtime.Runtime) {
	fmt.Printf("gop 1.0.0 — %s\n", statusWord(rt))
	fmt.Printf("proxy:        %s\n", rt.ProxyURL())
	fmt.Printf("socks:        %s\n", rt.SOCKSURL())
	fmt.Printf("pac:          %s\n", rt.PACURL())
	fmt.Printf("relay worker: %s\n", rt.WorkerDescription())
	if !rt.IsRunning() {
		fmt.Println("start one with `gop serve`")
	}
}

func envCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	unset := false
	for _, a := range args {
		if a == "--unset" {
			unset = true
		}
	}
	if asJSON {
		if unset {
			_ = runtime.PrintJSON(map[string]string{"mode": "unset"})
			return 0
		}
		if rt.Config.Proxy.Mode == "off" {
			_ = runtime.PrintJSON(map[string]string{"mode": "off"})
			return 0
		}
		url := "http://" + net.JoinHostPort(dialHost(rt.Config.Proxy.Bind), strconv.Itoa(rt.Config.Proxy.Port))
		_ = runtime.PrintJSON(map[string]string{"httpProxy": url, "httpsProxy": url, "allProxy": url, "noProxy": "localhost,127.0.0.1,::1"})
		return 0
	}
	if unset || rt.Config.Proxy.Mode == "off" {
		fmt.Println("unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY")
		return 0
	}
	url := "http://" + net.JoinHostPort(dialHost(rt.Config.Proxy.Bind), strconv.Itoa(rt.Config.Proxy.Port))
	fmt.Printf("export HTTP_PROXY=%s\nexport HTTPS_PROXY=%s\nexport ALL_PROXY=%s\nexport NO_PROXY=localhost,127.0.0.1,::1\n", url, url, url)
	return 0
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

func configCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	if len(args) == 0 {
		args = []string{"show"}
	}
	switch args[0] {
	case "path":
		fmt.Println(rt.Paths.ConfigFile())
	case "show":
		if asJSON {
			_ = runtime.PrintJSON(rt.Config)
		} else {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(rt.Config)
		}
	case "get":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: gop config get PATH")
			return 1
		}
		value, err := getPath(rt.Config, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		if s, ok := value.(string); ok {
			fmt.Println(s)
		} else {
			enc := json.NewEncoder(os.Stdout)
			_ = enc.Encode(value)
		}
	case "set":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: gop config set PATH VALUE")
			return 1
		}
		var value any = args[2]
		if err := json.Unmarshal([]byte(args[2]), &value); err != nil {
			value = args[2]
		}
		if err := setPath(rt.Config, args[1], value); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		if err := config.Save(rt.Paths, rt.Config); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Printf("%s = %v\n", args[1], value)
	default:
		fmt.Fprintf(os.Stderr, "gop: unknown config command %q\n", args[0])
		return 1
	}
	return 0
}

// getPath/setPath walk the JSON representation so PATH uses the same dotted
// names as the Rust CLI (groups.0.enabled, advanced.imageRelays.0.base, ...).
func getPath(cfg *config.AppConfig, path string) (any, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	return walk(tree, path, nil)
}

func setPath(cfg *config.AppConfig, path string, value any) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return err
	}
	if _, err := walk(tree, path, &value); err != nil {
		return err
	}
	updated, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	return json.Unmarshal(updated, cfg)
}

func walk(node any, path string, setValue *any) (any, error) {
	parts := strings.Split(path, ".")
	current := node
	for i, part := range parts {
		last := i == len(parts)-1
		switch n := current.(type) {
		case map[string]any:
			v, ok := n[part]
			if !ok {
				return nil, fmt.Errorf("no such setting `%s`", path)
			}
			if last {
				if setValue != nil {
					n[part] = *setValue
				}
				return v, nil
			}
			current = v
		case []any:
			idx, err := strconv.Atoi(part)
			if err != nil || idx < 0 || idx >= len(n) {
				return nil, fmt.Errorf("no such setting `%s`", path)
			}
			if last {
				if setValue != nil {
					n[idx] = *setValue
				}
				return n[idx], nil
			}
			current = n[idx]
		default:
			return nil, fmt.Errorf("no such setting `%s`", path)
		}
	}
	return current, nil
}

func groupCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		if asJSON {
			_ = runtime.PrintJSON(rt.Config.Groups)
			return 0
		}
		fmt.Printf("%-10s %-16s %-5s %-28s %s\n", "id", "name", "state", "default route", "domains")
		for _, g := range rt.Config.Groups {
			state := "off"
			if g.Enabled {
				state = "on"
			}
			fmt.Printf("%-10s %-16s %-5s %-28s %d\n", g.ID, g.Name, state, g.DefaultRoute.Label(), len(g.Domains))
		}
	case "show":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: gop group show ID")
			return 1
		}
		g, ok := rt.Config.Group(args[0])
		if !ok {
			fmt.Fprintf(os.Stderr, "gop: no such group %q\n", args[0])
			return 1
		}
		fmt.Printf("id:      %s\nname:    %s\nstate:   %v\nroute:   %s\n", g.ID, g.Name, g.Enabled, g.DefaultRoute.Label())
		for _, r := range g.Domains {
			fmt.Printf("  %s\n", r.Pattern)
		}
	case "add":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: gop group add ID")
			return 1
		}
		if _, exists := rt.Config.Group(args[0]); exists {
			fmt.Fprintf(os.Stderr, "gop: group `%s` already exists\n", args[0])
			return 1
		}
		rt.Config.SetGroup(config.GroupConfig{ID: args[0], Name: args[0], Enabled: true, DefaultRoute: config.AutoRoute()})
		if err := config.Save(rt.Paths, rt.Config); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Printf("added group `%s`\n", args[0])
	case "rm":
		if len(args) == 0 || !rt.Config.RemoveGroup(args[0]) {
			fmt.Fprintln(os.Stderr, "gop: group not found")
			return 1
		}
		if err := config.Save(rt.Paths, rt.Config); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Printf("removed group `%s`\n", args[0])
	case "set":
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "usage: gop group set ID [--enable|--disable]")
			return 1
		}
		g, ok := rt.Config.Group(args[0])
		if !ok {
			fmt.Fprintf(os.Stderr, "gop: no such group %q\n", args[0])
			return 1
		}
		for _, flag := range args[1:] {
			switch flag {
			case "--enable":
				g.Enabled = true
			case "--disable":
				g.Enabled = false
			}
		}
		rt.Config.SetGroup(g)
		if err := config.Save(rt.Paths, rt.Config); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Printf("id: %s state: %v\n", g.ID, g.Enabled)
	default:
		fmt.Fprintf(os.Stderr, "gop: unknown group command %q\n", sub)
		return 1
	}
	return 0
}

func caCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "status":
		if asJSON {
			_ = runtime.PrintJSON(rt.CA.Status())
		} else {
			status := rt.CA.Status()
			fmt.Printf("subject: %v\ntrusted: %v\ncert:    %v\n", status["subject"], status["trusted"], status["certificate"])
		}
	case "export":
		out := "ca.pem"
		if len(args) > 0 {
			out = args[0]
		}
		if err := rt.CA.Export(out); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Println(out)
	case "import":
		if len(args) < 1 {
			fmt.Fprintln(os.Stderr, "usage: gop ca import <p12-file> [passphrase]")
			return 1
		}
		pass := ""
		if len(args) > 1 {
			pass = args[1]
		} else {
			pass = os.Getenv("HAKIMI_CA_PASSPHRASE")
		}
		if err := rt.CA.ImportP12(args[0], pass); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		printCAStatus(rt, asJSON)
	case "import-base64":
		// Reads a base64-encoded PKCS#12 bundle from stdin.
		pass := ""
		if len(args) > 0 {
			pass = args[0]
		} else {
			pass = os.Getenv("HAKIMI_CA_PASSPHRASE")
		}
		var buf strings.Builder
		if _, err := io.Copy(&buf, os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, "gop: read stdin:", err)
			return 1
		}
		if err := rt.CA.ImportP12Base64(strings.TrimSpace(buf.String()), pass); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		printCAStatus(rt, asJSON)
	case "regenerate":
		if err := rt.CA.Regenerate(); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Println("regenerated")
	default:
		fmt.Fprintf(os.Stderr, "gop: unknown ca command %q (status|import|import-base64|export|regenerate)\n", sub)
		return 1
	}
	return 0
}

func printCAStatus(rt *runtime.Runtime, asJSON bool) {
	if asJSON {
		_ = runtime.PrintJSON(rt.CA.Status())
		return
	}
	status := rt.CA.Status()
	fmt.Printf("subject: %v\ntrusted: %v\ncert:    %v\n", status["subject"], status["trusted"], status["certificate"])
}

func catalogCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "status":
		info := map[string]any{"loadedAt": rt.Catalog.LoadedAt(), "version": rt.Catalog.Version()}
		if asJSON {
			_ = runtime.PrintJSON(info)
		} else {
			fmt.Printf("loadedAt: %v\nversion:  %v\n", info["loadedAt"], info["version"])
		}
	case "refresh":
		if err := rt.Catalog.Load(contextBackground(), true); err != nil {
			fmt.Fprintln(os.Stderr, "gop:", err)
			return 1
		}
		fmt.Println("refreshed")
	default:
		fmt.Fprintf(os.Stderr, "gop: unknown catalog command %q\n", sub)
		return 1
	}
	return 0
}

func doctorCommand(rt *runtime.Runtime, args []string, asJSON bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gop doctor DOMAIN")
		return 1
	}
	host := args[0]
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 2*time.Second)
	result := map[string]any{"domain": host, "state": "normal"}
	if err != nil {
		result["state"] = "failed"
		result["error"] = err.Error()
	} else {
		_ = conn.Close()
		result["ip"] = conn.RemoteAddr().String()
	}
	if asJSON {
		_ = runtime.PrintJSON(result)
	} else {
		fmt.Printf("domain:  %v\nstate:   %v\nip:      %v\nerror:   %v\n", result["domain"], result["state"], result["ip"], result["error"])
	}
	if result["state"] == "failed" {
		return 1
	}
	return 0
}

func contextBackground() context.Context { return context.Background() }
