// gop is the Go port of hakimi's CLI: a local HTTP/SOCKS5 proxy with
// PAC routing, DoH, IP selection, MITM and an in-process JS image relay.
package main

import (
	"os"

	"github.com/arick/hakimi-gop/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
