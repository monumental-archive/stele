// Command stele is the org's evidence engine and its public verifier:
// derive, assert, emit, verify. Workflows orchestrate, GitHub signs,
// stele computes and checks. main stays two lines thin — everything
// with behaviour lives in internal/cli where it is table-tested.
package main

import (
	"os"

	"github.com/monumental-archive/stele/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
