package main

import (
	"fmt"
	"os"
)

// Build-time variables injected via -ldflags.
// Defaults are used when building without make (e.g. go run, go test).
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// init runs before main() and before go-flags parsing.
// Handles --version and exits so go-flags never processes it.
func init() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Printf("aiproxy %s (commit: %s, built: %s)\n", Version, Commit, BuildDate)
			os.Exit(0)
		}
	}
}
