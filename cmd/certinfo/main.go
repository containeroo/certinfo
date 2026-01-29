package main

import (
	"context"
	"os"

	"github.com/containeroo/certinfo/internal/app"
)

var (
	Version string = "dev"
	Commit  string = "none"
)

// main sets up the application context and runs the main loop.
func main() {
	ctx := context.Background()

	if err := app.Run(ctx, Version, Commit, os.Args[1:], os.Stdout); err != nil {
		os.Exit(1)
	}
}
