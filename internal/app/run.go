package app

import (
	"context"
	"fmt"
	"io"

	"github.com/containeroo/certinfo/internal/certinfo"
	"github.com/containeroo/certinfo/internal/flag"
	"github.com/containeroo/certinfo/internal/logging"
	"github.com/containeroo/certinfo/internal/output"
	"github.com/containeroo/tinyflags"
)

// Run parses flags, performs the lookups, and writes output.
func Run(ctx context.Context, version, commit string, args []string, w io.Writer) error {
	// Parse and validate command-line flags.
	opts, err := flag.ParseFlags(args, version)
	if err != nil {
		if tinyflags.IsHelpRequested(err) || tinyflags.IsVersionRequested(err) {
			_, _ = io.WriteString(w, err.Error())
			return nil
		}
		return fmt.Errorf("CLI flags error: %w", err)
	}
	if len(opts.Hosts) == 0 {
		return fmt.Errorf("no hosts provided")
	}

	// Setup logger.
	logger := logging.SetupLogger(w, opts.Level)

	// Set dial policy from flags: --no-proxy > --proxy > environment.
	var policy certinfo.DialPolicy
	if err := certinfo.SetPolicy(&policy, opts.NoProxy, opts.Proxy); err != nil {
		return err
	}

	// Fetch certificates (resolves per-host ports and respects proxy policy).
	infos := certinfo.FetchHostCertInfo(opts.Hosts, opts.Timeout, opts.Retry, policy, logger)

	// Write the chosen output format.
	output.Write(w, opts.Output, infos)

	// Optionally warn about impending expirations.
	output.CheckCertExpiration(opts.Threshold, infos)

	// Merge and print any errors collected during processing.
	return certinfo.WriteErrors(opts.Output)
}
