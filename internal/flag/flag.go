package flag

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/containeroo/tinyflags"
)

// Options holds all parsed CLI options.
type Options struct {
	Hosts     []string      // Hosts are the positional targets to query (hostnames or URLs).
	Timeout   time.Duration // Timeout is the per-dial TCP timeout.
	Retry     int           // Retry is the number of dial attempts before giving up.
	Output    string        // Output is the output format: "text", "json", or "none".
	Threshold time.Duration // Threshold, if >0, warns when NotAfter is within this duration.
	Proxy     string        // Proxy is an optional proxy URL string (http(s) or socks5).
	NoProxy   bool          // NoProxy forces direct connections (overrides Proxy and env).
	Level     slog.Level    // Level is the log level.
}

// ParseFlags parses command-line flags using tinyflags and returns Options.
func ParseFlags(args []string, version string) (Options, error) {
	var o Options

	fs := tinyflags.NewFlagSet("certinfo", tinyflags.ContinueOnError)
	fs.Version(version)
	// Positional must be a valid URL.
	fs.SetPositionalValidate(func(s string) error {
		u, err := url.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid --proxy: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
			return nil
		default:
			return fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
		}
	})

	// Core network flags
	fs.DurationVar(&o.Timeout, "timeout", 5*time.Second, "Dial timeout").Value()
	fs.IntVar(&o.Retry, "retry", 2, "Retry attempts for TCP connect").Value()

	// Output flags
	fs.StringVar(&o.Output, "output", "text", "Output format: ").
		Choices("text", "json", "none").
		HideAllowed().
		Value()
	fs.DurationVar(&o.Threshold, "threshold", 0, "Warn if cert expires within this duration (e.g. 720h)").Value()

	// Proxy flags
	fs.StringVar(&o.Proxy, "proxy", "", "Proxy URL (http[s]:// or socks5[h]://). Overrides env.").
		OneOfGroup("proxy-choice").
		Value()
	fs.BoolVar(&o.NoProxy, "no-proxy", false, "Bypass all proxies. Overrides --proxy and env.").
		OneOfGroup("proxy-choice").
		Value()

	// Logging
	var silent bool
	fs.BoolVar(&silent, "silent", false, "Suppress normal output; only print expiration warnings").
		Short("s").
		Value()

	// Parse provided args
	if err := fs.Parse(args); err != nil {
		return Options{}, err
	}

	// Logger
	o.Level = slog.LevelInfo
	if silent {
		o.Level = slog.LevelError
	}

	// Positional args are hosts
	o.Hosts = fs.Args()

	return o, nil
}
