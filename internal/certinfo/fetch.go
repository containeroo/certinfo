package certinfo

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FetchHostCertInfo connects to each host and returns peer certificates.
//
// Each input target may be "host", "host:port", or a URL like "https://host[:port]".
// Missing ports default to 443. It tunnels through proxies when configured,
// but keeps TLS end-to-end to the origin (unless a corporate MITM proxy is in place).
func FetchHostCertInfo(targets []string, timeout time.Duration, retry int, policy DialPolicy, logger *slog.Logger) []HostInfo {
	hosts := parseTargets(targets)
	out := make([]HostInfo, 0, len(hosts))
	for _, hi := range hosts {
		info := HostInfo{Host: hi.Host, Port: hi.Port}
		if err := info.getCerts(timeout, retry, policy, logger); err != nil {
			errs.Push(err)
			continue
		}
		out = append(out, info)
	}
	return out
}

// parseTargets converts arbitrary host/URL strings into HostInfo with a resolved port.
// Defaults to 443 if no explicit port is provided.
func parseTargets(in []string) []HostInfo {
	const defaultPort = 443
	out := make([]HostInfo, 0, len(in))
	for _, raw := range in {
		// Try URL parse first (handles https://host[:port], etc.)
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			host := u.Hostname()
			portStr := u.Port()
			port := defaultPort
			if portStr != "" {
				if p, err := strconv.Atoi(portStr); err == nil {
					port = p
				}
			}
			if host != "" {
				out = append(out, HostInfo{Host: host, Port: port})
				continue
			}
		}

		// If not a URL, it may be "host" or "host:port".
		host := raw
		port := defaultPort

		// Handle [IPv6]:port or host:port
		if strings.HasPrefix(raw, "[") {
			// Likely [v6]:port form
			if h, p, err := net.SplitHostPort(raw); err == nil {
				host = strings.Trim(h, "[]")
				if pi, err := strconv.Atoi(p); err == nil {
					port = pi
				}
			} else {
				// Maybe just bare [v6] without port
				host = strings.Trim(raw, "[]")
			}
		} else if strings.Contains(raw, ":") {
			// Try host:port (but beware IPv6 without brackets)
			if h, p, err := net.SplitHostPort(raw); err == nil {
				host = h
				if pi, err := strconv.Atoi(p); err == nil {
					port = pi
				}
			} else {
				// If SplitHostPort failed, treat entire raw as hostname without port.
				host = raw
			}
		}

		out = append(out, HostInfo{Host: host, Port: port})
	}
	return out
}

// getCerts dials the host (with proxy policy) and performs a TLS handshake,
// retaining the peer certificate chain (non-CA certs).
func (h *HostInfo) getCerts(timeout time.Duration, retry int, policy DialPolicy, logger *slog.Logger) error {
	addr := net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
	logger.Info("connecting", "address", addr)

	dialer := &net.Dialer{Timeout: timeout}
	dial := makeProxyAwareDialer(dialer, h.Host, h.Port, policy)

	var raw net.Conn
	var err error
	for i := range retry {
		raw, err = dial("tcp", addr)
		if err == nil {
			break
		}
		logger.Warn("connect attempt failed", "attempt", i+1, "retry_total", retry, "error", err)
	}
	if raw == nil {
		return fmt.Errorf("cannot connect to %s: %w", addr, err)
	}

	// We only need to read the chain; verification is disabled.
	// SNI MUST be set to get the correct leaf on multi-tenant frontends.
	conf := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: we inspect, not verify
		ServerName:         h.Host,
	}

	conn := tls.Client(raw, conf)
	defer conn.Close() // nolint:errcheck

	if err := conn.Handshake(); err != nil {
		return err
	}

	pc := conn.ConnectionState().PeerCertificates
	h.Certs = h.Certs[:0]
	for _, cert := range pc {
		if cert.IsCA {
			continue
		}
		h.Certs = append(h.Certs, cert)
	}
	return nil
}
