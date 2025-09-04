package certinfo

import (
	"crypto/x509"
	"net/url"
)

// HostInfo is the result for a single host lookup.
type HostInfo struct {
	// Host is the DNS name (or IP) that was queried.
	Host string `json:"host"`
	// Port is the TCP port used for the TLS connection (default 443 if unspecified).
	Port int `json:"port"`
	// Certs are the non-CA peer certificates (leaf and non-CA intermediates).
	Certs []*x509.Certificate `json:"-"`
}

// DialPolicy controls how outbound TCP connections are established.
type DialPolicy struct {
	// ProxyURL, if set, forces the use of this proxy (http(s) CONNECT or socks5).
	ProxyURL *url.URL
	// NoProxy forces direct connections, ignoring proxy URL and environment.
	NoProxy bool
}
