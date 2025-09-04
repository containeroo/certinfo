package certinfo

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	xhttpproxy "golang.org/x/net/http/httpproxy"
	xproxy "golang.org/x/net/proxy"
)

// dialFunc is a simplified dial signature used by the fetcher.
type dialFunc func(network, address string) (net.Conn, error)

// makeProxyAwareDialer returns a dialer that honors NoProxy/ProxyURL,
// or falls back to environment (HTTP(S)_PROXY, NO_PROXY) when neither is set.
//
// - Direct when NoProxy or NO_PROXY matches
// - HTTP CONNECT when scheme is http/https
// - SOCKS5 when scheme is socks5/socks5h
func makeProxyAwareDialer(base *net.Dialer, host string, port int, policy DialPolicy) dialFunc {
	// 1) --no-proxy? => force direct
	if policy.NoProxy {
		return base.Dial
	}

	// 2) --proxy takes priority over env
	var proxyURL *url.URL
	if policy.ProxyURL != nil {
		proxyURL = policy.ProxyURL
	} else {
		// 3) fall back to environment rules
		cfg := xhttpproxy.FromEnvironment()
		reqURL := &url.URL{Scheme: "https", Host: net.JoinHostPort(host, strconv.Itoa(port))}
		proxyURL, _ = cfg.ProxyFunc()(reqURL)
	}

	// Honor NO_PROXY (ProxyFunc returns nil).
	if proxyURL == nil {
		return base.Dial
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https":
		// HTTP CONNECT tunnel
		return func(network, address string) (net.Conn, error) {
			paddr := proxyURL.Host
			if !strings.Contains(paddr, ":") {
				// Common default; real proxies should specify a port.
				paddr = net.JoinHostPort(paddr, "8080")
			}
			pconn, err := base.Dial(network, paddr)
			if err != nil {
				return nil, err
			}

			// Optional basic auth
			authHeader := ""
			if u := proxyURL.User; u != nil {
				if pw, ok := u.Password(); ok {
					cred := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + pw))
					authHeader = "Proxy-Authorization: Basic " + cred + "\r\n"
				}
			}

			target := address
			if target == "" {
				target = net.JoinHostPort(host, strconv.Itoa(port))
			}
			req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, authHeader)
			if _, err := pconn.Write([]byte(req)); err != nil {
				_ = pconn.Close()
				return nil, err
			}

			br := bufio.NewReader(pconn)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil {
				_ = pconn.Close()
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				_ = pconn.Close()
				return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
			}
			return pconn, nil
		}

	case "socks5", "socks5h":
		// SOCKS5 tunnel
		return func(network, address string) (net.Conn, error) {
			var auth *xproxy.Auth
			if proxyURL.User != nil {
				user := proxyURL.User.Username()
				pw, _ := proxyURL.User.Password()
				auth = &xproxy.Auth{User: user, Password: pw}
			}
			dialSocks, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, base)
			if err != nil {
				return nil, err
			}
			return dialSocks.Dial(network, address)
		}

	default:
		// Unknown proxy type; fall back to direct
		return base.Dial
	}
}
