package certinfo

import (
	"fmt"
	"net/url"
	"strings"
)

// SetPolicy sets the DialPolicy from the provided flags.
func SetPolicy(policy *DialPolicy, noProxy bool, proxy string) error {
	if noProxy {
		policy.NoProxy = true
		return nil
	}

	if proxy != "" {
		u, err := url.Parse(proxy)
		if err != nil {
			return fmt.Errorf("invalid proxy URL: %w", err)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https", "socks5", "socks5h":
			policy.ProxyURL = u
		default:
			return fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
		}
	}
	return nil
}
