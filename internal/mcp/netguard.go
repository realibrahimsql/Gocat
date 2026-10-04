package mcp

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// ValidateNetworkTarget rejects scan/connect targets that resolve to
// loopback, link-local, private, or cloud-metadata addresses unless the
// operator explicitly allows them. MCP clients can be prompt-injected, so
// network tools are deny-by-default toward sensitive ranges.
//
// Escape hatches:
//   - GOCAT_MCP_ALLOW_PRIVATE=1 (or true/yes) allows private ranges.
//   - GOCAT_MCP_ALLOW_HOSTS="host1,host2" allows listed names verbatim.
func ValidateNetworkTarget(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("empty target host")
	}

	for _, allowed := range strings.Split(os.Getenv("GOCAT_MCP_ALLOW_HOSTS"), ",") {
		if strings.TrimSpace(allowed) != "" && strings.EqualFold(strings.TrimSpace(allowed), host) {
			return nil
		}
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		if ip := net.ParseIP(host); ip == nil {
			return fmt.Errorf("cannot resolve target host: %q", host)
		}
		ips = []net.IP{net.ParseIP(host)}
	}

	allowPrivate := isTruthy(os.Getenv("GOCAT_MCP_ALLOW_PRIVATE"))
	for _, ip := range ips {
		if isSensitiveIP(ip) && !allowPrivate {
			return fmt.Errorf("target %q resolves to restricted address %s (set GOCAT_MCP_ALLOW_HOSTS or GOCAT_MCP_ALLOW_PRIVATE=1 to permit)", host, ip)
		}
	}
	return nil
}

func isSensitiveIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	// Cloud metadata endpoints.
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
