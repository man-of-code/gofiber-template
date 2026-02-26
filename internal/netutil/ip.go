package netutil

import (
	"encoding/json"
	"net"
	"strings"
)

// GetClientIP extracts the real client IP, respecting trusted proxy depth.
// If trustedProxies is empty or XFF is absent, falls back to directIP.
// Only honors X-Forwarded-For when the direct connection IP is within a trusted proxy range.
func GetClientIP(directIP, xff string, trustedProxies []*net.IPNet, trustedProxyDepth int) string {
	if xff == "" || len(trustedProxies) == 0 {
		return directIP
	}

	// Only honor XFF when the direct connection comes from a trusted proxy.
	direct := net.ParseIP(directIP)
	if direct == nil {
		return directIP
	}
	trusted := false
	for _, n := range trustedProxies {
		if n.Contains(direct) {
			trusted = true
			break
		}
	}
	if !trusted {
		return directIP
	}

	parts := strings.Split(strings.ReplaceAll(xff, " ", ""), ",")

	depth := trustedProxyDepth
	if depth <= 0 || depth >= len(parts) {
		depth = len(parts) - 1
	}
	idx := len(parts) - 1 - depth
	if idx < 0 {
		idx = 0
	}
	ip := strings.TrimSpace(parts[idx])
	if ip != "" {
		return ip
	}
	return directIP
}

// ParseCIDRs parses a slice of CIDR strings into net.IPNet objects, skipping invalid ones.
func ParseCIDRs(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

// ParseAllowedIPs parses a JSON array of CIDR strings.
func ParseAllowedIPs(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// IPInRanges checks if ip is in any of the CIDR ranges.
// Returns true if ranges is empty (no restriction).
func IPInRanges(ipStr string, ranges []string) bool {
	if len(ranges) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
