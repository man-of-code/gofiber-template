package netutil

import (
	"net"
	"testing"
)

func TestGetClientIP_NoXFF(t *testing.T) {
	got := GetClientIP("192.168.1.1", "", nil, 1)
	if got != "192.168.1.1" {
		t.Errorf("GetClientIP(no XFF) = %q, want 192.168.1.1", got)
	}
}

func TestGetClientIP_EmptyTrustedProxies(t *testing.T) {
	got := GetClientIP("192.168.1.1", "10.0.0.1, 192.168.1.2", []*net.IPNet{}, 1)
	if got != "192.168.1.1" {
		t.Errorf("GetClientIP(empty trusted) = %q, want 192.168.1.1 (direct)", got)
	}
}

func TestGetClientIP_UntrustedProxy(t *testing.T) {
	_, proxyNet, _ := net.ParseCIDR("10.0.0.0/8")
	trusted := []*net.IPNet{proxyNet}
	// XFF says last hop is 203.0.113.1 (not in 10.0.0.0/8), so we should not trust XFF
	got := GetClientIP("192.168.1.1", "192.168.1.2, 203.0.113.1", trusted, 1)
	if got != "192.168.1.1" {
		t.Errorf("GetClientIP(untrusted last hop) = %q, want 192.168.1.1", got)
	}
}

func TestGetClientIP_TrustedProxy(t *testing.T) {
	_, proxyNet, _ := net.ParseCIDR("10.0.0.0/8")
	trusted := []*net.IPNet{proxyNet}
	// Last hop 10.0.0.1 is trusted; depth 1 -> client is 192.168.1.2
	got := GetClientIP("10.0.0.1", "192.168.1.2, 10.0.0.1", trusted, 1)
	if got != "192.168.1.2" {
		t.Errorf("GetClientIP(trusted proxy) = %q, want 192.168.1.2", got)
	}
}

func TestParseCIDRs_ValidAndInvalid(t *testing.T) {
	in := []string{"192.168.0.0/24", "invalid", "10.0.0.0/8"}
	out := ParseCIDRs(in)
	if len(out) != 2 {
		t.Fatalf("ParseCIDRs: got %d nets, want 2", len(out))
	}
}

func TestParseAllowedIPs_Empty(t *testing.T) {
	for _, s := range []string{"", "[]"} {
		out := ParseAllowedIPs(s)
		if out != nil {
			t.Errorf("ParseAllowedIPs(%q) = %v, want nil", s, out)
		}
	}
}

func TestParseAllowedIPs_Valid(t *testing.T) {
	out := ParseAllowedIPs(`["192.168.0.0/24","10.0.0.0/8"]`)
	if len(out) != 2 {
		t.Fatalf("got len %d, want 2", len(out))
	}
	if out[0] != "192.168.0.0/24" || out[1] != "10.0.0.0/8" {
		t.Errorf("got %v", out)
	}
}

func TestIPInRanges_EmptyRanges(t *testing.T) {
	if !IPInRanges("192.168.1.1", nil) {
		t.Error("IPInRanges(empty ranges) should be true")
	}
	if !IPInRanges("192.168.1.1", []string{}) {
		t.Error("IPInRanges(empty slice) should be true")
	}
}

func TestIPInRanges_Match(t *testing.T) {
	ranges := []string{"192.168.0.0/24", "10.0.0.0/8"}
	if !IPInRanges("192.168.0.5", ranges) {
		t.Error("192.168.0.5 should be in 192.168.0.0/24")
	}
	if !IPInRanges("10.1.2.3", ranges) {
		t.Error("10.1.2.3 should be in 10.0.0.0/8")
	}
}

func TestIPInRanges_NoMatch(t *testing.T) {
	ranges := []string{"192.168.0.0/24"}
	if IPInRanges("10.0.0.1", ranges) {
		t.Error("10.0.0.1 should not be in 192.168.0.0/24")
	}
	if IPInRanges("not-an-ip", ranges) {
		t.Error("invalid IP should return false")
	}
}
