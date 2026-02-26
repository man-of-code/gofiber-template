package middleware

import (
	"log/slog"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

// IPValidator returns middleware that validates client IP against whitelist/blacklist.
// Modes: whitelist (only allow listed), blacklist (block listed), off (no check).
func IPValidator(cfg *config.Config) fiber.Handler {
	if cfg == nil || cfg.IPMode == "off" {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	cache := &ipValidatorCache{
		allowed: parseCIDRs(cfg.GlobalAllowedIPs),
		blocked: parseCIDRs(cfg.GlobalBlockedIPs),
	}
	return func(c *fiber.Ctx) error {
		ip := getClientIP(c, cfg)
		allowed := cache.isAllowed(ip)
		blocked := cache.isBlocked(ip)
		switch cfg.IPMode {
		case "whitelist":
			if !allowed {
				slog.Warn("ip blocked by whitelist", "ip", ip, "path", c.Path())
				c.Locals("ip_blocked", true)
				return fiber.NewError(fiber.StatusForbidden, "forbidden")
			}
		case "blacklist":
			if blocked {
				slog.Warn("ip blocked by blacklist", "ip", ip, "path", c.Path())
				c.Locals("ip_blocked", true)
				return fiber.NewError(fiber.StatusForbidden, "forbidden")
			}
		}
		return c.Next()
	}
}

func getClientIP(c *fiber.Ctx, cfg *config.Config) string {
	xff := c.Get("X-Forwarded-For")
	if xff == "" {
		return c.IP()
	}
	parts := strings.Split(strings.ReplaceAll(xff, " ", ""), ",")
	depth := cfg.TrustedProxyDepth
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
	return c.IP()
}

type ipValidatorCache struct {
	allowed []*net.IPNet
	blocked []*net.IPNet
}

func (v *ipValidatorCache) isAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if len(v.allowed) == 0 {
		return false
	}
	for _, n := range v.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (v *ipValidatorCache) isBlocked(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range v.blocked {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDRs(cidrs []string) []*net.IPNet {
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
