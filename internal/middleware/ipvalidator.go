package middleware

import (
	"log/slog"
	"net"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
	"gofiber_template/internal/netutil"
)

// IPValidator returns middleware that validates client IP against whitelist/blacklist.
// Modes: whitelist (only allow listed), blacklist (block listed), off (no check).
func IPValidator(cfg *config.Config) fiber.Handler {
	if cfg == nil || cfg.IPMode == "off" {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	cache := &ipValidatorCache{
		allowed: netutil.ParseCIDRs(cfg.GlobalAllowedIPs),
		blocked: netutil.ParseCIDRs(cfg.GlobalBlockedIPs),
	}
	return func(c *fiber.Ctx) error {
		ip := ClientIP(c) // Use the single canonical source — already set by RealIP middleware
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
