package middleware

import (
	"net"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
	"gofiber_template/internal/netutil"
)

// RealIP extracts the real client IP and stores it in Locals("real_ip").
// All downstream middleware should use ClientIP instead of c.IP().
func RealIP(cfg *config.Config) fiber.Handler {
	var trustedProxies = []*net.IPNet{}
	depth := 0
	if cfg != nil {
		trustedProxies = netutil.ParseCIDRs(cfg.TrustedProxies)
		depth = cfg.TrustedProxyDepth
	}
	return func(c *fiber.Ctx) error {
		ip := netutil.GetClientIP(c.IP(), c.Get("X-Forwarded-For"), trustedProxies, depth)
		c.Locals("real_ip", ip)
		return c.Next()
	}
}

// ClientIP returns the real client IP from Locals, falling back to c.IP().
func ClientIP(c *fiber.Ctx) string {
	if ip, ok := c.Locals("real_ip").(string); ok && ip != "" {
		return ip
	}
	return c.IP()
}
