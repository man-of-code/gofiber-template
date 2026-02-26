package middleware

import (
	"net"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"gofiber_template/internal/config"
	"gofiber_template/internal/netutil"
)

// RequestID generates or propagates X-Request-ID for each request.
func RequestID(cfg *config.Config) fiber.Handler {
	var trusted []*net.IPNet
	if cfg != nil {
		trusted = netutil.ParseCIDRs(cfg.TrustedProxies)
	}
	return func(c *fiber.Ctx) error {
		reqID := ""
		if requestIDFromTrustedProxy(c, trusted) {
			reqID = c.Get("X-Request-ID")
		}
		if reqID == "" {
			reqID = uuid.New().String()
		}
		c.Set("X-Request-ID", reqID)
		c.Locals("request_id", reqID)
		return c.Next()
	}
}

func requestIDFromTrustedProxy(c *fiber.Ctx, trusted []*net.IPNet) bool {
	if len(trusted) == 0 {
		return false // no trusted proxies configured: never trust incoming ID
	}
	if c.Get("X-Request-ID") == "" {
		return false // nothing to propagate
	}
	// Check whether the direct connection IP is in the trusted set
	directIP := net.ParseIP(c.IP())
	if directIP == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(directIP) {
			return true
		}
	}
	return false
}
