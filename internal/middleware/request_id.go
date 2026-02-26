package middleware

import (
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"gofiber_template/internal/config"
)

// RequestID generates or propagates X-Request-ID for each request.
func RequestID(cfg *config.Config) fiber.Handler {
	var trusted []*net.IPNet
	if cfg != nil {
		trusted = parseCIDRs(cfg.TrustedProxies)
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
	if c.Get("X-Request-ID") == "" {
		return false
	}
	xff := c.Get("X-Forwarded-For")
	if xff == "" {
		return len(trusted) == 0
	}
	parts := strings.Split(xff, ",")
	proxyIP := strings.TrimSpace(parts[len(parts)-1])
	ip := net.ParseIP(proxyIP)
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
