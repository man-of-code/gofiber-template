package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// SecurityHeaders adds security headers to every response.
func SecurityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "0")
		c.Set("Content-Security-Policy", "default-src 'none'")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Cache-Control", "no-store")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// Strip Server and X-Powered-By (Fiber sets ServerHeader: "-" in config)
		return c.Next()
	}
}
