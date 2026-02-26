package middleware

import (
	"crypto/subtle"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

// AdminAuth returns middleware that validates the X-Admin-Key header.
func AdminAuth(cfg *config.Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.AdminMasterKey == "" {
			return fiber.NewError(fiber.StatusServiceUnavailable, "admin not configured")
		}
		adminKey := c.Get("X-Admin-Key")
		if !constantTimeEqual(adminKey, cfg.AdminMasterKey) {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		return c.Next()
	}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
