package middleware

import (
	"crypto/sha256"
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
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
