package middleware

import (
	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/services"
)

// TokenBinding returns middleware that verifies IP and fingerprint match for authenticated requests.
// Runs after JWT auth; expects claims in Locals. Skips if no claims (e.g. public route).
func TokenBinding(tokenValidator services.TokenValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := c.Locals("claims")
		if claims == nil {
			return c.Next()
		}
		jwtClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			// Unexpected type in claims local — treat as auth failure, not pass-through
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		ip := ClientIP(c)
		userAgent := c.Get("User-Agent")
		if err := tokenValidator.ValidateBinding(jwtClaims, ip, userAgent); err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		return c.Next()
	}
}
