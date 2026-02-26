package middleware

import (
	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/services"
)

// TokenBinding returns middleware that verifies IP and fingerprint match for authenticated requests.
// Runs after JWT auth; expects claims in Locals. Skips if no claims (e.g. public route).
func TokenBinding(tokenService *services.TokenService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		claims := c.Locals("claims")
		if claims == nil {
			return c.Next()
		}
		jwtClaims, ok := claims.(*services.JWTClaims)
		if !ok {
			return c.Next()
		}
		ip := c.IP()
		userAgent := c.Get("User-Agent")
		if err := tokenService.ValidateBinding(jwtClaims, ip, userAgent); err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		return c.Next()
	}
}
