package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/services"
)

// JWTAuth returns middleware that validates JWT and stores claims in Locals.
func JWTAuth(tokenValidator services.TokenValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		auth := c.Get("Authorization")
		if auth == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		accessToken := strings.TrimSpace(parts[1])
		if accessToken == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		claims, err := tokenValidator.ParseJWT(accessToken)
		if err != nil {
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		}
		c.Locals("claims", claims)
		c.Locals("client_id", claims.Subject)
		return c.Next()
	}
}
