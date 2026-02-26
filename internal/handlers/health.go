package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// Health returns a simple health check response.
func Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}
