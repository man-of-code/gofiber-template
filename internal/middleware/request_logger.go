package middleware

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
)

// RequestLogger writes structured request logs without sensitive payloads.
func RequestLogger(logger *slog.Logger) fiber.Handler {
	if logger == nil {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start).Milliseconds()
		requestID, _ := c.Locals("request_id").(string)
		clientID, _ := c.Locals("client_id").(string)

		level := slog.LevelInfo
		status := c.Response().StatusCode()
		switch {
		case status >= fiber.StatusInternalServerError:
			level = slog.LevelError
		case status >= fiber.StatusBadRequest:
			level = slog.LevelWarn
		}

		logger.Log(c.Context(), level, "http_request",
			"request_id", requestID,
			"client_id", clientID,
			"ip", c.IP(),
			"method", c.Method(),
			"path", c.Path(),
			"status", status,
			"latency_ms", latency,
		)
		return err
	}
}
