package middleware

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/validator"
)

// ErrorHandler returns a Fiber error handler with consistent JSON envelopes.
func ErrorHandler(logger *slog.Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		requestID, _ := c.Locals("request_id").(string)
		if requestID == "" {
			requestID = c.Get("X-Request-ID")
		}

		var vErr *validator.Errors
		if errors.As(err, &vErr) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"errors":     vErr.Items,
				"request_id": requestID,
			})
		}

		var fErr *fiber.Error
		if errors.As(err, &fErr) {
			return c.Status(fErr.Code).JSON(fiber.Map{
				"error":      fErr.Message,
				"request_id": requestID,
			})
		}

		if logger != nil {
			logger.Error("request failed",
				"request_id", requestID,
				"method", c.Method(),
				"path", c.Path(),
				"ip", ClientIP(c),
				"error", err.Error(),
			)
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":      "internal server error",
			"request_id": requestID,
		})
	}
}
