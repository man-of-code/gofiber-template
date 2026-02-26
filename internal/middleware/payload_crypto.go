package middleware

import (
	"encoding/hex"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/services"
)

// PayloadCrypto returns middleware that decrypts request body when X-Encrypted-Payload: true.
// If decryption fails or cryptoService is nil, returns 400.
func PayloadCrypto(cryptoService services.PayloadCryptor, requireEncrypted bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		isEncrypted := c.Get("X-Encrypted-Payload") == "true"
		isMutating := c.Method() == "POST" || c.Method() == "PUT" ||
			c.Method() == "PATCH" || c.Method() == "DELETE"

		if requireEncrypted && isMutating && !isEncrypted && len(c.Body()) > 0 {
			return fiber.NewError(fiber.StatusBadRequest, "encrypted payload required")
		}

		if cryptoService == nil || !isEncrypted {
			return c.Next()
		}
		body := c.Body()
		if len(body) == 0 {
			return c.Next()
		}
		ct, err := hex.DecodeString(string(body))
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid encrypted payload")
		}
		pt, err := cryptoService.DecryptPayload(ct)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "decryption failed")
		}
		c.Request().SetBody(pt)
		c.Request().Header.SetContentTypeBytes([]byte(fiber.MIMEApplicationJSON))
		c.Locals("encrypted_response", true)
		return c.Next()
	}
}

// EncryptResponse encrypts the response body if the request was encrypted.
func EncryptResponse(cryptoService services.PayloadCryptor) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := c.Next(); err != nil {
			return err
		}
		if cryptoService == nil || c.Locals("encrypted_response") != true {
			return nil
		}
		body := c.Response().Body()
		if len(body) == 0 {
			return nil
		}
		ct, err := cryptoService.EncryptPayload(body)
		if err != nil {
			return err
		}
		c.Response().SetBody([]byte(hex.EncodeToString(ct)))
		c.Set("Content-Type", "application/octet-stream")
		return nil
	}
}
