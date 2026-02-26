package middleware

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

func TestAdminAuth_ValidKeyPasses(t *testing.T) {
	cfg := &config.Config{AdminMasterKey: "secret-admin-key"}
	app := fiber.New()
	app.Use(AdminAuth(cfg))
	app.Get("/admin/clients", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/admin/clients", nil)
	req.Header.Set("X-Admin-Key", "secret-admin-key")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Errorf("body = %q", body)
	}
}

func TestAdminAuth_InvalidKeyReturns401(t *testing.T) {
	cfg := &config.Config{AdminMasterKey: "secret-admin-key"}
	app := fiber.New()
	app.Use(AdminAuth(cfg))
	app.Get("/admin/clients", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/admin/clients", nil)
	req.Header.Set("X-Admin-Key", "wrong-key")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminAuth_MissingKeyReturns401(t *testing.T) {
	cfg := &config.Config{AdminMasterKey: "secret-admin-key"}
	app := fiber.New()
	app.Use(AdminAuth(cfg))
	app.Get("/admin/clients", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/admin/clients", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminAuth_EmptyConfigReturns503(t *testing.T) {
	cfg := &config.Config{AdminMasterKey: ""}
	app := fiber.New()
	app.Use(AdminAuth(cfg))
	app.Get("/admin/clients", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("GET", "/admin/clients", nil)
	req.Header.Set("X-Admin-Key", "any")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 when admin not configured", resp.StatusCode)
	}
}
