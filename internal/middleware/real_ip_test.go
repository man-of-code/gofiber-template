package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

func TestRealIP_NoXFF_ReturnsDirectIP(t *testing.T) {
	cfg := &config.Config{}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Get("/", func(c *fiber.Ctx) error {
		ip := ClientIP(c)
		return c.SendString(ip)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:9999"
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	// With no XFF, ClientIP must be the direct connection IP (Fiber may return with or without port)
	if body == "" {
		t.Error("ClientIP should be non-empty")
	}
	// In test, Fiber's app.Test may provide 0.0.0.0; in production RemoteAddr is used
	if body != "192.168.1.100" && body != "192.168.1.100:9999" && body != "0.0.0.0" {
		t.Errorf("ClientIP = %q", body)
	}
}

func TestRealIP_XFFWithoutTrustedProxy_Ignored(t *testing.T) {
	cfg := &config.Config{TrustedProxies: nil, TrustedProxyDepth: 1}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Get("/", func(c *fiber.Ctx) error {
		ip := ClientIP(c)
		return c.SendString(ip)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	// Without trusted proxies, XFF must be ignored -> we get direct IP (not 203.0.113.50 from XFF)
	if body == "203.0.113.50" || body == "70.41.3.18" {
		t.Errorf("XFF without trusted proxy must not be used; ClientIP = %q", body)
	}
}

func TestRealIP_XFFWithTrustedProxy_ExtractsClient(t *testing.T) {
	// Trust 10.0.0.0/8; direct connection from 10.0.0.1 (proxy), X-Forwarded-For: client, 10.0.0.1
	cfg := &config.Config{
		TrustedProxies:    []string{"10.0.0.0/8"},
		TrustedProxyDepth: 1,
	}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Get("/", func(c *fiber.Ctx) error {
		ip := ClientIP(c)
		return c.SendString(ip)
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:80"
	req.Header.Set("X-Forwarded-For", "192.168.2.50, 10.0.0.1")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if body != "192.168.2.50" {
		t.Errorf("ClientIP = %q, want 192.168.2.50 (client from XFF)", body)
	}
}

func TestClientIP_FallbackToDirectWhenNoRealIP(t *testing.T) {
	app := fiber.New()
	// No RealIP middleware; ClientIP should fall back to c.IP()
	app.Get("/", func(c *fiber.Ctx) error {
		ip := ClientIP(c)
		return c.SendString(ip)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.16.0.1:443"
	resp, _ := app.Test(req)
	body := readBody(t, resp)
	if body == "" {
		t.Error("ClientIP fallback should be non-empty")
	}
	// app.Test may yield 0.0.0.0 when no real connection
	if body != "172.16.0.1" && body != "172.16.0.1:443" && body != "0.0.0.0" {
		t.Errorf("fallback IP = %q", body)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
