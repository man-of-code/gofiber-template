package middleware

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

func TestGlobalRateLimit_AllowsUnderLimit(t *testing.T) {
	cfg := &config.Config{GlobalRateLimit: 10}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Use(GlobalRateLimit(cfg))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != fiber.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
		if limit := resp.Header.Get("X-RateLimit-Limit"); limit != "10" {
			t.Errorf("X-RateLimit-Limit = %q, want 10", limit)
		}
	}
}

func TestGlobalRateLimit_BlocksOverLimit(t *testing.T) {
	cfg := &config.Config{GlobalRateLimit: 2}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Use(GlobalRateLimit(cfg))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	var lastStatus int
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.2:12345"
		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		lastStatus = resp.StatusCode
		if i < 2 && resp.StatusCode != fiber.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i+1, resp.StatusCode)
		}
		if i >= 2 && resp.StatusCode != fiber.StatusTooManyRequests {
			t.Errorf("request %d: status = %d, want 429", i+1, resp.StatusCode)
		}
	}
	if lastStatus != fiber.StatusTooManyRequests {
		t.Errorf("last request status = %d, want 429", lastStatus)
	}
}

func TestGlobalRateLimit_SetsRetryAfterWhenLimited(t *testing.T) {
	cfg := &config.Config{GlobalRateLimit: 1}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Use(GlobalRateLimit(cfg))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	// First request OK
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.3:12345"
	resp, _ := app.Test(req)
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("first request: status = %d", resp.StatusCode)
	}
	// Second request limited
	resp2, _ := app.Test(req)
	if resp2.StatusCode != fiber.StatusTooManyRequests {
		t.Fatalf("second request: status = %d", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Error("expected Retry-After header when rate limited")
	}
}

func TestGlobalRateLimit_DisabledWhenZero(t *testing.T) {
	cfg := &config.Config{GlobalRateLimit: 0}
	handler := GlobalRateLimit(cfg)
	if handler == nil {
		t.Fatal("handler should not be nil")
	}
	app := fiber.New()
	app.Use(handler)
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })
	req := httptest.NewRequest("GET", "/", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != fiber.StatusOK {
		t.Errorf("status = %d when limit 0 (disabled)", resp.StatusCode)
	}
}

func TestAuthRateLimit_KeysByIP(t *testing.T) {
	cfg := &config.Config{AuthRateLimit: 2}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Use(AuthRateLimit(cfg))
	app.Post("/login", func(c *fiber.Ctx) error { return c.SendString("ok") })

	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "192.168.1.10:1"
	for i := 0; i < 3; i++ {
		resp, _ := app.Test(req)
		if i < 2 && resp.StatusCode != fiber.StatusOK {
			t.Errorf("request %d: want 200, got %d", i+1, resp.StatusCode)
		}
		if i == 2 && resp.StatusCode != fiber.StatusTooManyRequests {
			t.Errorf("request 3: want 429, got %d", resp.StatusCode)
		}
	}
}

func TestAPIRateLimit_AnonymousUsesIP(t *testing.T) {
	cfg := &config.Config{APIRateLimit: 1}
	app := fiber.New()
	app.Use(RealIP(cfg))
	app.Use(APIRateLimit(cfg))
	app.Get("/api/items", func(c *fiber.Ctx) error { return c.SendString("[]") })

	req := httptest.NewRequest("GET", "/api/items", nil)
	req.RemoteAddr = "192.168.1.20:1"
	resp1, _ := app.Test(req)
	resp2, _ := app.Test(req)
	if resp1.StatusCode != fiber.StatusOK {
		t.Errorf("first: %d", resp1.StatusCode)
	}
	if resp2.StatusCode != fiber.StatusTooManyRequests {
		t.Errorf("second (anon): want 429, got %d", resp2.StatusCode)
	}
}

func TestRateLimiter_Allow_ReturnsRemaining(t *testing.T) {
	rl := newRateLimiter(5, time.Minute)
	allowed, remaining, _ := rl.allow("key1")
	if !allowed {
		t.Error("first request should be allowed")
	}
	if remaining != 4 {
		t.Errorf("remaining = %d, want 4", remaining)
	}
}

// Test that cleanup removes stale entries.
func TestRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	rl := newRateLimiter(10, time.Minute)
	defer rl.Stop()
	rl.allow("k1")
	rl.allow("k2")

	// Manually backdate the entries so cleanup treats them as stale (older than 2*window).
	rl.mu.Lock()
	now := time.Now().Unix()
	windowSeconds := int64(time.Minute.Seconds())
	oldTS := now - windowSeconds*2 - 1
	for _, e := range rl.entries {
		for ts := range e.counts {
			delete(e.counts, ts)
		}
		e.counts[oldTS] = 1
	}
	rl.mu.Unlock()

	rl.cleanup()

	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n != 0 {
		t.Errorf("expected all entries evicted after cleanup, got %d", n)
	}
}
