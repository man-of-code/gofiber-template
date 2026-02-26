package middleware

import (
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
)

// RateLimiter implements sliding-window rate limiting per key (IP or client_id).
type RateLimiter struct {
	mu       sync.RWMutex
	entries  map[string]*rateEntry
	limit    int
	window   time.Duration
	banLimit int // exceed this multiple of limit to get banned
	banDur   time.Duration
	banned   map[string]time.Time
}

type rateEntry struct {
	count    int
	windowAt time.Time
}

func newRateLimiter(limit int, window time.Duration) *RateLimiter {
	banLimit := 5
	if limit > 0 {
		banLimit = limit * 5
	}
	return &RateLimiter{
		entries:  make(map[string]*rateEntry),
		limit:    limit,
		window:   window,
		banLimit: banLimit,
		banDur:   10 * time.Minute,
		banned:   make(map[string]time.Time),
	}
}

func (r *RateLimiter) allow(key string) (allowed bool, retryAfter int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if until, ok := r.banned[key]; ok {
		if now.Before(until) {
			return false, int(until.Sub(now).Seconds())
		}
		delete(r.banned, key)
	}
	e, ok := r.entries[key]
	if !ok {
		r.entries[key] = &rateEntry{count: 1, windowAt: now}
		return true, 0
	}
	if now.Sub(e.windowAt) >= r.window {
		e.count = 1
		e.windowAt = now
		return true, 0
	}
	e.count++
	if e.count > r.limit {
		if e.count >= r.banLimit {
			r.banned[key] = now.Add(r.banDur)
		}
		retrySec := int(r.window.Seconds())
		if rem := r.window - now.Sub(e.windowAt); rem > 0 {
			retrySec = int(rem.Seconds())
		}
		return false, retrySec
	}
	return true, 0
}

func (r *RateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, e := range r.entries {
		if now.Sub(e.windowAt) > r.window*2 {
			delete(r.entries, k)
		}
	}
	for k, until := range r.banned {
		if now.After(until) {
			delete(r.banned, k)
		}
	}
}

// GlobalRateLimit returns middleware that limits requests per IP (global limit).
func GlobalRateLimit(cfg *config.Config) fiber.Handler {
	if cfg == nil || cfg.GlobalRateLimit <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	rl := newRateLimiter(cfg.GlobalRateLimit, time.Minute)
	go func() {
		t := time.NewTicker(time.Minute)
		for range t.C {
			rl.cleanup()
		}
	}()
	return func(c *fiber.Ctx) error {
		key := c.IP()
		allowed, retryAfter := rl.allow(key)
		if !allowed {
			c.Set("Retry-After", strconv.Itoa(retryAfter))
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
		}
		return c.Next()
	}
}

// AuthRateLimit returns middleware for auth endpoints (stricter limit per IP).
func AuthRateLimit(cfg *config.Config) fiber.Handler {
	if cfg == nil || cfg.AuthRateLimit <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	rl := newRateLimiter(cfg.AuthRateLimit, time.Minute)
	return func(c *fiber.Ctx) error {
		key := "auth:" + c.IP()
		allowed, retryAfter := rl.allow(key)
		if !allowed {
			c.Set("Retry-After", strconv.Itoa(retryAfter))
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
		}
		return c.Next()
	}
}

// APIRateLimit returns middleware that limits per client_id (requires JWT, uses client_id from Locals).
func APIRateLimit(cfg *config.Config) fiber.Handler {
	if cfg == nil || cfg.APIRateLimit <= 0 {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	rl := newRateLimiter(cfg.APIRateLimit, time.Minute)
	return func(c *fiber.Ctx) error {
		clientID := c.Locals("client_id")
		if clientID == nil {
			key := "anon:" + c.IP()
			allowed, retryAfter := rl.allow(key)
			if !allowed {
				c.Set("Retry-After", strconv.Itoa(retryAfter))
				return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
			}
			return c.Next()
		}
		key := "api:" + clientID.(string)
		allowed, retryAfter := rl.allow(key)
		if !allowed {
			c.Set("Retry-After", strconv.Itoa(retryAfter))
			return fiber.NewError(fiber.StatusTooManyRequests, "rate limit exceeded")
		}
		return c.Next()
	}
}
