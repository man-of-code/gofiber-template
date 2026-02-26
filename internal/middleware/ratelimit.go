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
	counts map[int64]int // unix second -> count
}

func newRateLimiter(limit int, window time.Duration) *RateLimiter {
	banLimit := 5
	if limit > 0 {
		banLimit = limit * 5
	}
	rl := &RateLimiter{
		entries:  make(map[string]*rateEntry),
		limit:    limit,
		window:   window,
		banLimit: banLimit,
		banDur:   10 * time.Minute,
		banned:   make(map[string]time.Time),
	}
	go func() {
		t := time.NewTicker(window)
		for range t.C {
			rl.cleanup()
		}
	}()
	return rl
}

func (r *RateLimiter) allow(key string) (allowed bool, retryAfter int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	sec := now.Unix()
	windowSeconds := int64(r.window.Seconds())
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	windowStart := sec - windowSeconds + 1

	if until, ok := r.banned[key]; ok {
		if now.Before(until) {
			return false, int(until.Sub(now).Seconds())
		}
		delete(r.banned, key)
	}
	e, ok := r.entries[key]
	if !ok {
		e = &rateEntry{counts: make(map[int64]int)}
		r.entries[key] = e
	}
	e.counts[sec]++

	total := 0
	var earliest int64 = 0
	for ts, cnt := range e.counts {
		if ts < windowStart {
			delete(e.counts, ts)
			continue
		}
		total += cnt
		if earliest == 0 || ts < earliest {
			earliest = ts
		}
	}

	if total > r.limit {
		if total >= r.banLimit {
			r.banned[key] = now.Add(r.banDur)
		}
		retrySec := int(windowSeconds)
		if earliest != 0 {
			rem := (earliest + windowSeconds) - sec
			if rem > 0 {
				retrySec = int(rem)
			}
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
		// Drop entries with only old buckets.
		sec := now.Unix()
		windowSeconds := int64(r.window.Seconds())
		if windowSeconds <= 0 {
			windowSeconds = 60
		}
		windowStart := sec - windowSeconds*2
		for ts := range e.counts {
			if ts < windowStart {
				delete(e.counts, ts)
			}
		}
		if len(e.counts) == 0 {
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
