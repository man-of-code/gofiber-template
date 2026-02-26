package middleware

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"gofiber_template/internal/models"
)

const (
	auditBufferSize = 512
	auditBatchSize  = 50
)

// AuditLogger asynchronously persists audit events.
type AuditLogger struct {
	db     *gorm.DB
	events chan models.AuditLog
	done   chan struct{}
	wg     sync.WaitGroup
}

// NewAuditLogger creates an async audit logger with batched inserts.
func NewAuditLogger(db *gorm.DB) *AuditLogger {
	a := &AuditLogger{
		db:     db,
		events: make(chan models.AuditLog, auditBufferSize),
		done:   make(chan struct{}),
	}
	a.wg.Add(1)
	go a.run()
	return a
}

func (a *AuditLogger) run() {
	defer a.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	batch := make([]models.AuditLog, 0, auditBatchSize)
	flush := func() {
		if len(batch) == 0 || a.db == nil {
			return
		}
		_ = a.db.Create(&batch).Error
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-a.events:
			batch = append(batch, ev)
			if len(batch) >= auditBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-a.done:
			for {
				select {
				case ev := <-a.events:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Shutdown flushes queued audit events.
func (a *AuditLogger) Shutdown() {
	close(a.done)
	a.wg.Wait()
}

// Middleware captures and submits selected security and mutation actions.
func (a *AuditLogger) Middleware() fiber.Handler {
	if a == nil || a.db == nil {
		return func(c *fiber.Ctx) error { return c.Next() }
	}
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		status := c.Response().StatusCode()
		action, ok := auditActionFor(c.Method(), c.Path(), status)
		if !ok {
			return err
		}

		requestID, _ := c.Locals("request_id").(string)
		clientID, _ := c.Locals("client_id").(string)
		severity := "info"
		switch {
		case status >= fiber.StatusInternalServerError:
			severity = "error"
		case status >= fiber.StatusBadRequest:
			severity = "warn"
		}
		detailJSON, _ := json.Marshal(fiber.Map{
			"method":     c.Method(),
			"path":       c.Path(),
			"status":     status,
			"latency_ms": time.Since(start).Milliseconds(),
			"severity":   severity,
		})
		entry := models.AuditLog{
			RequestID: requestID,
			Action:    action,
			ClientID:  clientID,
			IPAddress: ClientIP(c),
			UserAgent: c.Get("User-Agent"),
			Detail:    string(detailJSON),
			CreatedAt: time.Now(),
		}

		select {
		case a.events <- entry:
		default:
			// Drop instead of blocking request path under pressure.
		}
		return err
	}
}

func auditActionFor(method, path string, status int) (string, bool) {
	switch {
	case method == fiber.MethodPost && path == "/auth/token":
		if status >= fiber.StatusBadRequest {
			return "auth_failed", true
		}
		return "token_issued", true
	case method == fiber.MethodPost && path == "/auth/token/refresh":
		if status >= fiber.StatusBadRequest {
			return "token_refresh_failed", true
		}
		return "token_refreshed", true
	case method == fiber.MethodPost && path == "/auth/token/revoke":
		if status >= fiber.StatusBadRequest {
			return "token_revoke_failed", true
		}
		return "token_revoked", true
	case method == fiber.MethodPost && path == "/admin/clients":
		if status >= fiber.StatusBadRequest {
			return "client_create_failed", true
		}
		return "client_created", true
	case method == fiber.MethodPut && strings.HasPrefix(path, "/admin/clients/"):
		if status >= fiber.StatusBadRequest {
			return "client_update_failed", true
		}
		return "client_updated", true
	case method == fiber.MethodDelete && strings.HasPrefix(path, "/admin/clients/"):
		if status >= fiber.StatusBadRequest {
			return "client_delete_failed", true
		}
		return "client_deleted", true
	case method == fiber.MethodPost && strings.HasPrefix(path, "/admin/clients/") && strings.HasSuffix(path, "/revoke-all"):
		if status >= fiber.StatusBadRequest {
			return "client_revoke_all_failed", true
		}
		return "client_revoke_all", true
	case method == fiber.MethodPost && path == "/api/items":
		if status >= fiber.StatusBadRequest {
			return "item_create_failed", true
		}
		return "item_created", true
	case method == fiber.MethodPut && strings.HasPrefix(path, "/api/items/"):
		if status >= fiber.StatusBadRequest {
			return "item_update_failed", true
		}
		return "item_updated", true
	case method == fiber.MethodDelete && strings.HasPrefix(path, "/api/items/"):
		if status >= fiber.StatusBadRequest {
			return "item_delete_failed", true
		}
		return "item_deleted", true
	case status == fiber.StatusTooManyRequests:
		return "rate_limit_exceeded", true
	case status == fiber.StatusForbidden:
		// IP validator marks blocked requests via c.Locals("ip_blocked", true),
		// but we don't have access here; treat all 403s from early middleware as ip_blocked.
		return "ip_blocked", true
	default:
		return "", false
	}
}
