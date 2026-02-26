package handlers

import (
	"crypto/subtle"
	"strings"

	"github.com/gofiber/fiber/v2"

	"gofiber_template/internal/config"
	"gofiber_template/internal/services"
	"gofiber_template/internal/validator"
)

// AuthHandler handles auth and admin client endpoints.
type AuthHandler struct {
	AuthService  *services.AuthService
	TokenService *services.TokenService
	Config       *config.Config
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// RegisterClientRequest is the JSON body for client registration.
type RegisterClientRequest struct {
	Name       string   `json:"name"`
	AllowedIPs []string `json:"allowed_ips"`
}

// RegisterClient creates a new client (admin only).
func (h *AuthHandler) RegisterClient(c *fiber.Ctx) error {
	if h.Config.AdminMasterKey == "" {
		return fiber.NewError(fiber.StatusServiceUnavailable, "admin not configured")
	}
	adminKey := c.Get("X-Admin-Key")
	if !constantTimeEqual(adminKey, h.Config.AdminMasterKey) {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}

	var req RegisterClientRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	errs := &validator.Errors{}
	validator.ValidateRequiredString(errs, "name", req.Name)
	if errs.HasAny() {
		return errs
	}
	if req.AllowedIPs == nil {
		req.AllowedIPs = []string{}
	}

	result, err := h.AuthService.RegisterClient(req.Name, req.AllowedIPs)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// TokenRequest is the JSON body for token issuance.
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// IssueToken issues JWT pair (POST /auth/token).
func (h *AuthHandler) IssueToken(c *fiber.Ctx) error {
	var req TokenRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	errs := &validator.Errors{}
	validator.ValidateRequiredString(errs, "client_id", req.ClientID)
	validator.ValidateRequiredString(errs, "client_secret", req.ClientSecret)
	if errs.HasAny() {
		return errs
	}
	ip := c.IP()
	userAgent := c.Get("User-Agent")
	pair, err := h.TokenService.IssueToken(req.ClientID, req.ClientSecret, ip, userAgent)
	if err != nil {
		switch err {
		case services.ErrClientNotFound, services.ErrInvalidSecret:
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		case services.ErrClientSuspended:
			return fiber.NewError(fiber.StatusForbidden, "forbidden")
		case services.ErrIPNotAllowed:
			return fiber.NewError(fiber.StatusForbidden, "forbidden")
		default:
			return err
		}
	}
	return c.JSON(pair)
}

// RefreshTokenRequest is the JSON body for token refresh.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshToken rotates a refresh token (POST /auth/token/refresh).
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	errs := &validator.Errors{}
	validator.ValidateRequiredString(errs, "refresh_token", req.RefreshToken)
	if errs.HasAny() {
		return errs
	}
	ip := c.IP()
	userAgent := c.Get("User-Agent")
	pair, err := h.TokenService.RefreshToken(req.RefreshToken, ip, userAgent)
	if err != nil {
		switch err {
		case services.ErrTokenNotFound, services.ErrTokenExpired, services.ErrRefreshReuse:
			return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
		case services.ErrIPNotAllowed:
			return fiber.NewError(fiber.StatusForbidden, "forbidden")
		default:
			return err
		}
	}
	return c.JSON(pair)
}

// RevokeTokenRequest is the JSON body for token revocation.
type RevokeTokenRequest struct {
	Token string `json:"token"` // optional: access or refresh token to revoke
}

// RevokeToken revokes a token (POST /auth/token/revoke).
func (h *AuthHandler) RevokeToken(c *fiber.Ctx) error {
	auth := c.Get("Authorization")
	accessToken := ""
	if parts := strings.SplitN(auth, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		accessToken = strings.TrimSpace(parts[1])
	}
	var req RevokeTokenRequest
	_ = c.BodyParser(&req)
	bodyToken := strings.TrimSpace(req.Token)
	ip := c.IP()
	if bodyToken == "" && accessToken == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}
	if err := h.TokenService.RevokeToken(accessToken, bodyToken, ip); err != nil {
		if err == services.ErrTokenNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(fiber.Map{"message": "revoked"})
}

// RevokeAllClientTokens revokes all tokens for a client (admin only).
func (h *AuthHandler) RevokeAllClientTokens(c *fiber.Ctx) error {
	if h.Config.AdminMasterKey == "" {
		return fiber.NewError(fiber.StatusServiceUnavailable, "admin not configured")
	}
	adminKey := c.Get("X-Admin-Key")
	if !constantTimeEqual(adminKey, h.Config.AdminMasterKey) {
		return fiber.NewError(fiber.StatusUnauthorized, "unauthorized")
	}
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	if err := h.TokenService.RevokeAllForClient(id); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"message": "revoked"})
}
