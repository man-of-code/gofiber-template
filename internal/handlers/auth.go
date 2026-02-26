package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"gofiber_template/internal/config"
	"gofiber_template/internal/middleware"
	"gofiber_template/internal/services"
	"gofiber_template/internal/validator"
)

// AuthHandler handles auth and admin client endpoints.
type AuthHandler struct {
	AuthService  services.ClientManager
	TokenService services.TokenIssuer
	Config       *config.Config
	DB           *gorm.DB
}

// RegisterClientRequest is the JSON body for client registration.
type RegisterClientRequest struct {
	Name       string   `json:"name"`
	AllowedIPs []string `json:"allowed_ips"`
}

// RegisterClient creates a new client (admin only).
func (h *AuthHandler) RegisterClient(c *fiber.Ctx) error {
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
	ip := middleware.ClientIP(c)
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
	ip := middleware.ClientIP(c)
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
	ip := middleware.ClientIP(c)
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
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	if err := h.TokenService.RevokeAllForClient(id); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"message": "revoked"})
}

// ClientResponse represents the admin-facing client data payload.
type ClientResponse struct {
	ID         uint     `json:"id"`
	Name       string   `json:"name"`
	ClientID   string   `json:"client_id"`
	AllowedIPs []string `json:"allowed_ips"`
	Status     string   `json:"status"`
	CreatedAt  int64    `json:"created_at"`
	UpdatedAt  int64    `json:"updated_at"`
}

func toClientResponse(view *services.ClientView) *ClientResponse {
	if view == nil {
		return nil
	}
	return &ClientResponse{
		ID:         view.ID,
		Name:       view.Name,
		ClientID:   view.ClientID,
		AllowedIPs: view.AllowedIPs,
		Status:     view.Status,
		CreatedAt:  view.CreatedAt.Unix(),
		UpdatedAt:  view.UpdatedAt.Unix(),
	}
}

// ListClients returns clients (admin only) with pagination.
func (h *AuthHandler) ListClients(c *fiber.Ctx) error {
	page, limit, err := validator.ParsePagination(c.Query("page"), c.Query("limit"), 20, 100)
	if err != nil {
		return err
	}
	views, total, err := h.AuthService.ListClients(page, limit)
	if err != nil {
		return err
	}
	responses := make([]*ClientResponse, 0, len(views))
	for _, v := range views {
		responses = append(responses, toClientResponse(v))
	}
	return c.JSON(fiber.Map{
		"data": responses,
		"meta": fiber.Map{
			"page":       page,
			"limit":      limit,
			"total":      total,
			"total_page": (total + int64(limit) - 1) / int64(limit),
		},
	})
}

// GetClient returns a single client by database ID (admin only).
func (h *AuthHandler) GetClient(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	view, err := h.AuthService.GetClient(id)
	if err != nil {
		if err == services.ErrClientNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(toClientResponse(view))
}

// UpdateClientRequest is the JSON body for updating a client.
type UpdateClientRequest struct {
	Name       string   `json:"name"`
	AllowedIPs []string `json:"allowed_ips"`
	Status     string   `json:"status"`
}

// UpdateClient updates client metadata (admin only).
func (h *AuthHandler) UpdateClient(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	var req UpdateClientRequest
	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid body")
	}
	if req.Status != "" {
		switch req.Status {
		case "active", "suspended", "revoked":
		default:
			verr := &validator.Errors{}
			verr.Add("status", "must be active, suspended, or revoked")
			return verr
		}
	}
	if req.AllowedIPs == nil {
		req.AllowedIPs = []string{}
	}
	view, err := h.AuthService.UpdateClient(id, req.Name, req.AllowedIPs, req.Status)
	if err != nil {
		if err == services.ErrClientNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.JSON(toClientResponse(view))
}

// DeleteClient deletes a client and revokes its tokens (admin only).
func (h *AuthHandler) DeleteClient(c *fiber.Ctx) error {
	id, err := validator.ParsePositiveUint(c.Params("id"), "id")
	if err != nil {
		return err
	}
	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err := h.TokenService.RevokeAllForClientTx(tx, id); err != nil {
			return err
		}
		if err := h.AuthService.DeleteClientTx(tx, id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if err == services.ErrClientNotFound {
			return fiber.NewError(fiber.StatusNotFound, "not found")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
