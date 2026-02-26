package routes

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"gofiber_template/internal/config"
	"gofiber_template/internal/handlers"
	"gofiber_template/internal/middleware"
	"gofiber_template/internal/services"
)

// Dependencies holds services needed for route registration.
type Dependencies struct {
	DB            *gorm.DB
	Config        *config.Config
	CryptoService *services.CryptoService
	AuthService   *services.AuthService
	TokenService  *services.TokenService
}

// Register mounts all routes on the Fiber app.
func Register(app *fiber.App, deps *Dependencies) {
	app.Get("/health", handlers.Health)

	// Public auth (no JWT required) — AuthRateLimit for brute-force prevention
	auth := app.Group("/auth", middleware.AuthRateLimit(deps.Config))
	authHandler := &handlers.AuthHandler{
		AuthService:  deps.AuthService,
		TokenService: deps.TokenService,
		Config:       deps.Config,
	}
	auth.Post("/token", authHandler.IssueToken)
	auth.Post("/token/refresh", authHandler.RefreshToken)
	auth.Post("/token/revoke",
		middleware.JWTAuth(deps.TokenService),
		middleware.TokenBinding(deps.TokenService),
		authHandler.RevokeToken)

	// Admin (X-Admin-Key required)
	admin := app.Group("/admin")
	admin.Post("/clients", authHandler.RegisterClient)
	admin.Post("/clients/:id/revoke-all", authHandler.RevokeAllClientTokens)

	// Authenticated API (JWT + TokenBinding + APIRateLimit)
	api := app.Group("/api",
		middleware.JWTAuth(deps.TokenService),
		middleware.TokenBinding(deps.TokenService),
		middleware.APIRateLimit(deps.Config))
	itemsHandler := &handlers.ItemsHandler{DB: deps.DB}
	api.Get("/items", itemsHandler.List)
	api.Get("/items/:id", itemsHandler.Get)
	api.Post("/items", itemsHandler.Create)
	api.Put("/items/:id", itemsHandler.Update)
	api.Delete("/items/:id", itemsHandler.Delete)
}
