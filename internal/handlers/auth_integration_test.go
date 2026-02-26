package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"gofiber_template/internal/cache"
	"gofiber_template/internal/config"
	"gofiber_template/internal/middleware"
	"gofiber_template/internal/models"
	"gofiber_template/internal/routes"
	"gofiber_template/internal/services"
)

// setupTestApp creates an in-memory DB, migrates, wires services, and returns a Fiber app and deps.
func setupTestApp(t *testing.T) (*fiber.App, *routes.Dependencies) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Item{}, &models.Client{}, &models.Token{}, &models.AuditLog{}); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AppID:           "test-app-v1",
		EncryptionKey:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		JWTSecret:       strings.Repeat("a", 128),
		AdminMasterKey:  "admin-master-key-32-bytes-long!!!!!!!!",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		AuthRateLimit:   100,
	}
	// CryptoService reads ENCRYPTION_KEY from env via crypto.MasterKey()
	os.Setenv("ENCRYPTION_KEY", cfg.EncryptionKey)
	defer os.Unsetenv("ENCRYPTION_KEY")
	cryptoService, err := services.NewCryptoService(cfg.AppID)
	if err != nil {
		t.Fatal(err)
	}
	blacklist := cache.NewTokenBlacklist()
	authService := services.NewAuthService(db, cryptoService)
	tokenService := services.NewTokenService(db, authService, cfg, blacklist)
	itemsService := services.NewItemsService(db)

	deps := &routes.Dependencies{
		DB:             db,
		Config:         cfg,
		CryptoService:  cryptoService,
		AuthService:    authService,
		TokenService:   tokenService,
		TokenValidator: tokenService,
		ItemsService:   itemsService,
	}

	app := fiber.New()
	app.Use(middleware.RealIP(cfg))
	app.Use(middleware.AuthRateLimit(cfg))
	routes.Register(app, deps)
	return app, deps
}

// registerTestClient registers a client via the admin API and returns client_id and client_secret.
func registerTestClient(t *testing.T, app *fiber.App, deps *routes.Dependencies) (clientID, clientSecret string) {
	t.Helper()
	body := `{"name":"test-client","allowed_ips":[]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/clients", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Key", deps.Config.AdminMasterKey)
	req.RemoteAddr = "127.0.0.1:1234"
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register client: status = %d, want 201", resp.StatusCode)
	}
	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result.ClientID, result.ClientSecret
}

func TestIssueToken_ValidCredentials_Returns200(t *testing.T) {
	app, deps := setupTestApp(t)
	clientID, clientSecret := registerTestClient(t, app, deps)

	body := bytes.NewBufferString(`{"client_id":"` + clientID + `","client_secret":"` + clientSecret + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:1234"

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result["access_token"] == nil || result["access_token"] == "" {
		t.Error("access_token missing or empty")
	}
	if result["refresh_token"] == nil || result["refresh_token"] == "" {
		t.Error("refresh_token missing or empty")
	}
}
