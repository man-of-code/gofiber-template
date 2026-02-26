package services_test

import (
	"os"
	"testing"
	"time"

	"gofiber_template/internal/cache"
	"gofiber_template/internal/config"
	"gofiber_template/internal/db"
	"gofiber_template/internal/models"
	"gofiber_template/internal/services"
)

func setupTokenService(t *testing.T) (*services.TokenService, *services.AuthService, *services.RegisterClientResult, func()) {
	t.Helper()
	os.Setenv("ENCRYPTION_KEY", testEncKey)
	path := t.TempDir() + "/token_test.db"
	gormDB, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := gormDB.AutoMigrate(&models.Client{}, &models.Token{}); err != nil {
		t.Fatal(err)
	}
	cryptoService, err := services.NewCryptoService("test-app-v1")
	if err != nil {
		t.Fatal(err)
	}
	authService := services.NewAuthService(gormDB, cryptoService)
	cfg := &config.Config{
		JWTSecret:        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 64 chars min
		AccessTokenTTL:   15 * time.Minute,
		RefreshTokenTTL:  24 * time.Hour,
		TokenBindingMode: "strict",
	}
	blacklist := cache.NewTokenBlacklist()
	tokenService := services.NewTokenService(gormDB, authService, cfg, blacklist)
	reg, err := authService.RegisterClient("token-test", []string{"192.168.0.0/24", "127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	return tokenService, authService, reg, func() { os.Unsetenv("ENCRYPTION_KEY") }
}

func TestTokenService_IssueToken_ReturnsValidPair(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	pair, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "192.168.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected non-empty access and refresh tokens")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", pair.TokenType)
	}
	if pair.ExpiresIn <= 0 {
		t.Error("expected positive expires_in")
	}

	claims, err := svc.ParseJWT(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != reg.ClientID {
		t.Errorf("jwt subject = %q, want %q", claims.Subject, reg.ClientID)
	}
}

func TestTokenService_IssueToken_IPNotAllowedFails(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	_, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "10.0.0.1", "agent")
	if err != services.ErrIPNotAllowed {
		t.Errorf("expected ErrIPNotAllowed, got %v", err)
	}
}

func TestTokenService_RefreshToken_RotatesCorrectly(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	pair1, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "127.0.0.1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	pair2, err := svc.RefreshToken(pair1.RefreshToken, "127.0.0.1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	if pair2.AccessToken == pair1.AccessToken {
		t.Error("refresh should return new access token")
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		t.Error("refresh should return new refresh token")
	}
	// Old access token should be invalid (revoked)
	_, err = svc.ParseJWT(pair1.AccessToken)
	if err == nil {
		t.Error("old access token should be invalid after refresh")
	}
}

func TestTokenService_RevokeToken_AddsToBlacklist(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	pair, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "127.0.0.1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	err = svc.RevokeToken(pair.AccessToken, "", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ParseJWT(pair.AccessToken)
	if err != services.ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked after revoke, got %v", err)
	}
}

func TestTokenService_ValidateBinding_IPMismatchFails(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	pair, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "127.0.0.1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := svc.ParseJWT(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.ValidateBinding(claims, "192.168.0.1", "agent")
	if err == nil {
		t.Error("expected error when IP does not match")
	}
}

func TestTokenService_ValidateBinding_SameIPPasses(t *testing.T) {
	svc, _, reg, cleanup := setupTokenService(t)
	defer cleanup()

	pair, err := svc.IssueToken(reg.ClientID, reg.ClientSecret, "127.0.0.1", "agent")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := svc.ParseJWT(pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ValidateBinding(claims, "127.0.0.1", "agent"); err != nil {
		t.Errorf("same IP should pass: %v", err)
	}
}
