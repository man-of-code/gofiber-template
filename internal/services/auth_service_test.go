package services_test

import (
	"os"
	"testing"

	"gofiber_template/internal/db"
	"gofiber_template/internal/models"
	"gofiber_template/internal/services"
)

const testEncKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func setupAuthService(t *testing.T) (*services.AuthService, func()) {
	t.Helper()
	os.Setenv("ENCRYPTION_KEY", testEncKey)
	defer os.Unsetenv("ENCRYPTION_KEY")

	path := t.TempDir() + "/auth_test.db"
	gormDB, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := gormDB.AutoMigrate(&models.Client{}); err != nil {
		t.Fatal(err)
	}
	cryptoService, err := services.NewCryptoService()
	if err != nil {
		t.Fatal(err)
	}
	authService := services.NewAuthService(gormDB, cryptoService)
	return authService, func() { os.Unsetenv("ENCRYPTION_KEY") }
}

func TestAuthService_RegisterClient_ReturnsUniqueCredentials(t *testing.T) {
	auth, _ := setupAuthService(t)

	r1, err := auth.RegisterClient("client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if r1.ClientID == "" || r1.ClientSecret == "" {
		t.Error("expected non-empty client_id and client_secret")
	}

	r2, err := auth.RegisterClient("client2", []string{"192.168.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if r2.ClientID == r1.ClientID || r2.ClientSecret == r1.ClientSecret {
		t.Error("expected unique credentials per registration")
	}
}

func TestAuthService_ValidateCredentials_CorrectSucceeds(t *testing.T) {
	auth, _ := setupAuthService(t)
	reg, err := auth.RegisterClient("test", nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := auth.ValidateCredentials(reg.ClientID, reg.ClientSecret)
	if err != nil {
		t.Fatal(err)
	}
	if got != reg.ClientID {
		t.Errorf("ValidateCredentials = %q, want %q", got, reg.ClientID)
	}
}

func TestAuthService_ValidateCredentials_WrongSecretFails(t *testing.T) {
	auth, _ := setupAuthService(t)
	reg, err := auth.RegisterClient("test", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateCredentials(reg.ClientID, reg.ClientSecret+"x")
	if err != services.ErrInvalidSecret && err != services.ErrClientNotFound {
		t.Errorf("expected ErrInvalidSecret or ErrClientNotFound, got %v", err)
	}
}

func TestAuthService_ValidateCredentials_UnknownClientFails(t *testing.T) {
	auth, _ := setupAuthService(t)
	// Use a valid-format but non-existent client_id and secret (64 hex chars)
	fakeSecret := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err := auth.ValidateCredentials("00000000-0000-0000-0000-000000000000", fakeSecret)
	if err != services.ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound, got %v", err)
	}
}

func TestAuthService_ValidateCredentials_SuspendedClientFails(t *testing.T) {
	auth, _ := setupAuthService(t)
	reg, err := auth.RegisterClient("test", nil)
	if err != nil {
		t.Fatal(err)
	}
	views, _ := auth.ListClients()
	if len(views) == 0 {
		t.Fatal("no clients listed")
	}
	_, err = auth.UpdateClient(views[0].ID, "", nil, "suspended")
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateCredentials(reg.ClientID, reg.ClientSecret)
	if err != services.ErrClientSuspended {
		t.Errorf("expected ErrClientSuspended, got %v", err)
	}
}

func TestAuthService_GetClient_ReturnsDecryptedView(t *testing.T) {
	auth, _ := setupAuthService(t)
	reg, err := auth.RegisterClient("myclient", []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	views, err := auth.ListClients()
	if err != nil || len(views) == 0 {
		t.Fatal("list clients", err)
	}
	v, err := auth.GetClient(views[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if v.ClientID != reg.ClientID {
		t.Errorf("GetClient client_id = %q, want %q", v.ClientID, reg.ClientID)
	}
	if v.Name != "myclient" {
		t.Errorf("name = %q, want myclient", v.Name)
	}
	if len(v.AllowedIPs) != 1 || v.AllowedIPs[0] != "10.0.0.0/8" {
		t.Errorf("allowed_ips = %v", v.AllowedIPs)
	}
}

func TestAuthService_DeleteClient_RemovesClient(t *testing.T) {
	auth, _ := setupAuthService(t)
	_, err := auth.RegisterClient("todel", nil)
	if err != nil {
		t.Fatal(err)
	}
	views, _ := auth.ListClients()
	if len(views) == 0 {
		t.Fatal("no clients")
	}
	id := views[0].ID
	if err := auth.DeleteClient(id); err != nil {
		t.Fatal(err)
	}
	_, err = auth.GetClient(id)
	if err != services.ErrClientNotFound {
		t.Errorf("expected ErrClientNotFound after delete, got %v", err)
	}
}
