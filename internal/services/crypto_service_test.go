package services_test

import (
	"os"
	"testing"

	"gofiber_template/internal/services"
)

func TestCryptoService_EncryptDecryptPayload_Roundtrip(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("ENCRYPTION_KEY")
	cs, err := services.NewCryptoService("test-app-v1")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"name":"test"}`)
	ct, err := cs.EncryptPayload(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext empty")
	}
	pt, err := cs.DecryptPayload(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(plain) {
		t.Errorf("decrypt got %q, want %q", pt, plain)
	}
}

func TestCryptoService_EncryptDecryptClientID_Roundtrip(t *testing.T) {
	os.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("ENCRYPTION_KEY")
	cs, err := services.NewCryptoService("test-app-v1")
	if err != nil {
		t.Fatal(err)
	}
	clientID := "550e8400-e29b-41d4-a716-446655440000"
	enc, err := cs.EncryptClientID(clientID)
	if err != nil {
		t.Fatal(err)
	}
	if enc == "" {
		t.Fatal("encrypted client_id empty")
	}
	dec, err := cs.DecryptClientID(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != clientID {
		t.Errorf("decrypt got %q, want %q", dec, clientID)
	}
}

func TestCryptoService_NewCryptoService_NoKey(t *testing.T) {
	os.Unsetenv("ENCRYPTION_KEY")
	_, err := services.NewCryptoService("test-app-v1")
	if err == nil {
		t.Error("expected error when ENCRYPTION_KEY not set")
	}
}
