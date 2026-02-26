package services_test

import (
	"os"
	"testing"

	"gofiber_template/internal/services"
)

func BenchmarkEncryptDecryptPayload(b *testing.B) {
	os.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("ENCRYPTION_KEY")
	cs, err := services.NewCryptoService("test-app-v1")
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte(`{"name":"benchmark test item","value":42}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := cs.EncryptPayload(payload)
		if err != nil {
			b.Fatal(err)
		}
		_, err = cs.DecryptPayload(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptDecryptClientID(b *testing.B) {
	os.Setenv("ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	defer os.Unsetenv("ENCRYPTION_KEY")
	cs, err := services.NewCryptoService("test-app-v1")
	if err != nil {
		b.Fatal(err)
	}
	clientID := "550e8400-e29b-41d4-a716-446655440000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := cs.EncryptClientID(clientID)
		if err != nil {
			b.Fatal(err)
		}
		_, err = cs.DecryptClientID(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}
