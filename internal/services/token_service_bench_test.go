package services_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"gofiber_template/internal/cache"
	"gofiber_template/internal/config"
	"gofiber_template/internal/services"
)

func BenchmarkParseJWT(b *testing.B) {
	cfg := &config.Config{JWTSecret: strings.Repeat("a", 64)}
	blacklist := cache.NewTokenBlacklist()
	service := &services.TokenService{Config: cfg, Blacklist: blacklist}

	now := time.Now()
	claims := services.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "client-id",
			ID:        "bench-jti",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		IP:          "127.0.0.1",
		Scope:       "api",
		Fingerprint: "bench",
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := jwtToken.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := service.ParseJWT(accessToken)
		if err != nil {
			b.Fatal(err)
		}
	}
}
