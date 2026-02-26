package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gofiber_template/internal/cache"
	"gofiber_template/internal/config"
	"gofiber_template/internal/db"
	"gofiber_template/internal/middleware"
	"gofiber_template/internal/models"
	"gofiber_template/internal/routes"
	"gofiber_template/internal/services"

	"github.com/gofiber/fiber/v2"
)

func main() {
	cfg := config.Load()
	logger := buildLogger(cfg)
	slog.SetDefault(logger)
	if cfg.EncryptionKey == "" {
		log.Fatal("ENCRYPTION_KEY required (32 bytes hex-encoded)")
	}
	if cfg.JWTSecret == "" || len(cfg.JWTSecret) < 64 {
		log.Fatal("JWT_SECRET required (min 64 bytes)")
	}

	gormDB, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	if err := gormDB.AutoMigrate(&models.Item{}, &models.Client{}, &models.Token{}, &models.AuditLog{}); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	cryptoService, err := services.NewCryptoService()
	if err != nil {
		log.Fatalf("crypto: %v", err)
	}
	blacklist := cache.NewTokenBlacklist()
	// Load revoked JTIs on startup
	var revoked []struct {
		JTI       string
		ExpiresAt time.Time
	}
	gormDB.Raw("SELECT jti, expires_at FROM tokens WHERE revoked = 1 AND expires_at > ?", time.Now()).Scan(&revoked)
	blacklist.LoadFromDB(func(add cache.AddFn) {
		for _, r := range revoked {
			add(r.JTI, r.ExpiresAt)
		}
	})

	authService := &services.AuthService{DB: gormDB, CryptoService: cryptoService}
	tokenService := &services.TokenService{
		DB:          gormDB,
		AuthService: authService,
		Config:      cfg,
		Blacklist:   blacklist,
	}
	auditLogger := middleware.NewAuditLogger(gormDB)
	defer auditLogger.Shutdown()

	app := fiber.New(fiber.Config{
		Prefork:               false, // single process for SQLite
		DisableStartupMessage: os.Getenv("ENV") == "prod",
		ReadBufferSize:        8192, // 8KB
		WriteBufferSize:       8192, // 8KB
		ReduceMemoryUsage:     os.Getenv("ENV") == "prod",
		ReadTimeout:           5 * time.Second,
		WriteTimeout:          10 * time.Second,
		IdleTimeout:           120 * time.Second,
		ServerHeader:          "-",
		BodyLimit:             cfg.BodyLimit,
		ErrorHandler:          middleware.ErrorHandler(logger),
	})

	// Middleware chain (order per plan: RequestID → SecurityHeaders → RateLimit → IPValidator → PayloadCrypto)
	app.Use(middleware.RequestID(cfg))
	app.Use(middleware.RequestLogger(logger))
	app.Use(middleware.SecurityHeaders())
	app.Use(middleware.GlobalRateLimit(cfg))
	app.Use(middleware.IPValidator(cfg))
	app.Use(middleware.PayloadCrypto(cryptoService))
	app.Use(middleware.EncryptResponse(cryptoService))
	app.Use(auditLogger.Middleware())

	routes.Register(app, &routes.Dependencies{
		DB:            gormDB,
		Config:        cfg,
		CryptoService: cryptoService,
		AuthService:   authService,
		TokenService:  tokenService,
	})

	portStr := fmt.Sprintf(":%d", cfg.Port)
	go func() {
		if err := app.Listen(portStr); err != nil {
			log.Fatalf("listen: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	if err := app.Shutdown(); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func buildLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
