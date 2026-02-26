package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration from environment or defaults.
type Config struct {
	DBPath          string
	Port            int
	AdminMasterKey  string        // for bootstrapping clients
	JWTSecret       string        // min 64 bytes for HMAC-SHA256
	AccessTokenTTL  time.Duration // default 15m
	RefreshTokenTTL time.Duration // default 24h
	EncryptionKey   string        // 32 bytes hex-encoded
	Environment     string        // dev, staging, prod
	LogLevel        string        // debug, info, warn, error

	// Rate limiting
	GlobalRateLimit int // req/min per IP
	AuthRateLimit   int // req/min per IP for auth endpoints
	APIRateLimit    int // req/min per client_id

	// IP validation
	IPMode            string   // whitelist, blacklist, off
	TrustedProxies    []string // CIDRs for trusted proxies; required to honor X-Forwarded-For
	GlobalAllowedIPs  []string // CIDR whitelist when IPMode=whitelist
	GlobalBlockedIPs  []string // CIDR blacklist when IPMode=blacklist
	TrustedProxyDepth int      // how many X-Forwarded-For hops to trust

	// Security
	TokenBindingMode        string // strict, subnet, off
	RequireEncryptedPayload bool   // when true, reject unencrypted POST/PUT/PATCH/DELETE bodies
	BodyLimit               int    // bytes, default 1MB
}

// Load reads config from environment and applies defaults.
func Load() *Config {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./data/app.db"
	}
	port := 3000
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	accessTTL := 15 * time.Minute
	if d := os.Getenv("ACCESS_TOKEN_TTL"); d != "" {
		if v, err := time.ParseDuration(d); err == nil {
			accessTTL = v
		}
	}
	refreshTTL := 24 * time.Hour
	if d := os.Getenv("REFRESH_TOKEN_TTL"); d != "" {
		if v, err := time.ParseDuration(d); err == nil {
			refreshTTL = v
		}
	}
	globalRate := 1000
	if v := os.Getenv("GLOBAL_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			globalRate = n
		}
	}
	authRate := 10
	if v := os.Getenv("AUTH_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			authRate = n
		}
	}
	apiRate := 200
	if v := os.Getenv("API_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			apiRate = n
		}
	}
	proxyDepth := 1
	if v := os.Getenv("TRUSTED_PROXY_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			proxyDepth = n
		}
	}
	bodyLimit := 1024 * 1024 // 1MB
	if v := os.Getenv("BODY_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			bodyLimit = n
		}
	}
	return &Config{
		DBPath:            dbPath,
		Port:              port,
		AdminMasterKey:    os.Getenv("ADMIN_MASTER_KEY"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		AccessTokenTTL:    accessTTL,
		RefreshTokenTTL:   refreshTTL,
		EncryptionKey:     os.Getenv("ENCRYPTION_KEY"),
		Environment:       getEnv("ENV", "dev"),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		GlobalRateLimit:   globalRate,
		AuthRateLimit:     authRate,
		APIRateLimit:      apiRate,
		IPMode:            getEnv("IP_MODE", "off"),
		TrustedProxies:    parseCommaList(os.Getenv("TRUSTED_PROXIES")),
		GlobalAllowedIPs:  parseCommaList(os.Getenv("GLOBAL_ALLOWED_IPS")),
		GlobalBlockedIPs:  parseCommaList(os.Getenv("GLOBAL_BLOCKED_IPS")),
		TrustedProxyDepth: proxyDepth,
		TokenBindingMode:  getEnv("TOKEN_BINDING_MODE", "strict"),
		RequireEncryptedPayload: getEnv("REQUIRE_ENCRYPTED_PAYLOAD", "false") == "true",
		BodyLimit:         bodyLimit,
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseCommaList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
