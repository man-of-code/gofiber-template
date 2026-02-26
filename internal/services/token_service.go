package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"gofiber_template/internal/cache"
	"gofiber_template/internal/config"
	"gofiber_template/internal/models"
)

const refreshTokenSize = 64

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token revoked")
	ErrTokenExpired  = errors.New("token expired")
	ErrIPNotAllowed  = errors.New("IP not in allowed ranges")
	ErrRefreshReuse  = errors.New("refresh token reuse detected")
)

// TokenService handles JWT issuance, refresh, and revocation.
type TokenService struct {
	DB          *gorm.DB
	AuthService *AuthService
	Config      *config.Config
	Blacklist   *cache.TokenBlacklist
}

// TokenPair holds access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// JWTClaims holds custom JWT claims.
type JWTClaims struct {
	jwt.RegisteredClaims
	IP          string `json:"ip"`
	Scope       string `json:"scope"`
	Fingerprint string `json:"fp,omitempty"` // SHA256(client_id|ip|user_agent)
}

// ParseAllowedIPs parses JSON array of CIDR strings.
func ParseAllowedIPs(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}

// IPInRanges checks if ip is in any of the CIDR ranges.
func IPInRanges(ipStr string, ranges []string) bool {
	if len(ranges) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range ranges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// IssueToken issues a new access + refresh token pair.
func (s *TokenService) IssueToken(clientID string, clientSecret string, ip string, userAgent string) (*TokenPair, error) {
	validatedID, err := s.AuthService.ValidateCredentials(clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	client, err := s.AuthService.GetClientByPlainID(validatedID)
	if err != nil {
		return nil, err
	}
	ranges := ParseAllowedIPs(client.AllowedIPs)
	if !IPInRanges(ip, ranges) {
		return nil, ErrIPNotAllowed
	}

	jti := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(s.Config.AccessTokenTTL)
	refreshExpiresAt := now.Add(s.Config.RefreshTokenTTL)

	refreshBytes := make([]byte, refreshTokenSize)
	if _, err := rand.Read(refreshBytes); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshBytes)
	refreshHash := sha256.Sum256([]byte(refreshToken))
	refreshHashHex := hex.EncodeToString(refreshHash[:])

	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   validatedID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		IP:          ip,
		Scope:       "api",
		Fingerprint: computeFingerprint(validatedID, ip, userAgent),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(s.Config.JWTSecret))
	if err != nil {
		return nil, err
	}

	tok := models.Token{
		JTI:              jti,
		ClientID:         validatedID,
		ClientDBID:       client.ID,
		RefreshTokenHash: refreshHashHex,
		IPAddress:        ip,
		UserAgent:        userAgent,
		IssuedAt:         now,
		ExpiresAt:        expiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}
	if err := s.DB.Create(&tok).Error; err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.Config.AccessTokenTTL.Seconds()),
		TokenType:    "Bearer",
	}, nil
}

// RefreshToken rotates a refresh token into a new pair.
func (s *TokenService) RefreshToken(refreshToken string, ip string, userAgent string) (*TokenPair, error) {
	refreshHash := sha256.Sum256([]byte(refreshToken))
	refreshHashHex := hex.EncodeToString(refreshHash[:])

	var tok models.Token
	if err := s.DB.Where("refresh_token_hash = ?", refreshHashHex).First(&tok).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}
	if tok.Revoked {
		now := time.Now()
		s.DB.Model(&models.Token{}).Where("client_id = ?", tok.ClientID).Updates(map[string]interface{}{
			"revoked": true, "revoked_at": now, "revoked_reason": "refresh_reuse",
		})
		s.loadRevokedJTIsForClient(tok.ClientID)
		return nil, ErrRefreshReuse
	}
	if time.Now().After(tok.RefreshExpiresAt) {
		return nil, ErrTokenExpired
	}
	client, err := s.AuthService.GetClientByPlainID(tok.ClientID)
	if err != nil {
		return nil, err
	}
	ranges := ParseAllowedIPs(client.AllowedIPs)
	if !IPInRanges(ip, ranges) && ip != tok.IPAddress {
		return nil, ErrIPNotAllowed
	}
	return s.rotateToken(&tok, ip, userAgent)
}

func (s *TokenService) rotateToken(old *models.Token, ip string, userAgent string) (*TokenPair, error) {
	var result *TokenPair
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		if err := tx.Model(old).Updates(map[string]interface{}{
			"revoked": true, "revoked_at": now, "revoked_reason": "rotated",
		}).Error; err != nil {
			return err
		}
		s.Blacklist.Add(old.JTI, old.ExpiresAt)

		jti := uuid.New().String()
		expiresAt := now.Add(s.Config.AccessTokenTTL)
		refreshExpiresAt := now.Add(s.Config.RefreshTokenTTL)

		refreshBytes := make([]byte, refreshTokenSize)
		if _, err := rand.Read(refreshBytes); err != nil {
			return err
		}
		refreshToken := hex.EncodeToString(refreshBytes)
		refreshHash := sha256.Sum256([]byte(refreshToken))
		refreshHashHex := hex.EncodeToString(refreshHash[:])

		claims := JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   old.ClientID,
				ID:        jti,
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(expiresAt),
			},
			IP:          ip,
			Scope:       "api",
			Fingerprint: computeFingerprint(old.ClientID, ip, userAgent),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		accessToken, err := token.SignedString([]byte(s.Config.JWTSecret))
		if err != nil {
			return err
		}

		tok := models.Token{
			JTI:              jti,
			ClientID:         old.ClientID,
			ClientDBID:       old.ClientDBID,
			RefreshTokenHash: refreshHashHex,
			IPAddress:        ip,
			UserAgent:        userAgent,
			IssuedAt:         now,
			ExpiresAt:        expiresAt,
			RefreshExpiresAt: refreshExpiresAt,
		}
		if err := tx.Create(&tok).Error; err != nil {
			return err
		}

		result = &TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int(s.Config.AccessTokenTTL.Seconds()),
			TokenType:    "Bearer",
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *TokenService) loadRevokedJTIsForClient(clientID string) {
	var tokens []models.Token
	s.DB.Where("client_id = ? AND revoked = ?", clientID, true).Find(&tokens)
	for _, t := range tokens {
		s.Blacklist.Add(t.JTI, t.ExpiresAt)
	}
}

// CleanupExpired removes old, already-revoked tokens to keep the table small.
func (s *TokenService) CleanupExpired() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	s.DB.Where("expires_at < ? AND revoked = ?", cutoff, true).
		Delete(&models.Token{})
}

// RevokeToken revokes a token by JTI or refresh token.
func (s *TokenService) RevokeToken(accessToken string, bodyToken string, ip string) error {
	now := time.Now()
	if bodyToken != "" {
		refreshHash := sha256.Sum256([]byte(bodyToken))
		refreshHashHex := hex.EncodeToString(refreshHash[:])
		var tok models.Token
		if err := s.DB.Where("refresh_token_hash = ?", refreshHashHex).First(&tok).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				return ErrTokenNotFound
			}
			return err
		}
		s.DB.Model(&tok).Updates(map[string]interface{}{
			"revoked": true, "revoked_at": now, "revoked_reason": "user_revoked",
		})
		s.Blacklist.Add(tok.JTI, tok.ExpiresAt)
		return nil
	}
	claims, err := s.parseAndValidateJWT(accessToken, ip, false)
	if err != nil {
		return err
	}
	s.DB.Model(&models.Token{}).Where("jti = ?", claims.ID).Updates(map[string]interface{}{
		"revoked": true, "revoked_at": now, "revoked_reason": "user_revoked",
	})
	s.Blacklist.Add(claims.ID, claims.ExpiresAt.Time)
	return nil
}

// RevokeAllForClient revokes all tokens for a client (admin action).
func (s *TokenService) RevokeAllForClient(clientDBID uint) error {
	now := time.Now()
	var tokens []models.Token
	s.DB.Where("client_db_id = ? AND revoked = ?", clientDBID, false).Find(&tokens)
	if len(tokens) == 0 {
		return nil
	}
	s.DB.Model(&models.Token{}).
		Where("client_db_id = ? AND revoked = ?", clientDBID, false).
		Updates(map[string]interface{}{
			"revoked": true, "revoked_at": now, "revoked_reason": "admin_revoke_all",
		})
	for _, t := range tokens {
		s.Blacklist.Add(t.JTI, t.ExpiresAt)
	}
	return nil
}

func computeFingerprint(clientID, ip, userAgent string) string {
	h := sha256.Sum256([]byte(clientID + "|" + ip + "|" + userAgent))
	return hex.EncodeToString(h[:])
}

// parseAndValidateJWT parses and validates JWT, checks blacklist. Optionally validates IP binding.
func (s *TokenService) parseAndValidateJWT(accessToken string, ip string, validateBinding bool) (*JWTClaims, error) {
	if s.Config.JWTSecret == "" || len(s.Config.JWTSecret) < 64 {
		return nil, errors.New("jwt not configured")
	}
	token, err := jwt.ParseWithClaims(accessToken, &JWTClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(s.Config.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	if s.Blacklist.Contains(claims.ID) {
		return nil, ErrTokenRevoked
	}
	if validateBinding {
		if err := s.validateBinding(claims, ip, ""); err != nil {
			return nil, err
		}
	}
	return claims, nil
}

// ParseAndValidateJWT is the public method for middleware use. Validates binding when validateBinding is true.
func (s *TokenService) ParseAndValidateJWT(accessToken string, ip string, validateBinding bool) (*JWTClaims, error) {
	return s.parseAndValidateJWT(accessToken, ip, validateBinding)
}

// ParseJWT parses JWT without IP/fingerprint binding check. For use before TokenBinding middleware.
func (s *TokenService) ParseJWT(accessToken string) (*JWTClaims, error) {
	return s.parseAndValidateJWT(accessToken, "", false)
}

// ValidateBinding checks IP and fingerprint against claims. Returns error if binding fails.
func (s *TokenService) ValidateBinding(claims *JWTClaims, ip, userAgent string) error {
	return s.validateBinding(claims, ip, userAgent)
}

func (s *TokenService) validateBinding(claims *JWTClaims, ip, userAgent string) error {
	mode := "strict"
	if s.Config != nil && s.Config.TokenBindingMode != "" {
		mode = s.Config.TokenBindingMode
	}
	if mode == "off" {
		return nil
	}
	if claims.IP == "" {
		return nil
	}
	if mode == "strict" {
		if claims.IP != ip {
			return errors.New("ip mismatch")
		}
	} else if mode == "subnet" {
		if !sameSubnet(claims.IP, ip) {
			return errors.New("ip subnet mismatch")
		}
	}
	if claims.Fingerprint != "" && userAgent != "" {
		expected := computeFingerprint(claims.Subject, ip, userAgent)
		if claims.Fingerprint != expected {
			return errors.New("fingerprint mismatch")
		}
	}
	return nil
}

func sameSubnet(a, b string) bool {
	ipa := net.ParseIP(a)
	ipb := net.ParseIP(b)
	if ipa == nil || ipb == nil {
		return false
	}
	if ipa4 := ipa.To4(); ipa4 != nil {
		ipb4 := ipb.To4()
		if ipb4 == nil {
			return false
		}
		return ipa4[0] == ipb4[0] && ipa4[1] == ipb4[1] && ipa4[2] == ipb4[2]
	}
	// IPv6: compare first 6 bytes (/48)
	for i := 0; i < 6 && i < len(ipa) && i < len(ipb); i++ {
		if ipa[i] != ipb[i] {
			return false
		}
	}
	return true
}
