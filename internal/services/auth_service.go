package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"gofiber_template/internal/models"
)

const secretSize = 64
const bcryptCost = 12

var (
	ErrClientNotFound  = errors.New("client not found")
	ErrInvalidSecret   = errors.New("invalid client secret")
	ErrClientSuspended = errors.New("client suspended or revoked")
)

var dummyHash []byte

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy"), bcryptCost)
	if err == nil {
		dummyHash = h
	}
}

type failCount struct {
	count    int
	windowAt time.Time
}

type failureTracker struct {
	mu     sync.Mutex
	counts map[string]*failCount // keyed by client_id_hash
	window time.Duration
	limit  int
}

func newFailureTracker(window time.Duration, limit int) *failureTracker {
	return &failureTracker{
		counts: make(map[string]*failCount),
		window: window,
		limit:  limit,
	}
}

// inc increments the failure count and returns true if the threshold is reached.
func (t *failureTracker) inc(key string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.counts[key]
	if !ok || now.Sub(e.windowAt) > t.window {
		t.counts[key] = &failCount{count: 1, windowAt: now}
		return false
	}
	e.count++
	return e.count >= t.limit
}

func (t *failureTracker) reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.counts, key)
}

// AuthService handles client registration and credential validation.
type AuthService struct {
	DB            *gorm.DB
	CryptoService *CryptoService
	failures      *failureTracker
}

// NewAuthService constructs an AuthService with failure tracking.
func NewAuthService(db *gorm.DB, crypto *CryptoService) *AuthService {
	return &AuthService{
		DB:            db,
		CryptoService: crypto,
		failures:      newFailureTracker(5*time.Minute, 10),
	}
}

// clientIDHash returns SHA256 of client_id for lookup.
func clientIDHash(clientID string) string {
	h := sha256.Sum256([]byte(clientID))
	return hex.EncodeToString(h[:])
}

// RegisterClientResult holds the one-time client credentials.
type RegisterClientResult struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// RegisterClient creates a new client and returns client_id + client_secret (one-time display).
func (s *AuthService) RegisterClient(name string, allowedIPs []string) (*RegisterClientResult, error) {
	clientID := uuid.New().String()
	secretBytes := make([]byte, secretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, err
	}
	clientSecret := hex.EncodeToString(secretBytes)

	secretHash, err := bcrypt.GenerateFromPassword(secretBytes, bcryptCost)
	if err != nil {
		return nil, err
	}

	allowedIPsJSON, err := json.Marshal(allowedIPs)
	if err != nil {
		return nil, err
	}

	clientIDEnc, err := s.CryptoService.EncryptClientID(clientID)
	if err != nil {
		return nil, err
	}

	client := models.Client{
		ClientIDHash: clientIDHash(clientID),
		ClientIDEnc:  clientIDEnc,
		SecretHash:   string(secretHash),
		Name:         name,
		AllowedIPs:   string(allowedIPsJSON),
		Status:       "active",
	}
	if err := s.DB.Create(&client).Error; err != nil {
		return nil, err
	}

	return &RegisterClientResult{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

// ValidateCredentials checks client_id and client_secret, returns client_id if valid.
func (s *AuthService) ValidateCredentials(clientIDPlain string, clientSecret string) (string, error) {
	hash := clientIDHash(clientIDPlain)
	var client models.Client
	if err := s.DB.Where("client_id_hash = ?", hash).First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			if dummyHash != nil {
				_ = bcrypt.CompareHashAndPassword(dummyHash, []byte("dummy"))
			}
			return "", ErrClientNotFound
		}
		return "", err
	}
	secretBytes, err := decodeClientSecret(clientSecret)
	if err != nil {
		// Normalize timing for invalid formats.
		_ = bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte("dummy"))
		return "", ErrInvalidSecret
	}
	if client.Status != "active" {
		// Normalize timing with valid/suspended clients.
		_ = bcrypt.CompareHashAndPassword([]byte(client.SecretHash), secretBytes)
		return "", ErrClientSuspended
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), secretBytes); err != nil {
		if s.failures != nil && s.failures.inc(hash) {
			now := time.Now()
			if err := s.DB.Model(&client).Updates(map[string]interface{}{
				"status": "suspended",
			}).Error; err == nil {
				slog.Warn("client_auto_suspended",
					"client_id_hash", hash,
					"client_id", client.ID,
					"at", now,
				)
			}
		}
		return "", ErrInvalidSecret
	}
	if s.failures != nil {
		s.failures.reset(hash)
	}
	return clientIDPlain, nil
}

func decodeClientSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	if len(secret) != secretSize*2 {
		return nil, errors.New("invalid secret length")
	}
	b, err := hex.DecodeString(secret)
	if err != nil || len(b) != secretSize {
		return nil, errors.New("invalid secret format")
	}
	return b, nil
}

// GetClientByPlainID fetches a client by plaintext client_id (after validation).
func (s *AuthService) GetClientByPlainID(clientIDPlain string) (*models.Client, error) {
	hash := clientIDHash(clientIDPlain)
	var client models.Client
	if err := s.DB.Where("client_id_hash = ?", hash).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

// ClientView is a safe projection of client data for admin use.
type ClientView struct {
	ID         uint
	Name       string
	ClientID   string
	AllowedIPs []string
	Status     string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ListClients returns all clients with decrypted client_id.
func (s *AuthService) ListClients() ([]*ClientView, error) {
	var clients []models.Client
	if err := s.DB.Order("id DESC").Find(&clients).Error; err != nil {
		return nil, err
	}
	views := make([]*ClientView, 0, len(clients))
	for _, c := range clients {
		clientID, err := s.CryptoService.DecryptClientID(c.ClientIDEnc)
		if err != nil {
			return nil, err
		}
		views = append(views, &ClientView{
			ID:         c.ID,
			Name:       c.Name,
			ClientID:   clientID,
			AllowedIPs: ParseAllowedIPs(c.AllowedIPs),
			Status:     c.Status,
			CreatedAt:  c.CreatedAt,
			UpdatedAt:  c.UpdatedAt,
		})
	}
	return views, nil
}

// GetClient returns one client by ID with decrypted client_id.
func (s *AuthService) GetClient(id uint) (*ClientView, error) {
	var client models.Client
	if err := s.DB.First(&client, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	clientID, err := s.CryptoService.DecryptClientID(client.ClientIDEnc)
	if err != nil {
		return nil, err
	}
	return &ClientView{
		ID:         client.ID,
		Name:       client.Name,
		ClientID:   clientID,
		AllowedIPs: ParseAllowedIPs(client.AllowedIPs),
		Status:     client.Status,
		CreatedAt:  client.CreatedAt,
		UpdatedAt:  client.UpdatedAt,
	}, nil
}

// UpdateClient updates mutable fields and returns the updated view.
func (s *AuthService) UpdateClient(id uint, name string, allowedIPs []string, status string) (*ClientView, error) {
	var client models.Client
	if err := s.DB.First(&client, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	updates := map[string]interface{}{}
	if strings.TrimSpace(name) != "" {
		updates["name"] = name
	}
	if allowedIPs != nil {
		allowedIPsJSON, err := json.Marshal(allowedIPs)
		if err != nil {
			return nil, err
		}
		updates["allowed_ips"] = string(allowedIPsJSON)
	}
	if status != "" {
		updates["status"] = status
	}
	if len(updates) > 0 {
		if err := s.DB.Model(&client).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	return s.GetClient(id)
}

// DeleteClient removes a client (soft delete via gorm.DeletedAt).
func (s *AuthService) DeleteClient(id uint) error {
	res := s.DB.Delete(&models.Client{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrClientNotFound
	}
	return nil
}
