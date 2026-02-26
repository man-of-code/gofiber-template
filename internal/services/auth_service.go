package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"gofiber_template/internal/models"
)

const secretSize = 64
const bcryptCost = 12

var (
	ErrClientNotFound   = errors.New("client not found")
	ErrInvalidSecret    = errors.New("invalid client secret")
	ErrClientSuspended  = errors.New("client suspended or revoked")
)

// AuthService handles client registration and credential validation.
type AuthService struct {
	DB            *gorm.DB
	CryptoService *CryptoService
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

	secretHash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcryptCost)
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
			return "", ErrClientNotFound
		}
		return "", err
	}
	if client.Status != "active" {
		return "", ErrClientSuspended
	}
	if err := bcrypt.CompareHashAndPassword([]byte(client.SecretHash), []byte(clientSecret)); err != nil {
		return "", ErrInvalidSecret
	}
	return clientIDPlain, nil
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
