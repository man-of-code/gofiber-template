package services

import (
	"encoding/hex"

	"gofiber_template/internal/crypto"
)

// CryptoService orchestrates encrypt/decrypt of model fields and payloads.
type CryptoService struct {
	masterKey []byte
}

// NewCryptoService creates a CryptoService. Returns error if ENCRYPTION_KEY is not set.
func NewCryptoService() (*CryptoService, error) {
	master, err := crypto.MasterKey()
	if err != nil {
		return nil, err
	}
	return &CryptoService{masterKey: master}, nil
}

// EncryptClientID encrypts a client_id for storage.
func (s *CryptoService) EncryptClientID(plaintext string) (string, error) {
	key, err := crypto.ClientAtRestKey(s.masterKey)
	if err != nil {
		return "", err
	}
	ct, err := crypto.Encrypt([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ct), nil
}

// DecryptClientID decrypts a stored client_id.
func (s *CryptoService) DecryptClientID(encryptedHex string) (string, error) {
	ct, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}
	key, err := crypto.ClientAtRestKey(s.masterKey)
	if err != nil {
		return "", err
	}
	pt, err := crypto.Decrypt(ct, key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptPayload encrypts a payload for transport.
func (s *CryptoService) EncryptPayload(plaintext []byte) ([]byte, error) {
	key, err := crypto.PayloadTransportKey(s.masterKey)
	if err != nil {
		return nil, err
	}
	return crypto.Encrypt(plaintext, key)
}

// DecryptPayload decrypts a transport payload.
func (s *CryptoService) DecryptPayload(ciphertext []byte) ([]byte, error) {
	key, err := crypto.PayloadTransportKey(s.masterKey)
	if err != nil {
		return nil, err
	}
	return crypto.Decrypt(ciphertext, key)
}
