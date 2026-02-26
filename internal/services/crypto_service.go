package services

import (
	"encoding/hex"

	"gofiber_template/internal/crypto"
)

// CryptoService orchestrates encrypt/decrypt of model fields and payloads.
type CryptoService struct {
	masterKey       []byte
	clientAtRestKey []byte
	payloadKey      []byte
}

// NewCryptoService creates a CryptoService. Returns error if ENCRYPTION_KEY is not set.
// appID must be unique per application (e.g. from APP_ID env) for key derivation separation.
func NewCryptoService(appID string) (*CryptoService, error) {
	master, err := crypto.MasterKey()
	if err != nil {
		return nil, err
	}
	clientKey, err := crypto.ClientAtRestKey(master, appID)
	if err != nil {
		return nil, err
	}
	payloadKey, err := crypto.PayloadTransportKey(master, appID)
	if err != nil {
		return nil, err
	}
	return &CryptoService{
		masterKey:       master,
		clientAtRestKey: clientKey,
		payloadKey:      payloadKey,
	}, nil
}

// EncryptClientID encrypts a client_id for storage.
func (s *CryptoService) EncryptClientID(plaintext string) (string, error) {
	ct, err := crypto.Encrypt([]byte(plaintext), s.clientAtRestKey)
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
	pt, err := crypto.Decrypt(ct, s.clientAtRestKey)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// EncryptPayload encrypts a payload for transport.
func (s *CryptoService) EncryptPayload(plaintext []byte) ([]byte, error) {
	return crypto.Encrypt(plaintext, s.payloadKey)
}

// DecryptPayload decrypts a transport payload.
func (s *CryptoService) DecryptPayload(ciphertext []byte) ([]byte, error) {
	return crypto.Decrypt(ciphertext, s.payloadKey)
}
