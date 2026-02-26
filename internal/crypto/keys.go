package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"

	"golang.org/x/crypto/hkdf"
)

const keySize = 32

// Key contexts for HKDF derivation.
const (
	ContextClientAtRest     = "client-at-rest"
	ContextTokenAtRest      = "token-at-rest"
	ContextPayloadTransport = "payload-transport"
)

var appSalt = []byte("hanushield-v1")

// deriveKey derives a 32-byte key from master using HKDF-SHA256.
func deriveKey(master []byte, context string) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, master, appSalt, []byte(context))
	key := make([]byte, keySize)
	if _, err := hkdf.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// MasterKey returns the 32-byte master encryption key from env ENCRYPTION_KEY (hex-encoded).
func MasterKey() ([]byte, error) {
	hexKey := os.Getenv("ENCRYPTION_KEY")
	if hexKey == "" {
		return nil, errors.New("ENCRYPTION_KEY not set")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, errors.New("ENCRYPTION_KEY must be hex-encoded")
	}
	if len(key) != 32 {
		return nil, errors.New("ENCRYPTION_KEY must be 32 bytes (64 hex chars)")
	}
	return key, nil
}

// ClientAtRestKey derives the key for encrypting client_id at rest.
func ClientAtRestKey(master []byte) ([]byte, error) {
	return deriveKey(master, ContextClientAtRest)
}

// TokenAtRestKey derives the key for token-related encryption.
func TokenAtRestKey(master []byte) ([]byte, error) {
	return deriveKey(master, ContextTokenAtRest)
}

// PayloadTransportKey derives the key for request/response payload encryption.
func PayloadTransportKey(master []byte) ([]byte, error) {
	return deriveKey(master, ContextPayloadTransport)
}
