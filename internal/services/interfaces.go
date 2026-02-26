package services

import "gorm.io/gorm"

// TokenValidator is the interface used by JWT middleware.
type TokenValidator interface {
	ParseJWT(accessToken string) (*JWTClaims, error)
	ValidateBinding(claims *JWTClaims, ip, userAgent string) error
}

// TokenIssuer is the interface used by auth handlers for token operations.
type TokenIssuer interface {
	IssueToken(clientID, clientSecret, ip, userAgent string) (*TokenPair, error)
	RefreshToken(refreshToken, ip, userAgent string) (*TokenPair, error)
	RevokeToken(accessToken, bodyToken, ip string) error
	RevokeAllForClient(clientDBID uint) error
	RevokeAllForClientTx(tx *gorm.DB, clientDBID uint) error
}

// ClientManager is the interface used by auth handlers for client operations.
type ClientManager interface {
	RegisterClient(name string, allowedIPs []string) (*RegisterClientResult, error)
	ValidateCredentials(clientIDPlain, clientSecret string) (string, error)
	ListClients(page, limit int) ([]*ClientView, int64, error)
	GetClient(id uint) (*ClientView, error)
	UpdateClient(id uint, name string, allowedIPs []string, status string) (*ClientView, error)
	DeleteClient(id uint) error
	DeleteClientTx(tx *gorm.DB, id uint) error
}

// PayloadCryptor is the interface for payload encryption/decryption.
type PayloadCryptor interface {
	EncryptPayload(plaintext []byte) ([]byte, error)
	DecryptPayload(ciphertext []byte) ([]byte, error)
	EncryptClientID(plaintext string) (string, error)
	DecryptClientID(encryptedHex string) (string, error)
}
