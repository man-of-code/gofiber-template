package models

import (
	"time"
)

// Token holds JWT and refresh token metadata.
type Token struct {
	ID               uint      `gorm:"primaryKey"`
	JTI              string    `gorm:"uniqueIndex;size:64"` // JWT ID
	ClientIDHash     string    `gorm:"index;size:64"`       // SHA-256 hash of client_id
	ClientDBID       uint      `gorm:"index"`               // clients.id for admin revoke-all
	RefreshTokenHash string    `gorm:"uniqueIndex;size:64"` // SHA-256 of refresh token
	IPAddress        string    `gorm:"size:45"`             // IPv4 or IPv6
	UserAgent        string    `gorm:"size:512"`
	IssuedAt         time.Time `gorm:"index"`
	ExpiresAt        time.Time `gorm:"index"`
	RefreshExpiresAt time.Time
	Revoked          bool `gorm:"default:false;index"`
	RevokedAt        *time.Time
	RevokedReason    string `gorm:"size:255"`
}

// TableName overrides the table name.
func (Token) TableName() string {
	return "tokens"
}
