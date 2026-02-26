package models

import (
	"time"

	"gorm.io/gorm"
)

// Client represents an API client with credentials.
type Client struct {
	ID              uint           `gorm:"primaryKey"`
	ClientIDHash    string         `gorm:"uniqueIndex;size:64"`   // SHA256 of client_id for lookup
	ClientIDEnc     string         `gorm:"size:256"`               // AES-GCM encrypted client_id at rest
	SecretHash      string         `gorm:"size:256"`              // bcrypt hash of the secret
	Name            string         `gorm:"size:255"`
	AllowedIPs      string         `gorm:"size:1024"`             // JSON array of CIDR ranges
	Status          string         `gorm:"size:20;default:active"` // active, suspended, revoked
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

// TableName overrides the table name.
func (Client) TableName() string {
	return "clients"
}
