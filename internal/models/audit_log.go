package models

import "time"

// AuditLog stores security and mutation events for traceability.
type AuditLog struct {
	ID        uint      `gorm:"primaryKey"`
	RequestID string    `gorm:"index;size:64"`
	Action    string    `gorm:"size:64"`
	ClientID  string    `gorm:"index;size:64"`
	IPAddress string    `gorm:"size:45"`
	UserAgent string    `gorm:"size:512"`
	Detail    string    `gorm:"type:text"`
	CreatedAt time.Time `gorm:"index"`
}

// TableName overrides the table name.
func (AuditLog) TableName() string {
	return "audit_logs"
}
