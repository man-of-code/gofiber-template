package cache

import (
	"sync"
	"time"
)

// TokenBlacklist is an in-memory cache for revoked JTIs (O(1) lookup).
// Entries are evicted when their TTL (expiry) has passed.
type TokenBlacklist struct {
	mu   sync.RWMutex
	data map[string]time.Time // JTI -> expiresAt
}

// NewTokenBlacklist creates a new blacklist.
func NewTokenBlacklist() *TokenBlacklist {
	return &TokenBlacklist{data: make(map[string]time.Time)}
}

// Add adds a JTI to the blacklist with the given expiry.
func (b *TokenBlacklist) Add(jti string, expiresAt time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[jti] = expiresAt
}

// Contains returns true if the JTI is blacklisted and not yet expired.
func (b *TokenBlacklist) Contains(jti string) bool {
	b.mu.RLock()
	expAt, ok := b.data[jti]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expAt) {
		b.mu.Lock()
		delete(b.data, jti)
		b.mu.Unlock()
		return false
	}
	return true
}

// AddFn is called for each (jti, expiresAt) pair when loading from DB.
type AddFn func(jti string, expiresAt time.Time)

// LoadFromDB loads revoked JTIs from a callback. Call with (jti, expiresAt) pairs.
func (b *TokenBlacklist) LoadFromDB(iter func(AddFn)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	iter(func(jti string, expiresAt time.Time) {
		if time.Now().Before(expiresAt) {
			b.data[jti] = expiresAt
		}
	})
}
