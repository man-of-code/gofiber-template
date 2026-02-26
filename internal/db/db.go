package db

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open opens a SQLite database at path and returns the GORM DB.
// Creates the parent directory of path if it does not exist.
// Optimized for sub-10ms latency: WAL mode, pragmas, single-writer pool.
func Open(path string) (*gorm.DB, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
	}
	// WAL mode, NORMAL sync, 64MB cache, memory temp store, 5s busy timeout, 256MB mmap
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_synchronous=NORMAL&_cache_size=-64000&_temp_store=MEMORY&_busy_timeout=5000&_mmap_size=268435456", path)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		PrepareStmt: true,
		Logger:      logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	// WAL allows concurrent reads
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}
