package db_test

import (
	"testing"

	"gofiber_template/internal/db"
	"gofiber_template/internal/models"
	"gorm.io/gorm"
)

func setupBenchDB(b *testing.B) *gorm.DB {
	b.Helper()
	gormDB, err := db.Open(b.TempDir() + "/bench.db")
	if err != nil {
		b.Fatal(err)
	}
	_ = gormDB.AutoMigrate(&models.Item{})
	return gormDB
}

func BenchmarkItemCreate(b *testing.B) {
	gormDB := setupBenchDB(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		item := models.Item{Name: "bench"}
		gormDB.Create(&item)
	}
}

func BenchmarkItemRead(b *testing.B) {
	gormDB := setupBenchDB(b)
	item := models.Item{Name: "bench"}
	gormDB.Create(&item)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var found models.Item
		gormDB.First(&found, item.ID)
	}
}

func BenchmarkItemList(b *testing.B) {
	gormDB := setupBenchDB(b)
	for j := 0; j < 100; j++ {
		gormDB.Create(&models.Item{Name: "bench"})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var items []models.Item
		gormDB.Limit(20).Find(&items)
	}
}
