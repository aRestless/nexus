package model

import (
	"database/sql"
	"fmt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
)
import "gorm.io/driver/sqlite"

func NewDatabase(path string, admins map[string]string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.Logger = logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		LogLevel: logger.Info,
	})

	err = migrate(db)
	if err != nil {
		return nil, err
	}

	err = createAdmins(db, admins)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func migrate(db *gorm.DB) error {
	models := []interface{}{
		&Admin{},
		&Certificate{},
		&Client{},
		&ClientNetwork{},
		&Lighthouse{},
		&Network{},
		&NetworkGroup{},
		&Router{},
	}

	return db.AutoMigrate(models...)
}

func createAdmins(db *gorm.DB, admins map[string]string) error {
	db.Unscoped().Delete(&Admin{}, "1 = 1")

	for name, pubKeyHash := range admins {
		db.Create(&Admin{
			Name: name,
			PublicKeyHash: sql.NullString{
				String: pubKeyHash,
				Valid:  true,
			},
		})
	}

	return nil
}
