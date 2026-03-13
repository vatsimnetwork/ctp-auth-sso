package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"gorm.io/gorm"
)

var (
	ErrAPIKeyNotFound = errors.New("api key not found")
)

func CreateAPIKey(name string, rateLimit int) (*models.APIKey, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generating api key: %w", err)
	}
	rawHex := hex.EncodeToString(raw)

	h := sha256.Sum256([]byte(rawHex))
	keyHash := hex.EncodeToString(h[:])

	key := &models.APIKey{
		Name:      name,
		KeyHash:   keyHash,
		RateLimit: rateLimit,
	}
	if err := database.DB.Create(key).Error; err != nil {
		return nil, fmt.Errorf("storing api key: %w", err)
	}

	key.RawKey = rawHex
	return key, nil
}

func ListAPIKeys() ([]models.APIKey, error) {
	var keys []models.APIKey
	if err := database.DB.Order("created_at desc").Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}
	return keys, nil
}

func RevokeAPIKey(id uint) error {
	result := database.DB.Delete(&models.APIKey{}, id)
	if result.Error != nil {
		return fmt.Errorf("revoking api key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

func ValidateAPIKey(raw string) (*models.APIKey, error) {
	h := sha256.Sum256([]byte(raw))
	keyHash := hex.EncodeToString(h[:])

	var key models.APIKey
	err := database.DB.Where("key_hash = ?", keyHash).First(&key).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up api key: %w", err)
	}
	return &key, nil
}
