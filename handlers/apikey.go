package handlers

import (
	"errors"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

type rateBucket struct {
	mu        sync.Mutex
	count     int
	windowEnd time.Time
}

var apiKeyBuckets sync.Map

func checkAPIKeyRateLimit(keyHash string, limit int) bool {
	v, _ := apiKeyBuckets.LoadOrStore(keyHash, &rateBucket{})
	b := v.(*rateBucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if now.After(b.windowEnd) {
		b.count = 0
		b.windowEnd = now.Add(time.Minute)
	}

	if b.count >= limit {
		return false
	}
	b.count++
	return true
}

func ValidateAPIKey(c fiber.Ctx) error {
	raw := c.Get("X-API-Key")
	if raw == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "unauthorized",
			"message": "missing api key",
		})
	}

	key, err := services.ValidateAPIKey(raw)
	if err != nil {
		if errors.Is(err, services.ErrAPIKeyNotFound) {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "unauthorized",
				"message": "invalid api key",
			})
		}
		log.Error().Err(err).Msg("apikey: validate error")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "an internal error occurred",
		})
	}

	if !checkAPIKeyRateLimit(key.KeyHash, key.RateLimit) {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error":   "rate_limit_exceeded",
			"message": "too many requests, please try again later",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"valid": true,
	})
}
