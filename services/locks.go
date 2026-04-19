package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
)

const systemAPIKeyName = "__system_locks"

var (
	ErrLockServiceUnavailable = errors.New("lock service unavailable")
	ErrCtpAPINotConfigured    = errors.New("CTP_API_URL not configured")

	systemAPIKeyOnce sync.Once
	systemAPIKeyRaw  string
)

func ensureSystemAPIKey() string {
	systemAPIKeyOnce.Do(func() {
		var existing models.APIKey
		err := database.DB.Where("name = ?", systemAPIKeyName).First(&existing).Error
		if err == nil {
			// Key exists but we can't recover the raw value; rotate it
			database.DB.Delete(&existing)
			apiKeyCacheMu.Lock()
			for hash, k := range apiKeyCache {
				if k.ID == existing.ID {
					delete(apiKeyCache, hash)
					break
				}
			}
			apiKeyCacheMu.Unlock()
		}

		key, err := CreateAPIKey(systemAPIKeyName, 100000, false)
		if err != nil {
			log.Error().Err(err).Msg("locks: failed to create system api key")
			return
		}
		systemAPIKeyRaw = key.RawKey
		log.Info().Msg("locks: system api key ready")
	})
	return systemAPIKeyRaw
}

type LockState struct {
	SlotLock  bool `json:"slotLock"`
	RouteLock bool `json:"routeLock"`
}

// GetLockSettings fetches the current lock state from ctp-api.
func GetLockSettings() (*LockState, error) {
	apiURL := config.C.CtpAPIURL
	if apiURL == "" {
		return &LockState{}, nil
	}

	apiKey := ensureSystemAPIKey()
	if apiKey == "" {
		return nil, ErrLockServiceUnavailable
	}

	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/locks", nil)
	if err != nil {
		return nil, fmt.Errorf("creating lock request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("locks: ctp-api unreachable")
		return nil, ErrLockServiceUnavailable
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Warn().Int("status", resp.StatusCode).Msg("locks: ctp-api returned non-200 on lock get")
		return nil, ErrLockServiceUnavailable
	}

	var state LockState
	if err := json.Unmarshal(body, &state); err != nil {
		return nil, fmt.Errorf("parsing lock state: %w", err)
	}
	return &state, nil
}

// SetSlotLock updates the slot lock in ctp-api.
func SetSlotLock(locked bool) error {
	return updateRemoteLock(func(s *LockState) { s.SlotLock = locked })
}

// SetRouteLock updates the route lock in ctp-api.
func SetRouteLock(locked bool) error {
	return updateRemoteLock(func(s *LockState) { s.RouteLock = locked })
}

func updateRemoteLock(mutate func(*LockState)) error {
	apiURL := config.C.CtpAPIURL
	if apiURL == "" {
		return ErrCtpAPINotConfigured
	}

	apiKey := ensureSystemAPIKey()
	if apiKey == "" {
		return ErrLockServiceUnavailable
	}

	// Read current state first so we only change the requested field
	current, err := GetLockSettings()
	if err != nil {
		return err
	}

	mutate(current)

	body, _ := json.Marshal(current)

	req, err := http.NewRequest(http.MethodPut, apiURL+"/api/locks", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating lock update request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("locks: ctp-api unreachable on update")
		return ErrLockServiceUnavailable
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Warn().Int("status", resp.StatusCode).Str("body", string(respBody)).Msg("locks: ctp-api returned non-200 on lock update")
		return ErrLockServiceUnavailable
	}

	return nil
}
