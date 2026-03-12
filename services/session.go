package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"gorm.io/gorm"
)

var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionRevoked      = errors.New("session revoked")
	ErrSessionExpired      = errors.New("session expired")
	ErrSessionIdle         = errors.New("session idle timeout exceeded")
	ErrFingerprintMismatch = errors.New("session fingerprint mismatch")
)

func CreateSession(userID uint, ip, userAgent string) (*models.Session, error) {
	if err := RevokeAllUserSessions(userID); err != nil {
		return nil, fmt.Errorf("revoking old sessions: %w", err)
	}

	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}

	now := time.Now()
	session := &models.Session{
		ID:         hashSessionToken(token),
		UserID:     userID,
		IPAddress:  ip,
		UAHash:     hashUA(userAgent),
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Duration(config.C.SessionLifetimeDays) * 24 * time.Hour),
		Revoked:    false,
		Token:      token,
	}

	if err := database.DB.Create(session).Error; err != nil {
		return nil, fmt.Errorf("storing session: %w", err)
	}

	return session, nil
}

func ValidateSession(token, ip, userAgent string) (*models.User, error) {
	sessionID := hashSessionToken(token)
	var session models.Session
	err := database.DB.Preload("User.Roles").First(&session, "id = ?", sessionID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("looking up session: %w", err)
	}

	if session.Revoked {
		return nil, ErrSessionRevoked
	}

	now := time.Now()

	if now.After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	idleLimit := time.Duration(config.C.IdleTimeoutHours) * time.Hour
	if now.After(session.LastSeenAt.Add(idleLimit)) {
		return nil, ErrSessionIdle
	}

	if session.UAHash != hashUA(userAgent) {
		log.Warn().
			Str("session", ShortID(sessionID)).
			Bool("ip_changed", session.IPAddress != ip).
			Msg("session fingerprint mismatch: UA hash changed")
		return nil, ErrFingerprintMismatch
	}

	if session.IPAddress != ip {
		log.Warn().
			Str("session", ShortID(sessionID)).
			Str("old_ip", session.IPAddress).
			Str("new_ip", ip).
			Msg("session IP changed (UA unchanged), updating stored IP")
		if err := database.DB.Model(&session).Update("ip_address", ip).Error; err != nil {
			log.Warn().Err(err).Str("session", ShortID(sessionID)).Msg("failed to update ip_address")
		}
	}

	if err := database.DB.Model(&session).Update("last_seen_at", now).Error; err != nil {
		log.Warn().Err(err).Str("session", ShortID(sessionID)).Msg("failed to update last_seen_at")
	}

	return &session.User, nil
}

func RevokeSession(token string) error {
	result := database.DB.Model(&models.Session{}).
		Where("id = ? AND revoked = false", hashSessionToken(token)).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("revoking session: %w", result.Error)
	}
	return nil
}

func RevokeAllUserSessions(userID uint) error {
	result := database.DB.Model(&models.Session{}).
		Where("user_id = ? AND revoked = false", userID).
		Update("revoked", true)
	if result.Error != nil {
		return fmt.Errorf("revoking user sessions: %w", result.Error)
	}
	return nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func GenerateStateToken() (string, error) {
	nonce, err := generateToken()
	if err != nil {
		return "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	payload := ts + "." + nonce
	mac := computeStateMAC(payload)
	return payload + "." + mac, nil
}

func ValidateStateToken(token string) bool {
	lastDot := strings.LastIndexByte(token, '.')
	if lastDot < 1 {
		return false
	}
	payload := token[:lastDot]
	gotMAC := token[lastDot+1:]

	expectedMAC := computeStateMAC(payload)
	if !hmac.Equal([]byte(gotMAC), []byte(expectedMAC)) {
		return false
	}

	firstDot := strings.IndexByte(payload, '.')
	if firstDot < 1 {
		return false
	}
	ts, err := strconv.ParseInt(payload[:firstDot], 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(ts, 0)) <= 10*time.Minute
}

func computeStateMAC(payload string) string {
	mac := hmac.New(sha256.New, []byte(config.C.StateTokenSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func hashUA(userAgent string) string {
	sum := sha256.Sum256([]byte(userAgent))
	return hex.EncodeToString(sum[:8])
}

func ShortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8] + "…"
}

func StartSessionCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			result := database.DB.
				Where("expires_at < ? OR revoked = true", time.Now()).
				Delete(&models.Session{})
			if result.Error != nil {
				log.Error().Err(result.Error).Msg("session cleanup failed")
			} else if result.RowsAffected > 0 {
				log.Info().Int64("deleted", result.RowsAffected).Msg("session cleanup complete")
			}
		}
	}()
}

const reauthWindow = 15 * time.Minute

func GenerateReauthToken() string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := computeStateMAC(ts)
	return ts + "." + mac
}

func ValidateReauthToken(token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot < 1 {
		return false
	}
	payload := token[:dot]
	gotMAC := token[dot+1:]

	expectedMAC := computeStateMAC(payload)
	if !hmac.Equal([]byte(gotMAC), []byte(expectedMAC)) {
		return false
	}

	ts, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	return time.Since(time.Unix(ts, 0)) <= reauthWindow
}
