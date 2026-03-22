package handlers

import (
	"crypto/subtle"
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

func ValidateSession(c fiber.Ctx) error {
	if subtle.ConstantTimeCompare([]byte(c.Get("X-Internal-Key")), []byte(config.C.InternalAPIKey)) != 1 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "unauthorized",
			"message": "invalid or missing internal api key",
		})
	}

	sessionID := c.Cookies(sessionCookieName)
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error":   "unauthorized",
			"message": "no session cookie present",
		})
	}

	ip := c.IP()
	ua := c.Get("User-Agent")

	user, err := services.ValidateSession(sessionID, ip, ua)
	if err != nil {
		status := ErrToStatus(err)

		errCode := "invalid_session"
		switch {
		case errors.Is(err, services.ErrSessionExpired):
			errCode = "session_expired"
		case errors.Is(err, services.ErrSessionIdle):
			errCode = "session_idle"
		case errors.Is(err, services.ErrFingerprintMismatch):
			log.Warn().Str("session", services.ShortID(sessionID)).Str("ip", ip).Msg("fingerprint mismatch on validate")
			errCode = "session_hijack_detected"
		}

		return c.Status(status).JSON(fiber.Map{
			"error":   errCode,
			"message": err.Error(),
		})
	}

	log.Debug().Str("session", services.ShortID(sessionID)).Str("cid", user.CID).Msg("session valid")

	addedAdmin := false
	roles := make([]string, len(user.Roles))
	for i, r := range user.Roles {
		roles[i] = r.Name
		if r.Name == "administrator" {
			addedAdmin = true
		}
	}

	if user.CID == config.C.AdminCID && !addedAdmin {
		roles = append(roles, "administrator")
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"cid":   user.CID,
		"roles": roles,
	})
}
