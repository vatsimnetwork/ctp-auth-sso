package handlers

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

const stateCookieName = "oauth_state"
const sessionCookieName = "session_id"
const reauthCookieName = "reauth_at"
const returnToCookieName = "return_to"

const reauthMaxAge = 15 * 60 // 15 minutes

func Login(c fiber.Ctx) error {
	state, err := services.GenerateStateToken()
	if err != nil {
		log.Error().Err(err).Msg("failed to generate state token")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "could not initiate login",
		})
	}

	setStateCookie(c, state)

	return c.Redirect().To(services.AuthorizeURL(state))
}

func Callback(c fiber.Ctx) error {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "bad_request",
			"message": "missing code or state parameter",
		})
	}

	cookieState := c.Cookies(stateCookieName)
	if cookieState == "" || subtle.ConstantTimeCompare([]byte(cookieState), []byte(state)) != 1 {
		log.Warn().Str("ip", c.IP()).Msg("oauth state mismatch")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_state",
			"message": "oauth state mismatch, possible csrf attempt",
		})
	}

	if !services.ValidateStateToken(state) {
		log.Warn().Str("ip", c.IP()).Msg("oauth state token expired")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_state",
			"message": "oauth state token expired",
		})
	}

	clearStateCookie(c)

	vUser, err := services.ExchangeCodeAndFetchUser(code)
	if err != nil {
		log.Error().Err(err).Msg("exchange and fetch user failed")
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error":   "upstream_error",
			"message": "could not complete authentication with VATSIM",
		})
	}

	user := models.User{
		CID:      vUser.CID,
		FullName: vUser.FullName,
	}
	result := database.DB.Where(models.User{CID: vUser.CID}).Assign(user).FirstOrCreate(&user)
	if result.Error != nil {
		log.Error().Err(result.Error).Msg("user upsert failed")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "could not persist user",
		})
	}
	if result.RowsAffected == 0 {
		database.DB.Model(&user).Updates(models.User{FullName: vUser.FullName})
	}

	ip := c.IP()
	ua := c.Get("User-Agent")

	session, err := services.CreateSession(user.ID, ip, ua)
	if err != nil {
		log.Error().Err(err).Msg("session creation failed")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":   "internal_error",
			"message": "could not create session",
		})
	}

	setSessionCookie(c, session.Token, session.ExpiresAt)
	setReauthCookie(c)

	log.Info().Str("cid", vUser.CID).Str("session", services.ShortID(session.ID)).Str("ip", ip).Msg("login successful")

	returnTo := c.Cookies(returnToCookieName)
	clearReturnToCookie(c)
	if returnTo == "/admin" || returnTo == "/admin/" {
		return c.Redirect().To(returnTo)
	}
	return c.Redirect().To("/")
}

func Logout(c fiber.Ctx) error {
	sessionID := c.Cookies(sessionCookieName)
	if sessionID != "" {
		if err := services.RevokeSession(sessionID); err != nil {
			log.Error().Err(err).Str("session", services.ShortID(sessionID)).Msg("logout revoke failed")
		} else {
			log.Info().Str("session", services.ShortID(sessionID)).Str("ip", c.IP()).Msg("logout")
		}
	}

	clearSessionCookie(c)
	clearReauthCookie(c)
	return c.Redirect().To("/")
}

func setSessionCookie(c fiber.Ctx, sessionID string, expiresAt time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func clearSessionCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   -1,
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func setStateCookie(c fiber.Ctx, state string) {
	c.Cookie(&fiber.Cookie{
		Name:     stateCookieName,
		Value:    state,
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   10 * 60,
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func clearStateCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     stateCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   -1,
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func GetSessionCookieName() string {
	return sessionCookieName
}

func IsLoggedIn(c fiber.Ctx) bool {
	return c.Cookies(sessionCookieName) != ""
}

func setReauthCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     reauthCookieName,
		Value:    services.GenerateReauthToken(),
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   reauthMaxAge,
		Path:     "/admin",
		Domain:   config.C.CookieDomain,
	})
}

func clearReauthCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     reauthCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   -1,
		Path:     "/admin",
		Domain:   config.C.CookieDomain,
	})
}

func SetReturnToCookie(c fiber.Ctx, dest string) {
	c.Cookie(&fiber.Cookie{
		Name:     returnToCookieName,
		Value:    dest,
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   10 * 60,
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func clearReturnToCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     returnToCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   config.C.CookieSecure,
		SameSite: "Lax",
		MaxAge:   -1,
		Path:     "/",
		Domain:   config.C.CookieDomain,
	})
}

func ValidReauthCookie(c fiber.Ctx) bool {
	return services.ValidateReauthToken(c.Cookies(reauthCookieName))
}

func ErrToStatus(err error) int {
	switch {
	case errors.Is(err, services.ErrSessionNotFound),
		errors.Is(err, services.ErrSessionRevoked),
		errors.Is(err, services.ErrSessionExpired),
		errors.Is(err, services.ErrSessionIdle),
		errors.Is(err, services.ErrFingerprintMismatch):
		return fiber.StatusUnauthorized
	default:
		return fiber.StatusInternalServerError
	}
}
