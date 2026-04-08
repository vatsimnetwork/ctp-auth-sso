package middleware

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"github.com/vatsimnetwork/ctp-auth-sso/handlers"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

func RequireAdmin(c fiber.Ctx) error {
	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		return c.Redirect().To("/")
	}

	user, err := services.ValidateSession(sessionID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if !errors.Is(err, services.ErrSessionNotFound) {
			_ = err
		}
		return c.Redirect().To("/")
	}

	if !services.UserIsAdministrator(user) {
		return c.Status(fiber.StatusForbidden).SendString("forbidden")
	}

	if !handlers.ValidReauthCookie(c) {
		handlers.SetReturnToCookie(c, c.Path())
		return c.Redirect().To("/auth/login")
	}

	c.Locals("adminCID", user.CID)
	return c.Next()
}

// RequireAdminSession checks that the requester is an admin without requiring a
// reauth cookie. Used for actions initiated from the landing page where the
// reauth redirect chain would pass through external OAuth and violate CSP
// form-action 'self'.
func RequireAdminSession(c fiber.Ctx) error {
	sessionID := c.Cookies("session_id")
	if sessionID == "" {
		return c.Redirect().To("/")
	}

	user, err := services.ValidateSession(sessionID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		if !errors.Is(err, services.ErrSessionNotFound) {
			_ = err
		}
		return c.Redirect().To("/")
	}

	if !services.UserIsAdministrator(user) {
		return c.Status(fiber.StatusForbidden).SendString("forbidden")
	}

	c.Locals("adminCID", user.CID)
	return c.Next()
}
