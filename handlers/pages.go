package handlers

import (
	"errors"
	"html/template"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

var tmpl *template.Template
var startupVersion = time.Now().Unix()

func LoadTemplates(pattern string) error {
	var err error
	tmpl, err = template.ParseGlob(pattern)
	return err
}

func Index(c fiber.Ctx) error {
	sessionID := c.Cookies(sessionCookieName)

	data := pageData{
		Services: config.C.Services,
		AppEnv:   config.C.AppEnv,
		Version:  startupVersion,
	}

	if sessionID != "" {
		ip := c.IP()
		ua := c.Get("User-Agent")

		user, err := services.ValidateSession(sessionID, ip, ua)
		if err != nil {
			if !errors.Is(err, services.ErrSessionNotFound) {
				log.Warn().Err(err).Str("session", services.ShortID(sessionID)).Msg("invalid session on landing page")
			}
			clearSessionCookie(c)
		} else {
			data.LoggedIn = true
			data.UserName = user.FullName
			data.CID = user.CID
			data.IsAdmin = services.UserIsAdministrator(user)

			userRoles := make([]string, 0, len(user.Roles))
			addedAdmin := false
			for _, r := range user.Roles {
				userRoles = append(userRoles, r.Name)
				if r.Name == "administrator" {
					addedAdmin = true
				}
			}
			if data.IsAdmin && user.CID == config.C.AdminCID && !addedAdmin {
				userRoles = append(userRoles, "administrator")
			}
			data.UserRoles = userRoles

			if data.IsAdmin {
				if suspended, err := services.GetSuspension(user.CID); err == nil && suspended != nil {
					data.SuspendedUntil = suspended
					data.SuspendedUntilStr = suspended.UTC().Format("15:04Z")
				}
			}

			if !data.IsAdmin {
				if roles, err := services.ListRoles(); err == nil {
					newRoles := make([]models.Role, 0, len(roles))
					for _, r := range roles {
						if r.Name != "administrator" {
							newRoles = append(newRoles, r)
						}
					}
					data.Roles = newRoles
				}
			}
		}
	}

	c.Set("Content-Type", "text/html; charset=utf-8")

	if err := tmpl.ExecuteTemplate(c.Response().BodyWriter(), "index.html", data); err != nil {
		log.Error().Err(err).Msg("template render error")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	return nil
}
