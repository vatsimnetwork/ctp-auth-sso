package handlers

import (
	"errors"
	"html/template"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
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
			data.IsAdmin = services.IsAdministrator(user.CID)
		}
	}

	c.Set("Content-Type", "text/html; charset=utf-8")

	if err := tmpl.ExecuteTemplate(c.Response().BodyWriter(), "index.html", data); err != nil {
		log.Error().Err(err).Msg("template render error")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	return nil
}
