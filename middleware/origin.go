package middleware

import (
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v3"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
)

func OriginCheck(c fiber.Ctx) error {
	if c.Method() != fiber.MethodPost {
		return c.Next()
	}

	origin := c.Get("Origin")
	if origin == "" {
		referer := c.Get("Referer")
		if referer != "" && originMatchesApp(referer) {
			return c.Next()
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "forbidden",
			"message": "missing origin header",
		})
	}

	if origin != config.C.AppURL {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "forbidden",
			"message": "origin not allowed",
		})
	}

	return c.Next()
}

func originMatchesApp(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host) == config.C.AppURL
}
