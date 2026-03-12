package middleware

import (
	"github.com/gofiber/fiber/v3"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
)

func SecurityHeaders() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")

		c.Set("X-Frame-Options", "DENY")

		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if config.C.AppEnv == "production" {
			c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		c.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"img-src 'self' data:; "+
				"font-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self';",
		)

		return c.Next()
	}
}
