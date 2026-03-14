package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/favicon"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/handlers"
	"github.com/vatsimnetwork/ctp-auth-sso/middleware"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

func main() {
	zerolog.TimeFieldFormat = time.RFC3339
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log.Logger = zerolog.New(output).With().Timestamp().Logger()

	log.Info().Msg("starting ctpsso...")

	config.Load()

	log.Info().Msg("loading templates...")

	if err := handlers.LoadTemplates("templates/*.html"); err != nil {
		log.Fatal().Err(err).Msg("failed to load templates")
	}

	log.Info().Msg("registering routes...")

	app := fiber.New(fiber.Config{
		ServerHeader: "",

		// Only trust for known proxy, otherwise ignore X-Forwarded-For
		ProxyHeader: config.C.ProxyHeader,
		TrustProxy:  len(config.C.TrustedProxies) > 0,
		TrustProxyConfig: fiber.TrustProxyConfig{
			Proxies: config.C.TrustedProxies,
		},

		ErrorHandler: func(c fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			if code >= 500 {
				return c.Status(code).JSON(fiber.Map{
					"error":   "internal_error",
					"message": "an internal error occurred",
				})
			}
			return c.Status(code).JSON(fiber.Map{
				"error":   "error",
				"message": err.Error(),
			})
		},
	})

	app.Hooks().OnPreStartupMessage(func(sm *fiber.PreStartupMessageData) error {
		sm.BannerHeader = `
          ______________      ____________ 
         / ___/_  __/ _ \____/ __/ __/ __ \
        / /__  / / / ___/___/\ \_\ \/ /_/ /
        \___/ /_/ /_/      /___/___/\____/ 
		`
		return nil
	})

	database.Connect()

	services.StartSessionCleanup(6 * time.Hour)

	app.Use(recover.New())
	app.Use(middleware.SecurityHeaders())
	app.Use(favicon.New(favicon.Config{File: "favicon.ico"}))

	app.Use("/static", static.New("static"))

	authLimiter := middleware.AuthLimiter()

	app.Get("/", handlers.Index)
	app.Get("/auth/login", authLimiter, handlers.Login)
	app.Get("/auth/redirect", authLimiter, handlers.Redirect)
	app.Get("/auth/callback", authLimiter, handlers.Callback)
	app.Post("/auth/logout", authLimiter, middleware.OriginCheck, handlers.Logout)

	admin := app.Group("/admin", middleware.RequireAdmin)
	admin.Get("/", handlers.AdminPanel)
	admin.Post("/roles/create", middleware.OriginCheck, handlers.AdminCreateRole)
	admin.Post("/roles/delete", middleware.OriginCheck, handlers.AdminDeleteRole)
	admin.Post("/roles/assign", middleware.OriginCheck, handlers.AdminAssignRole)
	admin.Post("/roles/remove", middleware.OriginCheck, handlers.AdminRemoveRole)
	admin.Post("/apikeys/create", middleware.OriginCheck, handlers.AdminCreateAPIKey)
	admin.Post("/apikeys/revoke", middleware.OriginCheck, handlers.AdminRevokeAPIKey)

	if len(config.C.InternalAllowlist) > 0 {
		app.Get("/internal/session/validate",
			middleware.IPAllowlist(config.C.InternalAllowlist),
			handlers.ValidateSession,
		)
		app.Get("/internal/apikey/validate",
			middleware.IPAllowlist(config.C.InternalAllowlist),
			handlers.ValidateAPIKey,
		)
	} else {
		app.Get("/internal/session/validate", handlers.ValidateSession)
		app.Get("/internal/apikey/validate", handlers.ValidateAPIKey)
	}

	addr := fmt.Sprintf(":%s", config.C.AppPort)
	log.Info().Str("addr", addr).Str("env", config.C.AppEnv).Msg("listening")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Info().Msg("shutdown signal received, draining connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := app.ShutdownWithContext(ctx); err != nil {
			log.Error().Err(err).Msg("error during shutdown")
		}
	}()

	if err := app.Listen(addr); err != nil {
		log.Fatal().Err(err).Msg("server error")
	}

	log.Info().Msg("server stopped cleanly")
}
