package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/favicon"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tdewolff/minify/v2"
	minifyjs "github.com/tdewolff/minify/v2/js"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/handlers"
	"github.com/vatsimnetwork/ctp-auth-sso/middleware"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

//go:embed static
var staticFiles embed.FS

func buildAssets(fsys fs.FS) (map[string][]byte, error) {
	m := minify.New()
	m.AddFunc("application/javascript", minifyjs.Minify)

	assets := make(map[string][]byte)
	err := fs.WalkDir(fsys, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		key := strings.TrimPrefix(path, "static/")
		if strings.HasSuffix(path, ".js") {
			minified, err := m.String("application/javascript", string(data))
			if err != nil {
				return err
			}
			data = []byte(minified)
		}
		assets[key] = data
		return nil
	})
	return assets, err
}


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

	assets, err := buildAssets(staticFiles)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to build static assets")
	}
	log.Info().Int("count", len(assets)).Msg("static assets loaded")

	app.Use(recover.New())
	app.Use(middleware.SecurityHeaders())
	app.Use(favicon.New(favicon.Config{File: "favicon.ico"}))

	app.Use("/static/", func(c fiber.Ctx) error {
		key := strings.TrimPrefix(c.Path(), "/static/")
		data, ok := assets[key]
		if !ok {
			return fiber.ErrNotFound
		}
		ct := mime.TypeByExtension(filepath.Ext(key))
		if ct == "" {
			if strings.HasSuffix(key, ".js") {
				ct = "application/javascript"
			} else {
				ct = "application/octet-stream"
			}
		}
		c.Set("Content-Type", ct)
		c.Set("Cache-Control", "public, max-age=31536000, immutable")
		return c.Send(data)
	})

	authLimiter := middleware.AuthLimiter()

	app.Get("/", handlers.Index)
	app.Get("/auth/login", authLimiter, handlers.Login)
	app.Get("/auth/redirect", authLimiter, handlers.Redirect)
	app.Get("/auth/callback", authLimiter, handlers.Callback)
	app.Post("/auth/logout", authLimiter, middleware.OriginCheck, handlers.Logout)
	app.Post("/role-requests", middleware.OriginCheck, handlers.RequestAccess)

	admin := app.Group("/admin", middleware.RequireAdmin)
	admin.Get("/", handlers.AdminPanel)
	admin.Post("/roles/create", middleware.OriginCheck, handlers.AdminCreateRole)
	admin.Post("/roles/delete", middleware.OriginCheck, handlers.AdminDeleteRole)
	admin.Get("/users/roles", handlers.AdminGetUserRoles)
	admin.Post("/roles/set", middleware.OriginCheck, handlers.AdminSetRoles)
	admin.Post("/roles/remove", middleware.OriginCheck, handlers.AdminRemoveRole)
	admin.Post("/roles/bulk-assign", middleware.OriginCheck, handlers.AdminBulkAssignRole)
	admin.Post("/apikeys/create", middleware.OriginCheck, handlers.AdminCreateAPIKey)
	admin.Post("/apikeys/revoke", middleware.OriginCheck, handlers.AdminRevokeAPIKey)
	admin.Post("/requests/approve", middleware.OriginCheck, handlers.AdminApproveRequest)
	admin.Post("/requests/deny-one", middleware.OriginCheck, handlers.AdminDenySingleRequest)
	admin.Post("/requests/deny", middleware.OriginCheck, handlers.AdminDenyRequests)

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

	addr := fmt.Sprintf("0.0.0.0:%s", config.C.AppPort)
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
