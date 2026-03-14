package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog/log"
)

type ServiceEntry struct {
	Name string
	URL  string
}

type Config struct {
	AppEnv  string
	AppPort string
	AppURL  string

	CookieDomain string
	CookieSecure bool

	DatabaseURL string

	VatsimBaseURL      string
	VatsimClientID     string
	VatsimClientSecret string
	VatsimRedirectURI  string

	InternalAPIKey string

	StateTokenSecret string

	// IPs that can validate Sessions
	InternalAllowlist []string

	// Origins allowed as return_to destinations after login
	RedirectAllowlist []string

	AdminCID string

	TrustedProxies []string

	ProxyHeader string

	Services []ServiceEntry

	IdleTimeoutHours    int
	SessionLifetimeDays int
}

var C *Config

func Load() {
	_ = godotenv.Load()

	env := getEnv("APP_ENV", "development")

	vatsimBase := "https://auth-dev.vatsim.net"
	if env == "production" {
		vatsimBase = "https://auth.vatsim.net"
	}

	C = &Config{
		AppEnv:  env,
		AppPort: getEnv("APP_PORT", "3000"),
		AppURL:  getEnv("APP_URL", "http://localhost:3000"),

		CookieDomain: getEnv("COOKIE_DOMAIN", ""),
		CookieSecure: env == "production",

		DatabaseURL: requireEnv("DATABASE_URL"),

		VatsimBaseURL:      vatsimBase,
		VatsimClientID:     requireEnv("VATSIM_CLIENT_ID"),
		VatsimClientSecret: requireEnv("VATSIM_CLIENT_SECRET"),
		VatsimRedirectURI:  requireEnv("VATSIM_REDIRECT_URI"),

		InternalAPIKey:    requireEnv("INTERNAL_API_KEY"),
		StateTokenSecret:  requireEnv("STATE_TOKEN_SECRET"),
		InternalAllowlist: splitCSV(getEnv("INTERNAL_ALLOWLIST", "")),
		RedirectAllowlist: splitCSV(getEnv("REDIRECT_ALLOWLIST", "")),

		AdminCID: getEnv("ADMIN_CID", ""),

		TrustedProxies: splitCSV(getEnv("TRUSTED_PROXIES", "")),
		ProxyHeader:    getEnv("PROXY_HEADER", "X-Forwarded-For"),

		Services: loadServices(),

		IdleTimeoutHours:    getEnvInt("IDLE_TIMEOUT_HOURS", 4),
		SessionLifetimeDays: getEnvInt("SESSION_LIFETIME_DAYS", 14),
	}

	log.Info().
		Str("env", C.AppEnv).
		Str("vatsim_base", C.VatsimBaseURL).
		Str("port", C.AppPort).
		Int("services", len(C.Services)).
		Int("internal_allowlist", len(C.InternalAllowlist)).
		Int("redirect_allowlist", len(C.RedirectAllowlist)).
		Int("trusted_proxies", len(C.TrustedProxies)).
		Msg("config loaded")
}

func loadServices() []ServiceEntry {
	keys := getEnv("SERVICES", "")
	if keys == "" {
		return nil
	}

	var entries []ServiceEntry
	for _, key := range strings.Split(keys, ",") {
		key = strings.TrimSpace(strings.ToUpper(key))
		if key == "" {
			continue
		}
		u := getEnv("SERVICE_"+key+"_URL", "")
		n := getEnv("SERVICE_"+key+"_NAME", key)
		if u == "" {
			log.Warn().Str("key", key).Msg("service entry missing URL, skipping")
			continue
		}
		entries = append(entries, ServiceEntry{Name: n, URL: u})
	}
	return entries
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		log.Warn().Str("key", key).Msg("invalid integer value, using default")
	}
	return fallback
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatal().Msg(fmt.Sprintf("required environment variable %q is not set", key))
	}
	return v
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
