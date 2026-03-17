package middleware

import (
	"net"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
)

func IPAllowlist(patterns []string) fiber.Handler {
	matchers := buildMatchers(patterns)

	return func(c fiber.Ctx) error {
		addr := c.RequestCtx().RemoteAddr().String()
		ipStr, _, err := net.SplitHostPort(addr)
		if err != nil {
			log.Warn().Str("remote_addr", addr).Err(err).Msg("allowlist: could not parse remote address, denying")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "forbidden",
				"message": "access denied",
			})
		}
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			log.Warn().Str("raw_ip", ipStr).Msg("allowlist: could not parse request IP, denying")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "forbidden",
				"message": "access denied",
			})
		}

		for _, m := range matchers {
			if m(parsed) {
				return c.Next()
			}
		}

		log.Warn().Str("ip", ipStr).Msg("allowlist: request denied")
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":   "forbidden",
			"message": "access denied",
		})
	}
}

type matcherFn func(net.IP) bool

func buildMatchers(patterns []string) []matcherFn {
	var ms []matcherFn

	for _, raw := range patterns {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		m, err := buildMatcher(raw)
		if err != nil {
			log.Error().Str("pattern", raw).Err(err).Msg("allowlist: invalid IP pattern, skipping")
			continue
		}
		ms = append(ms, m)
	}

	return ms
}

func buildMatcher(pattern string) (matcherFn, error) {
	if strings.Contains(pattern, "/") {
		_, network, err := net.ParseCIDR(pattern)
		if err != nil {
			return nil, err
		}
		return func(ip net.IP) bool { return network.Contains(ip) }, nil
	}

	if strings.Contains(pattern, "*") {
		cidr, err := wildcardToCIDR(pattern)
		if err != nil {
			return nil, err
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		return func(ip net.IP) bool { return network.Contains(ip) }, nil
	}

	exact := net.ParseIP(pattern)
	if exact == nil {
		return nil, &net.AddrError{Err: "invalid IP address", Addr: pattern}
	}
	return func(ip net.IP) bool { return ip.Equal(exact) }, nil
}

// Examples what this does
//
//	"10.0.*" becomes "10.0.0.0/16"
//	"10.*.*"   → "10.0.0.0/8"
//	"10.0.1.*" → "10.0.1.0/24"
func wildcardToCIDR(pattern string) (string, error) {
	parts := strings.Split(pattern, ".")

	if len(parts) > 4 {
		return "", &net.AddrError{Err: "too many octets in wildcard pattern", Addr: pattern}
	}

	concrete := [4]string{"0", "0", "0", "0"}
	prefixBits := 0

	for i, p := range parts {
		if p == "*" {
			break
		}
		concrete[i] = p
		prefixBits += 8
	}

	cidr := strings.Join(concrete[:], ".") + "/" + strconv.Itoa(prefixBits)
	return cidr, nil
}
