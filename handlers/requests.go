package handlers

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

func RequestAccess(c fiber.Ctx) error {
	sessionID := c.Cookies(sessionCookieName)
	if sessionID == "" {
		return c.Status(fiber.StatusUnauthorized).SendString("unauthorized")
	}

	user, err := services.ValidateSession(sessionID, c.IP(), c.Get("User-Agent"))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("unauthorized")
	}

	roleValues := c.Request().PostArgs().PeekMulti("role")
	if len(roleValues) == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("select at least one role")
	}

	reason := strings.TrimSpace(c.FormValue("reason"))
	if reason == "" || utf8.RuneCountInString(reason) > 500 {
		return c.Status(fiber.StatusBadRequest).SendString("reason must be 1–500 characters")
	}

	roles := make([]string, 0, len(roleValues))
	for _, rb := range roleValues {
		role := string(rb)
		if !validateRoleName(role) {
			return c.Status(fiber.StatusBadRequest).SendString("invalid role name")
		}
		roles = append(roles, role)
	}

	if err := services.CreateRoleRequests(user.ID, roles, reason); err != nil {
		log.Error().Err(err).Str("cid", user.CID).Msg("failed to create role requests")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Str("cid", user.CID).Strs("roles", roles).Msg("role access requested")
	return c.Redirect().To("/")
}

func AdminApproveRequest(c fiber.Ctx) error {
	raw := c.FormValue("id")
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("invalid request id")
	}

	if err := services.ApproveRoleRequest(uint(id)); err != nil {
		if errors.Is(err, services.ErrRequestNotFound) {
			return c.Status(fiber.StatusNotFound).SendString("request not found")
		}
		log.Error().Err(err).Uint64("id", id).Msg("admin: failed to approve request")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Uint64("id", id).Str("by", c.Locals("adminCID").(string)).Msg("admin: role request approved")
	return c.Redirect().To("/admin")
}

func AdminDenyRequests(c fiber.Ctx) error {
	raw := c.FormValue("user_id")
	userID, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || userID == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("invalid user id")
	}

	if err := services.DenyUserRequests(uint(userID)); err != nil {
		log.Error().Err(err).Uint64("user_id", userID).Msg("admin: failed to deny requests")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Uint64("user_id", userID).Str("by", c.Locals("adminCID").(string)).Msg("admin: role requests denied")
	return c.Redirect().To("/admin")
}
