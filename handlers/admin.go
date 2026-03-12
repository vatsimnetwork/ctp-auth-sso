package handlers

import (
	"errors"
	"regexp"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog/log"
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/services"
)

var (
	reNumeric  = regexp.MustCompile(`^\d+$`)
	reRoleName = regexp.MustCompile(`^[a-z0-9_]+$`)
)

func validateCID(cid string) bool {
	return cid != "" && utf8.RuneCountInString(cid) <= 20 && reNumeric.MatchString(cid)
}

func validateRoleName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= 64 && reRoleName.MatchString(name)
}

type adminPageData struct {
	Roles      []services.RoleWithUsers
	AdminCID   string
	SessionCID string
	Version    int64
}

func AdminPanel(c fiber.Ctx) error {
	roles, err := services.ListRolesWithUsers()
	if err != nil {
		log.Error().Err(err).Msg("admin: failed to list roles")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	data := adminPageData{
		Roles:      roles,
		AdminCID:   config.C.AdminCID,
		SessionCID: c.Locals("adminCID").(string),
		Version:    startupVersion,
	}

	c.Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(c.Response().BodyWriter(), "admin.html", data); err != nil {
		log.Error().Err(err).Msg("admin: template render error")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}
	return nil
}

func AdminCreateRole(c fiber.Ctx) error {
	name := c.FormValue("name")
	if !validateRoleName(name) {
		return c.Status(fiber.StatusBadRequest).SendString("role name must be 1–64 lowercase alphanumeric/underscore characters")
	}

	if err := services.CreateRole(name); err != nil {
		if errors.Is(err, services.ErrRoleExists) {
			return c.Status(fiber.StatusConflict).SendString("role already exists")
		}
		log.Error().Err(err).Str("role", name).Msg("admin: failed to create role")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Str("role", name).Str("by", c.Locals("adminCID").(string)).Msg("admin: role created")
	return c.Redirect().To("/admin")
}

func AdminDeleteRole(c fiber.Ctx) error {
	name := c.FormValue("name")
	if !validateRoleName(name) {
		return c.Status(fiber.StatusBadRequest).SendString("role name must be 1–64 lowercase alphanumeric/underscore characters")
	}

	if err := services.DeleteRole(name); err != nil {
		if errors.Is(err, services.ErrRoleNotFound) {
			return c.Status(fiber.StatusNotFound).SendString("role not found")
		}
		if errors.Is(err, services.ErrCannotDeleteAdministrator) {
			return c.Status(fiber.StatusForbidden).SendString("cannot delete the administrator role")
		}
		log.Error().Err(err).Str("role", name).Msg("admin: failed to delete role")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Str("role", name).Str("by", c.Locals("adminCID").(string)).Msg("admin: role deleted")
	return c.Redirect().To("/admin")
}

func AdminAssignRole(c fiber.Ctx) error {
	cid := c.FormValue("cid")
	role := c.FormValue("role")
	if !validateCID(cid) {
		return c.Status(fiber.StatusBadRequest).SendString("cid must be numeric and at most 20 characters")
	}
	if !validateRoleName(role) {
		return c.Status(fiber.StatusBadRequest).SendString("role name must be 1–64 lowercase alphanumeric/underscore characters")
	}

	if err := services.AssignRole(cid, role); err != nil {
		if errors.Is(err, services.ErrRoleNotFound) {
			return c.Status(fiber.StatusNotFound).SendString("role not found")
		}
		log.Error().Err(err).Str("cid", cid).Str("role", role).Msg("admin: failed to assign role")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Str("cid", cid).Str("role", role).Str("by", c.Locals("adminCID").(string)).Msg("admin: role assigned")
	return c.Redirect().To("/admin")
}

func AdminRemoveRole(c fiber.Ctx) error {
	cid := c.FormValue("cid")
	role := c.FormValue("role")
	if !validateCID(cid) {
		return c.Status(fiber.StatusBadRequest).SendString("cid must be numeric and at most 20 characters")
	}
	if !validateRoleName(role) {
		return c.Status(fiber.StatusBadRequest).SendString("role name must be 1–64 lowercase alphanumeric/underscore characters")
	}

	if err := services.RemoveRole(cid, role); err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			return c.Status(fiber.StatusNotFound).SendString("user not found")
		}
		if errors.Is(err, services.ErrRoleNotFound) {
			return c.Status(fiber.StatusNotFound).SendString("role not found")
		}
		log.Error().Err(err).Str("cid", cid).Str("role", role).Msg("admin: failed to remove role")
		return c.Status(fiber.StatusInternalServerError).SendString("internal server error")
	}

	log.Info().Str("cid", cid).Str("role", role).Str("by", c.Locals("adminCID").(string)).Msg("admin: role removed")
	return c.Redirect().To("/admin")
}
