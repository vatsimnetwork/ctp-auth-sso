package services

import (
	"errors"
	"fmt"

	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"gorm.io/gorm"
)

var (
	ErrRoleNotFound              = errors.New("role not found")
	ErrRoleExists                = errors.New("role already exists")
	ErrUserNotFound              = errors.New("user not found")
	ErrCannotDeleteAdministrator = errors.New("cannot delete the administrator role")
)

const administratorRole = "administrator"

func IsAdministrator(cid string) bool {
	if config.C.AdminCID != "" && cid == config.C.AdminCID {
		return true
	}

	var user models.User
	err := database.DB.Preload("Roles").Where(&models.User{CID: cid}).First(&user).Error
	if err != nil {
		return false
	}

	for _, r := range user.Roles {
		if r.Name == administratorRole {
			return true
		}
	}
	return false
}

func ListRoles() ([]models.Role, error) {
	var roles []models.Role
	if err := database.DB.Order("name").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	return roles, nil
}

type RoleWithUsers struct {
	models.Role
	Users []models.User
}

func ListRolesWithUsers() ([]RoleWithUsers, error) {
	var roles []models.Role
	if err := database.DB.Order("name").Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}

	result := make([]RoleWithUsers, len(roles))
	for i, role := range roles {
		var users []models.User
		if err := database.DB.
			Joins("JOIN user_roles ON user_roles.user_id = users.id").
			Where("user_roles.role_id = ?", role.ID).
			Find(&users).Error; err != nil {
			return nil, fmt.Errorf("listing users for role %s: %w", role.Name, err)
		}
		result[i] = RoleWithUsers{Role: role, Users: users}
	}
	return result, nil
}

func CreateRole(name string) error {
	var existing models.Role
	err := database.DB.Where("name = ?", name).First(&existing).Error
	if err == nil {
		return ErrRoleExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("checking role: %w", err)
	}

	if err := database.DB.Create(&models.Role{Name: name}).Error; err != nil {
		return fmt.Errorf("creating role: %w", err)
	}
	return nil
}

func DeleteRole(name string) error {
	if name == administratorRole {
		return ErrCannotDeleteAdministrator
	}

	var role models.Role
	err := database.DB.Where("name = ?", name).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("finding role: %w", err)
	}

	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&role).Association("Users").Clear(); err != nil {
			return fmt.Errorf("clearing role associations: %w", err)
		}
		if err := tx.Delete(&role).Error; err != nil {
			return fmt.Errorf("deleting role: %w", err)
		}
		return nil
	})
}

func AssignRole(cid, roleName string) error {
	var user models.User
	err := database.DB.Where(&models.User{CID: cid}).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		user = models.User{CID: cid}
		if err := database.DB.Create(&user).Error; err != nil {
			return fmt.Errorf("creating stub user: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("finding user: %w", err)
	}

	var role models.Role
	err = database.DB.Where("name = ?", roleName).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("finding role: %w", err)
	}

	if err := database.DB.Model(&user).Association("Roles").Append(&role); err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	return nil
}

func RemoveRole(cid, roleName string) error {
	var user models.User
	err := database.DB.Where(&models.User{CID: cid}).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrUserNotFound
	}
	if err != nil {
		return fmt.Errorf("finding user: %w", err)
	}

	var role models.Role
	err = database.DB.Where("name = ?", roleName).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrRoleNotFound
	}
	if err != nil {
		return fmt.Errorf("finding role: %w", err)
	}

	if err := database.DB.Model(&user).Association("Roles").Delete(&role); err != nil {
		return fmt.Errorf("removing role: %w", err)
	}
	return nil
}
