package services

import (
	"errors"
	"fmt"

	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"gorm.io/gorm"
)

var ErrRequestNotFound = errors.New("request not found")

type PendingRequestGroup struct {
	User     models.User
	Reason   string
	Requests []models.RoleRequest
}

func CreateRoleRequests(userID uint, roles []string, reason string) error {
	for _, roleName := range roles {
		var existing models.RoleRequest
		err := database.DB.Where("user_id = ? AND role_name = ? AND status = 'pending'", userID, roleName).First(&existing).Error
		if err == nil {
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("checking existing request: %w", err)
		}
		req := models.RoleRequest{
			UserID:   userID,
			RoleName: roleName,
			Reason:   reason,
			Status:   "pending",
		}
		if err := database.DB.Create(&req).Error; err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
	}
	return nil
}

func ListPendingRequestGroups() ([]PendingRequestGroup, error) {
	var requests []models.RoleRequest
	if err := database.DB.Where("status = 'pending'").Preload("User").Order("created_at asc").Find(&requests).Error; err != nil {
		return nil, fmt.Errorf("listing requests: %w", err)
	}

	groupMap := make(map[uint]*PendingRequestGroup)
	order := []uint{}
	for _, req := range requests {
		if _, ok := groupMap[req.UserID]; !ok {
			groupMap[req.UserID] = &PendingRequestGroup{
				User:   req.User,
				Reason: req.Reason,
			}
			order = append(order, req.UserID)
		}
		groupMap[req.UserID].Requests = append(groupMap[req.UserID].Requests, req)
	}

	result := make([]PendingRequestGroup, 0, len(order))
	for _, uid := range order {
		result = append(result, *groupMap[uid])
	}
	return result, nil
}

func ApproveRoleRequest(id uint) error {
	var req models.RoleRequest
	err := database.DB.Preload("User").Where("id = ? AND status = 'pending'", id).First(&req).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrRequestNotFound
	}
	if err != nil {
		return fmt.Errorf("finding request: %w", err)
	}

	if err := AssignRole(req.User.CID, req.RoleName); err != nil && !errors.Is(err, ErrRoleNotFound) {
		return fmt.Errorf("assigning role: %w", err)
	}

	req.Status = "approved"
	if err := database.DB.Save(&req).Error; err != nil {
		return fmt.Errorf("updating request status: %w", err)
	}
	return nil
}

func DenyUserRequests(userID uint) error {
	if err := database.DB.Model(&models.RoleRequest{}).
		Where("user_id = ? AND status = 'pending'", userID).
		Update("status", "denied").Error; err != nil {
		return fmt.Errorf("denying requests: %w", err)
	}
	return nil
}

func DenySingleRequest(id uint) error {
	result := database.DB.Model(&models.RoleRequest{}).
		Where("id = ? AND status = 'pending'", id).
		Update("status", "denied")
	if result.Error != nil {
		return fmt.Errorf("denying request: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrRequestNotFound
	}
	return nil
}
