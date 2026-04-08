package services

import (
	"errors"
	"time"

	"github.com/vatsimnetwork/ctp-auth-sso/database"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const suspensionDuration = 5 * time.Minute

func SuspendRoles(cid string) error {
	suspension := models.RoleSuspension{
		UserCID:        cid,
		SuspendedUntil: time.Now().Add(suspensionDuration),
	}
	return database.DB.
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_cid"}},
			DoUpdates: clause.AssignmentColumns([]string{"suspended_until"}),
		}).
		Create(&suspension).Error
}

func UnsuspendRoles(cid string) error {
	return database.DB.Where("user_cid = ?", cid).Delete(&models.RoleSuspension{}).Error
}

func GetSuspension(cid string) (*time.Time, error) {
	var s models.RoleSuspension
	err := database.DB.Where("user_cid = ?", cid).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(s.SuspendedUntil) {
		database.DB.Delete(&s)
		return nil, nil
	}
	return &s.SuspendedUntil, nil
}
