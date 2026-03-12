package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	CID      string `gorm:"uniqueIndex;not null"`
	FullName string
	Roles    []Role `gorm:"many2many:user_roles;"`
}

type Role struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Name  string `gorm:"uniqueIndex;not null"`
	Users []User `gorm:"many2many:user_roles;"`
}

type Session struct {
	ID         string    `gorm:"primaryKey"`
	UserID     uint      `gorm:"index;not null"`
	User       User      `gorm:"constraint:OnDelete:CASCADE"`
	IPAddress  string    `gorm:"not null"`
	UAHash     string    `gorm:"not null"`
	LastSeenAt time.Time `gorm:"not null"`
	ExpiresAt  time.Time `gorm:"not null"`
	Revoked    bool      `gorm:"default:false"`
	CreatedAt  time.Time
	Token      string `gorm:"-"`
}

type VatsimUser struct {
	CID      string
	FullName string
}
