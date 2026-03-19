package handlers

import (
	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
)

type pageData struct {
	LoggedIn bool
	UserName string
	CID      string
	IsAdmin  bool
	Services []config.ServiceEntry
	AppEnv   string
	Version  int64
	Roles    []models.Role
}
