package handlers

import "github.com/vatsimnetwork/ctp-auth-sso/config"

type pageData struct {
	LoggedIn bool
	UserName string
	CID      string
	Services []config.ServiceEntry
	AppEnv   string
	Version  int64
}
