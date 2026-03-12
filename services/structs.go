package services

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

type vatsimPersonal struct {
	NameFull string `json:"name_full"`
}

type vatsimData struct {
	CID      string         `json:"cid"`
	Personal vatsimPersonal `json:"personal"`
}

type vatsimUserResponse struct {
	Data *vatsimData `json:"data"`
}
