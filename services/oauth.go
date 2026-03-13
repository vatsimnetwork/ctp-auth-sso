package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vatsimnetwork/ctp-auth-sso/config"
	"github.com/vatsimnetwork/ctp-auth-sso/models"
)

var oauthClient = &http.Client{Timeout: 10 * time.Second}

func AuthorizeURL(state string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", config.C.VatsimClientID)
	params.Set("redirect_uri", config.C.VatsimRedirectURI)
	params.Set("scope", "full_name")
	params.Set("state", state)
	params.Set("prompt", "consent")

	return fmt.Sprintf("%s/oauth/authorize?%s", config.C.VatsimBaseURL, params.Encode())
}

func ExchangeCodeAndFetchUser(code string) (*models.VatsimUser, error) {
	endpoint := fmt.Sprintf("%s/oauth/token", config.C.VatsimBaseURL)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", config.C.VatsimClientID)
	form.Set("client_secret", config.C.VatsimClientSecret)
	form.Set("redirect_uri", config.C.VatsimRedirectURI)
	form.Set("code", code)

	resp, err := oauthClient.Post(endpoint, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokens tokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	return getUserInfo(tokens.AccessToken)
}

func getUserInfo(accessToken string) (*models.VatsimUser, error) {
	endpoint := fmt.Sprintf("%s/api/user", config.C.VatsimBaseURL)

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building user info request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := oauthClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user info request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading user info body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info returned %d: %s", resp.StatusCode, string(body))
	}

	var result vatsimUserResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing user info response: %w", err)
	}

	if result.Data == nil {
		return nil, fmt.Errorf("user info response contained no data")
	}

	return &models.VatsimUser{
		CID:      result.Data.CID,
		FullName: result.Data.Personal.NameFull,
	}, nil
}
