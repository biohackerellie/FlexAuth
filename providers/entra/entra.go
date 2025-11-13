package entra

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/biohackerellie/flexauth"
	"net/http"
	"net/url"
	"strings"
)

const (
	authURLTemplate  = "https://login.microsoftonline.com/%s/oauth2/v2.0/authorize"
	tokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	userInfoURL      = "https://graph.microsoft.com/v1.0/me"
	providerName     = "entra"
)

var defaultScopes = []string{"User.Read", "email", "profile", "openid", "offline_access"}

type EntraProvider struct {
	config   flexauth.Config
	tenantID string
	client   *http.Client
}

// NewEntraProvider creates a new Microsoft Entra OAuth provider
func NewEntraProvider(config flexauth.Config, tenantID string) *EntraProvider {
	return &EntraProvider{
		config:   config,
		tenantID: tenantID,
		client:   &http.Client{},
	}
}

func (p *EntraProvider) Name() string {
	return providerName
}

func (p *EntraProvider) GetAuthType() flexauth.AuthType {
	return flexauth.AuthTypeOauth
}

func (p *EntraProvider) GetAuthURL(state string, scopes ...string) (string, error) {
	if len(scopes) == 0 {
		scopes = defaultScopes
	}

	authURL := fmt.Sprintf(authURLTemplate, p.tenantID)
	params := url.Values{
		"client_id":     {p.config.ClientID},
		"response_type": {"code"},
		"redirect_uri":  {p.config.RedirectURL},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
		"response_mode": {"query"},
	}

	return fmt.Sprintf("%s?%s", authURL, params.Encode()), nil
}

func (p *EntraProvider) ExchangeCodeForToken(ctx context.Context, code string) (*flexauth.TokenResponse, error) {
	tokenURL := fmt.Sprintf(tokenURLTemplate, p.tenantID)

	data := url.Values{
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.config.RedirectURL},
		"scope":         {strings.Join(defaultScopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	var tokenResp flexauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

func (p *EntraProvider) GetUserInfo(ctx context.Context, accessToken string) (*flexauth.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
	}

	var rawUser map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rawUser); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	userInfo := &flexauth.UserInfo{
		Raw: rawUser,
	}

	// Map Entra-specific fields to standard fields
	if id, ok := rawUser["id"].(string); ok {
		userInfo.ID = id
	}
	if email, ok := rawUser["mail"].(string); ok {
		userInfo.Email = email
	} else if upn, ok := rawUser["userPrincipalName"].(string); ok {
		userInfo.Email = upn
	}
	if name, ok := rawUser["displayName"].(string); ok {
		userInfo.Name = name
	}

	return userInfo, nil
}

func (p *EntraProvider) RefreshToken(ctx context.Context, refreshToken string) (*flexauth.TokenResponse, error) {
	tokenURL := fmt.Sprintf(tokenURLTemplate, p.tenantID)

	data := url.Values{
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"refresh_token": {refreshToken},
		"grant_type":    {"refresh_token"},
		"scope":         {strings.Join(defaultScopes, " ")},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status: %d", resp.StatusCode)
	}

	var tokenResp flexauth.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

func (p *EntraProvider) HasRefreshToken() bool {
	return true
}
