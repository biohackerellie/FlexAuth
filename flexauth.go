package flexauth

import (
	"context"
)

type AuthType string

const (
	AuthTypeOauth AuthType = "oauth"
	AuthTypeEmail AuthType = "email"
)

// Provider defines the interface that all OAuth providers must implement
type Provider interface {

	// GetAuthURL generates the authorization URL for the OAuth flow
	GetAuthURL(state string, scopes ...string) (string, error)

	// ExchangeCodeForToken exchanges the authorization code for tokens
	ExchangeCodeForToken(ctx context.Context, code string) (*TokenResponse, error)

	// GetUserInfo retrieves user information using the access token
	GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)

	// RefreshToken refreshes the access token using the refresh token
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)

	// Checks if Provider has a refresh token
	HasRefreshToken() bool

	// Get Provider Name
	Name() string
}

// TokenResponse represents the response from token exchange
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// UserInfo represents basic user information
type UserInfo struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	Avatar   string `json:"avatar,omitempty"`
	// Provider-specific data can be stored here
	Raw map[string]any `json:"raw,omitempty"`
}

// Config holds common OAuth configuration
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type ProviderRegistry map[string]Provider

// AuthResponse for the initial authentication step with 2FA
type AuthResponse struct {
	TempToken   string         `json:"temp_token"`          // Short-lived token for 2FA flow
	Requires2FA bool           `json:"requires_2fa"`        // Whether 2FA is required
	UserInfo    *UserInfo      `json:"user_info,omitempty"` // If no 2FA required
	Tokens      *TokenResponse `json:"tokens,omitempty"`    // If no 2FA required
}
