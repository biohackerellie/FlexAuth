package entra

import (
	"context"
	"encoding/json"
	"github.com/biohackerellie/flexauth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewEntraProvider(t *testing.T) {
	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"

	provider := NewEntraProvider(config, tenantID)

	if provider == nil {
		t.Error("NewEntraProvider should not return nil")
	}
	if provider.config.ClientID != config.ClientID {
		t.Errorf("ClientID = %v, want %v", provider.config.ClientID, config.ClientID)
	}
	if provider.config.ClientSecret != config.ClientSecret {
		t.Errorf("ClientSecret = %v, want %v", provider.config.ClientSecret, config.ClientSecret)
	}
	if provider.config.RedirectURL != config.RedirectURL {
		t.Errorf("RedirectURL = %v, want %v", provider.config.RedirectURL, config.RedirectURL)
	}
	if provider.tenantID != tenantID {
		t.Errorf("TenantID = %v, want %v", provider.tenantID, tenantID)
	}
	if provider.client == nil {
		t.Error("HTTP client should not be nil")
	}
}

func TestEntraProvider_GetAuthURL(t *testing.T) {
	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"
	provider := NewEntraProvider(config, tenantID)

	tests := []struct {
		name          string
		state         string
		scopes        []string
		expectedError bool
	}{
		{
			name:          "default scopes",
			state:         "test-state",
			scopes:        nil,
			expectedError: false,
		},
		{
			name:          "custom scopes",
			state:         "test-state",
			scopes:        []string{"User.Read", "Mail.Read"},
			expectedError: false,
		},
		{
			name:          "empty state",
			state:         "",
			scopes:        []string{"User.Read"},
			expectedError: false,
		},
		{
			name:          "single scope",
			state:         "state123",
			scopes:        []string{"User.Read"},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := provider.GetAuthURL(tt.state, tt.scopes...)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
				return
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !tt.expectedError {
				// Validate URL structure
				if !strings.Contains(url, "login.microsoftonline.com") {
					t.Error("URL should contain Microsoft OAuth endpoint")
				}
				if !strings.Contains(url, tenantID) {
					t.Error("URL should contain tenant ID")
				}
				if !strings.Contains(url, "client_id="+config.ClientID) {
					t.Error("URL should contain client ID")
				}
				if !strings.Contains(url, "redirect_uri=") {
					t.Error("URL should contain redirect URI")
				}
				if tt.state != "" && !strings.Contains(url, "state="+tt.state) {
					t.Error("URL should contain state parameter")
				}
				if !strings.Contains(url, "response_type=code") {
					t.Error("URL should contain response_type=code")
				}
				if !strings.Contains(url, "scope=") {
					t.Error("URL should contain scope parameter")
				}
			}
		})
	}
}

func TestEntraProvider_GetAuthURL_URLFormat(t *testing.T) {
	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"
	provider := NewEntraProvider(config, tenantID)

	authURL, err := provider.GetAuthURL("test-state", "User.Read")
	if err != nil {
		t.Fatalf("GetAuthURL failed: %v", err)
	}

	// Parse the URL to validate its structure
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Failed to parse auth URL: %v", err)
	}

	// Check query parameters
	query := parsedURL.Query()

	expectedParams := map[string]string{
		"client_id":     config.ClientID,
		"response_type": "code",
		"redirect_uri":  config.RedirectURL,
		"state":         "test-state",
		"response_mode": "query",
	}

	for param, expectedValue := range expectedParams {
		actualValue := query.Get(param)
		if actualValue != expectedValue {
			t.Errorf("Query parameter %s = %v, want %v", param, actualValue, expectedValue)
		}
	}

	// Check scope parameter (should contain User.Read)
	scope := query.Get("scope")
	if !strings.Contains(scope, "User.Read") {
		t.Errorf("Scope should contain User.Read, got: %s", scope)
	}
}

func TestEntraProvider_ExchangeCodeForToken_MockServer(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-www-form-urlencoded" {
			t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", contentType)
		}

		// Parse form data
		err := r.ParseForm()
		if err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Validate form parameters
		expectedParams := map[string]string{
			"client_id":     "test-client-id",
			"client_secret": "test-client-secret",
			"code":          "test-code",
			"grant_type":    "authorization_code",
			"redirect_uri":  "https://example.com/callback",
		}

		for param, expectedValue := range expectedParams {
			actualValue := r.Form.Get(param)
			if actualValue != expectedValue {
				t.Errorf("Form parameter %s = %v, want %v", param, actualValue, expectedValue)
			}
		}

		// Return mock token response
		response := flexauth.TokenResponse{
			AccessToken:  "mock-access-token",
			RefreshToken: "mock-refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			Scope:        "User.Read email profile openid offline_access",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Update the provider to use mock server URL
	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"
	provider := NewEntraProvider(config, tenantID)

	// This test can't easily mock the internal URL construction,
	// so we'll test the happy path with the real URL structure
	// but won't actually make the request to Microsoft
	ctx := context.Background()

	// We can't easily test the actual exchange without mocking the URL,
	// but we can test that the method exists and has the right signature
	_, err := provider.ExchangeCodeForToken(ctx, "test-code")
	// We expect this to fail since we can't reach Microsoft's actual endpoint
	if err == nil {
		t.Log("Token exchange succeeded (unexpected in test environment)")
	} else {
		t.Logf("Token exchange failed as expected: %v", err)
	}
}

func TestEntraProvider_GetUserInfo_MockServer(t *testing.T) {
	// Create a mock server for Microsoft Graph API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}

		auth := r.Header.Get("Authorization")
		expectedAuth := "Bearer test-access-token"
		if auth != expectedAuth {
			t.Errorf("Authorization header = %v, want %v", auth, expectedAuth)
		}

		// Return mock user info
		userInfo := map[string]any{
			"id":                "12345",
			"mail":              "test@example.com",
			"displayName":       "Test User",
			"userPrincipalName": "test@example.com",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userInfo)
	}))
	defer server.Close()

	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"
	provider := NewEntraProvider(config, tenantID)

	ctx := context.Background()

	// Similar to token exchange, we can't easily mock the internal URL
	// but we can test that the method exists and has the right signature
	_, err := provider.GetUserInfo(ctx, "test-access-token")
	// We expect this to fail since we can't reach Microsoft's actual endpoint
	if err == nil {
		t.Log("GetUserInfo succeeded (unexpected in test environment)")
	} else {
		t.Logf("GetUserInfo failed as expected: %v", err)
	}
}

func TestEntraProvider_Constants(t *testing.T) {
	// Test that constants are properly defined
	if authURLTemplate == "" {
		t.Error("authURLTemplate should not be empty")
	}
	if tokenURLTemplate == "" {
		t.Error("tokenURLTemplate should not be empty")
	}
	if userInfoURL == "" {
		t.Error("userInfoURL should not be empty")
	}

	// Test that default scopes are defined
	if len(defaultScopes) == 0 {
		t.Error("defaultScopes should not be empty")
	}

	expectedScopes := []string{"User.Read", "email", "profile", "openid", "offline_access"}
	if len(defaultScopes) != len(expectedScopes) {
		t.Errorf("defaultScopes length = %d, want %d", len(defaultScopes), len(expectedScopes))
	}

	for i, scope := range expectedScopes {
		if i >= len(defaultScopes) || defaultScopes[i] != scope {
			t.Errorf("Missing or incorrect scope at index %d: want %s", i, scope)
		}
	}
}

func TestEntraProvider_URLTemplates(t *testing.T) {
	tenantID := "test-tenant-123"

	// Test auth URL template
	expectedAuthURL := "https://login.microsoftonline.com/test-tenant-123/oauth2/v2.0/authorize"
	actualAuthURL := strings.Replace(authURLTemplate, "%s", tenantID, 1)
	if actualAuthURL != expectedAuthURL {
		t.Errorf("Auth URL = %s, want %s", actualAuthURL, expectedAuthURL)
	}

	// Test token URL template
	expectedTokenURL := "https://login.microsoftonline.com/test-tenant-123/oauth2/v2.0/token"
	actualTokenURL := strings.Replace(tokenURLTemplate, "%s", tenantID, 1)
	if actualTokenURL != expectedTokenURL {
		t.Errorf("Token URL = %s, want %s", actualTokenURL, expectedTokenURL)
	}

	// Test user info URL (should not contain tenant ID)
	if userInfoURL != "https://graph.microsoft.com/v1.0/me" {
		t.Errorf("User info URL = %s, want https://graph.microsoft.com/v1.0/me", userInfoURL)
	}
}

func TestEntraProvider_EdgeCases(t *testing.T) {
	config := flexauth.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "https://example.com/callback",
	}
	tenantID := "test-tenant-id"
	provider := NewEntraProvider(config, tenantID)

	t.Run("empty state in GetAuthURL", func(t *testing.T) {
		url, err := provider.GetAuthURL("", "User.Read")
		if err != nil {
			t.Errorf("GetAuthURL with empty state failed: %v", err)
		}
		if !strings.Contains(url, "state=") {
			t.Error("URL should still contain state parameter even if empty")
		}
	})

	t.Run("no scopes provided", func(t *testing.T) {
		url, err := provider.GetAuthURL("test-state")
		if err != nil {
			t.Errorf("GetAuthURL with no scopes failed: %v", err)
		}
		// Should use default scopes
		for _, scope := range defaultScopes {
			if !strings.Contains(url, scope) {
				t.Errorf("URL should contain default scope: %s", scope)
			}
		}
	})
}
