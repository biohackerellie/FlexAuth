# FlexAuth

[![Go Report Card](https://goreportcard.com/badge/github.com/biohackerellie/flexauth)](https://goreportcard.com/report/github.com/biohackerellie/flexauth)

A simple, flexible authentication library for Go that provides easy integration with various authentication providers. Inspired by [Arctic.js](https://github.com/pilcrowOnPaper/arctic), this library focuses purely on authentication flows without imposing session management decisions on your application.

## Features

- 🔐 **Provider-agnostic**: Interface-based design for easy extensibility
- 🚀 **No session management**: You control how tokens and user data are stored
- 🌐 **HTTP handlers included**: Ready-to-use endpoints for web applications
- 🛡️ **Security focused**: State verification, secure token generation, bcrypt hashing
- 🎯 **Go-idiomatic**: Clean interfaces and error handling

## Currently Supported Providers

- **Microsoft Entra ID** (Azure AD) - OAuth 2.0
- **GitHub** - OAuth 2.0

More providers coming soon! Contributions welcome.

## Installation

```bash
go get github.com/biohackerellie/flexauth
```

## Quick Start

### OAuth Provider (Microsoft Entra)

<details>

<summary>Expand</summary>

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/biohackerellie/flexauth"
    "github.com/biohackerellie/flexauth/providers/entra"
)

func main() {
    // Create OAuth handlers
    oauthHandlers := flexauth.NewOAuthHandlers()
    
    // Configure Microsoft Entra provider
    entraConfig := flexauth.Config{
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
        RedirectURL:  "http://localhost:8080/auth/entra/callback",
    }
    
    entraProvider := entra.NewEntraProvider(entraConfig, "your-tenant-id")
    oauthHandlers.RegisterProvider("entra", entraProvider)
    
    // Custom success handler
    oauthHandlers.SetSuccessHandler(func(w http.ResponseWriter, r *http.Request, userInfo *flexauth.UserInfo, tokens *flexauth.TokenResponse) {
        // Handle successful authentication
        // Store tokens, create session, etc.
        log.Printf("User %s logged in successfully", userInfo.Email)
        
        // Redirect to dashboard or return JSON
        http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
    })
    
    // Setup routes
    mux := http.NewServeMux()
    mux.HandleFunc("GET /auth/{provider}", oauthHandlers.AuthHandler)
    mux.HandleFunc("GET /auth/{provider}/callback", oauthHandlers.CallbackHandler)
    
    // Start server
    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

</details>


## API Endpoints

### OAuth Providers
- `GET /auth/{provider}` - Initiate OAuth flow
- `GET /auth/{provider}/callback` - Handle OAuth callback


## Token Refresh

The library provides programmatic token refresh without exposing refresh tokens to HTTP clients:



<details>

<summary>Expand</summary>

```go
// In your middleware or authentication logic
newTokens, err := oauthHandlers.RefreshToken(
    ctx, 
    "entra", 
    storedRefreshToken, // Retrieved securely from your database
)
if err != nil {
    // Handle refresh failure
    redirectToLogin(w, r)
    return
}

// Update stored tokens
updateTokensInDatabase(userID, newTokens.AccessToken, newTokens.RefreshToken)
```

</details>

## Creating a Custom Provider

Want to add support for a new OAuth provider? Here's how:

### 1. Create Provider Package

Create a new directory under `providers/` for your provider (e.g., `providers/github/`):

```
providers/
├── github/
│   ├── github.go
│   └── github_test.go
```

### 2. Implement the Provider Interface

<details>

<summary>Expand</summary>

```go
// providers/github/github.go
package github

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    
    "github.com/biohackerellie/flexauth"
)

type GitHubProvider struct {
    config flexauth.Config
    client *http.Client
}

func NewGitHubProvider(config flexauth.Config) *GitHubProvider {
    return &GitHubProvider{
        config: config,
        client: &http.Client{},
    }
}

func (p *GitHubProvider) GetAuthType() flexauth.AuthType {
    return flexauth.AuthTypeOAuth
}

func (p *GitHubProvider) GetAuthURL(state string, scopes ...string) (string, error) {
    if len(scopes) == 0 {
        scopes = []string{"user:email"}
    }
    
    params := url.Values{
        "client_id":     {p.config.ClientID},
        "redirect_uri":  {p.config.RedirectURL},
        "scope":         {strings.Join(scopes, " ")},
        "state":         {state},
    }
    
    return fmt.Sprintf("https://github.com/login/oauth/authorize?%s", params.Encode()), nil
}

func (p *GitHubProvider) ExchangeCodeForToken(ctx context.Context, code string) (*flexauth.TokenResponse, error) {
    data := url.Values{
        "client_id":     {p.config.ClientID},
        "client_secret": {p.config.ClientSecret},
        "code":          {code},
    }
    
    req, err := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Accept", "application/json")
    
    resp, err := p.client.Do(req)
    if err != nil {
        return nil, err
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

func (p *GitHubProvider) GetUserInfo(ctx context.Context, accessToken string) (*flexauth.UserInfo, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+accessToken)
    req.Header.Set("Accept", "application/vnd.github.v3+json")
    
    resp, err := p.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("user info request failed with status: %d", resp.StatusCode)
    }
    
    var rawUser map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&rawUser); err != nil {
        return nil, err
    }
    
    userInfo := &flexauth.UserInfo{
        Raw: rawUser,
    }
    
    // Map GitHub-specific fields
    if id, ok := rawUser["id"].(float64); ok {
        userInfo.ID = fmt.Sprintf("%.0f", id)
    }
    if email, ok := rawUser["email"].(string); ok {
        userInfo.Email = email
    }
    if name, ok := rawUser["name"].(string); ok {
        userInfo.Name = name
    }
    if login, ok := rawUser["login"].(string); ok {
        userInfo.Username = login
    }
    if avatar, ok := rawUser["avatar_url"].(string); ok {
        userInfo.Avatar = avatar
    }
    
    return userInfo, nil
}

func (p *GitHubProvider) RefreshToken(ctx context.Context, refreshToken string) (*flexauth.TokenResponse, error) {
    // GitHub doesn't support refresh tokens in the same way
    return nil, fmt.Errorf("GitHub does not support refresh tokens")
}
```

</details>

### 3. Usage Example

<details>

<summary>Expand</summary>

```go
package main

import (
    "github.com/biohackerellie/flexauth"
    "github.com/biohackerellie/flexauth/providers/github"
)

func main() {
    handlers := flexauth.NewOAuthHandlers()
    
    // Configure GitHub provider
    githubConfig := flexauth.Config{
        ClientID:     "your-github-client-id",
        ClientSecret: "your-github-client-secret",
        RedirectURL:  "http://localhost:8080/auth/github/callback",
    }
    
    githubProvider := github.NewGitHubProvider(githubConfig)
    handlers.RegisterProvider("github", githubProvider)
    
    // Setup routes and start server...
}
```

### 4. Testing Your Provider

```go
// providers/github/github_test.go
package github

import (
    "testing"
    "github.com/biohackerellie/flexauth"
)

func TestGitHubProvider(t *testing.T) {
    config := flexauth.Config{
        ClientID:     "test-client-id",
        ClientSecret: "test-client-secret",
        RedirectURL:  "http://localhost:8080/callback",
    }
    
    provider := NewGitHubProvider(config)
    
    // Test auth URL generation
    authURL, err := provider.GetAuthURL("test-state", "user:email")
    if err != nil {
        t.Fatalf("Failed to generate auth URL: %v", err)
    }
    
    if !strings.Contains(authURL, "github.com/login/oauth/authorize") {
        t.Errorf("Expected GitHub auth URL, got: %s", authURL)
    }
    
    // Add more tests...
}
```

</details>

## Contributing

We welcome contributions! To add a new provider:

1. Fork the repository
2. Create a new provider package in `providers/your-provider/`
3. Implement the `flexauth.Provider` interface
4. Add tests
5. Update this README with usage examples if necessary(if provider flow is different then existing examples)
6. Submit a pull request

### Guidelines

- Follow Go naming conventions
- Include comprehensive tests
- Handle errors appropriately
- Document any provider-specific configuration
- Keep dependencies minimal

## License

FlexAuth is distributed under the [MIT License](LICENSE).
