# FlexAuth

A simple, flexible authentication library for Go that provides easy integration with various authentication providers. Inspired by [Arctic.js](https://github.com/pilcrowOnPaper/arctic), this library focuses purely on authentication flows without imposing session management decisions on your application.

## Features

- 🔐 **Provider-agnostic**: Interface-based design for easy extensibility
- 🚀 **No session management**: You control how tokens and user data are stored
- 🌐 **HTTP handlers included**: Ready-to-use endpoints for web applications
- 🔒 **Multiple auth types**: OAuth and password-based authentication
- 🛡️ **Security focused**: State verification, secure token generation, bcrypt hashing
- 📧 **2FA support**: Built-in email-based two-factor authentication
- 🎯 **Go-idiomatic**: Clean interfaces and error handling

## Currently Supported Providers

- **Microsoft Entra ID** (Azure AD) - OAuth 2.0
- **Email/Password** - Traditional authentication with 2FA support

More providers coming soon! Contributions welcome.

## Installation

```bash
go get github.com/biohackerellie/flexauth
```

## Quick Start

### OAuth Provider (Microsoft Entra)

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

### Email/Password Provider with 2FA

```go
package main

import (
    "context"
    "log"
    "net/http"
    
    "github.com/biohackerellie/flexauth"
    "github.com/biohackerellie/flexauth/providers/email"
)

// Implement user storage interface
type DatabaseUserStorage struct {
    // Your database connection
}

func (db *DatabaseUserStorage) GetUserByEmail(ctx context.Context, email string) (*email.StoredUser, error) {
    // Query your database
    return &email.StoredUser{
        ID:       "user123",
        Email:    email,
        Password: "$2a$10$...", // bcrypt hash
        Name:     "John Doe",
    }, nil
}

func (db *DatabaseUserStorage) CreateUser(ctx context.Context, email, hashedPassword string) (*email.StoredUser, error) {
    // Create user in database
    return &email.StoredUser{
        ID:       "newuser123",
        Email:    email,
        Password: hashedPassword,
    }, nil
}

func (db *DatabaseUserStorage) UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error {
    // Update password in database
    return nil
}

// Implement email sender interface
type EmailSender struct {
    // Your email service configuration
}

func (e *EmailSender) SendCode(ctx context.Context, email, code string) error {
    // Send 2FA code via email
    log.Printf("Sending 2FA code %s to %s", code, email)
    return nil
}

func main() {
    oauthHandlers := flexauth.NewOAuthHandlers()
    
    // Setup email/password provider
    userStorage := &DatabaseUserStorage{}
    emailSender := &EmailSender{}
    emailProvider := email.NewEmailProvider(userStorage, emailSender)
    oauthHandlers.RegisterProvider("email", emailProvider)
    
    // Setup routes
    mux := http.NewServeMux()
    
    // Email/Password routes
    mux.HandleFunc("POST /auth/{provider}/login", oauthHandlers.LoginHandler)
    mux.HandleFunc("POST /auth/{provider}/verify", oauthHandlers.Verify2FAHandler)
    mux.HandleFunc("POST /auth/{provider}/resend", oauthHandlers.ResendCodeHandler)
    mux.HandleFunc("POST /auth/{provider}/register", oauthHandlers.RegisterHandler)
    
    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## API Endpoints

### OAuth Providers
- `GET /auth/{provider}` - Initiate OAuth flow
- `GET /auth/{provider}/callback` - Handle OAuth callback

### Email/Password Provider
- `POST /auth/{provider}/login` - Login with email/password
- `POST /auth/{provider}/verify` - Verify 2FA code
- `POST /auth/{provider}/resend` - Resend 2FA code
- `POST /auth/{provider}/register` - Register new user

## Token Refresh

The library provides programmatic token refresh without exposing refresh tokens to HTTP clients:

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

### 3. Usage Example

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
