package email

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/biohackerellie/flexauth"
	"golang.org/x/crypto/bcrypt"
)

// Add token storage structures
type TokenSession struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// EmailProvider implements password-based authentication
type EmailProvider struct {
	storage     UserStorage
	emailSender EmailSender

	// In-memory cache for 2FA codes and temp tokens
	codeCache  map[string]*TwoFASession
	tokenCache map[string]*TempSession

	accessTokens  map[string]*TokenSession // accessToken -> TokenSession
	refreshTokens map[string]*TokenSession // refreshToken -> TokenSession

	cacheMux sync.RWMutex

	// Configuration
	codeExpiry        time.Duration
	tokenExpiry       time.Duration
	accessTokenExpiry time.Duration
}

// TwoFASession stores 2FA verification data
type TwoFASession struct {
	UserID    string
	Code      string
	Email     string
	ExpiresAt time.Time
}

// TempSession stores temporary authentication data
type TempSession struct {
	UserID    string
	Email     string
	ExpiresAt time.Time
}

// EmailSender interface for sending 2FA codes
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// NewEmailProvider creates a new email/password provider
func NewEmailProvider(storage UserStorage, emailSender EmailSender) *EmailProvider {
	p := &EmailProvider{
		storage:           storage,
		emailSender:       emailSender,
		codeCache:         make(map[string]*TwoFASession),
		tokenCache:        make(map[string]*TempSession),
		accessTokens:      make(map[string]*TokenSession),
		refreshTokens:     make(map[string]*TokenSession),
		codeExpiry:        5 * time.Minute,  // 2FA codes expire in 5 minutes
		tokenExpiry:       10 * time.Minute, // Temp tokens expire in 10 minutes
		accessTokenExpiry: 1 * time.Hour,    // Access tokens expire in 1 hour
	}

	// Start cleanup goroutine
	go p.cleanupExpired()

	return p
}

func (p *EmailProvider) GetAuthType() flexauth.AuthType {
	return flexauth.AuthTypePassword
}

// Implement OAuth Provider interface methods
func (p *EmailProvider) GetAuthURL(state string, scopes ...string) (string, error) {
	return fmt.Sprintf("/login?state=%s", state), nil
}

func (p *EmailProvider) ExchangeCodeForToken(ctx context.Context, code string) (*flexauth.TokenResponse, error) {
	// This will be our 2FA verification essentially - but we need the temp token
	// This method is less useful for password auth, but required by interface
	return p.verify2FAByCode(ctx, code)
}

func (p *EmailProvider) GetUserInfo(ctx context.Context, accessToken string) (*flexauth.UserInfo, error) {
	return p.getUserByAccessToken(ctx, accessToken)
}

func (p *EmailProvider) RefreshToken(ctx context.Context, refreshToken string) (*flexauth.TokenResponse, error) {
	return p.refreshAccessToken(ctx, refreshToken)
}

// Password-specific methods
func (p *EmailProvider) Authenticate(ctx context.Context, email, password string) (*flexauth.AuthResponse, error) {
	// Get user from storage
	user, err := p.storage.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate temporary token
	tempToken := generateSecureToken()

	// Store temp session
	p.cacheMux.Lock()
	p.tokenCache[tempToken] = &TempSession{
		UserID:    user.ID,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(p.tokenExpiry),
	}
	p.cacheMux.Unlock()

	// Generate and send 2FA code
	code := generate2FACode()

	p.cacheMux.Lock()
	p.codeCache[tempToken] = &TwoFASession{
		UserID:    user.ID,
		Code:      code,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(p.codeExpiry),
	}
	p.cacheMux.Unlock()

	// Send 2FA code via email
	if err := p.emailSender.SendCode(ctx, user.Email, code); err != nil {
		return nil, fmt.Errorf("failed to send 2FA code: %w", err)
	}

	return &flexauth.AuthResponse{
		TempToken:   tempToken,
		Requires2FA: true,
	}, nil
}

func (p *EmailProvider) Verify2FA(ctx context.Context, tempToken, code string) (*flexauth.TokenResponse, error) {
	p.cacheMux.Lock()
	session, exists := p.codeCache[tempToken]
	if !exists {
		p.cacheMux.Unlock()
		return nil, fmt.Errorf("invalid or expired temp token")
	}

	// Check expiry
	if time.Now().After(session.ExpiresAt) {
		delete(p.codeCache, tempToken)
		delete(p.tokenCache, tempToken)
		p.cacheMux.Unlock()
		return nil, fmt.Errorf("2FA code expired")
	}

	// Verify code
	if session.Code != code {
		p.cacheMux.Unlock()
		return nil, fmt.Errorf("invalid 2FA code")
	}

	userID := session.UserID

	// Clean up used codes/tokens
	delete(p.codeCache, tempToken)
	delete(p.tokenCache, tempToken)
	p.cacheMux.Unlock()

	// Generate access and refresh tokens
	accessToken := generateSecureToken()
	refreshToken := generateSecureToken()

	// Store token session
	tokenSession := &TokenSession{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(p.accessTokenExpiry),
		CreatedAt:    time.Now(),
	}

	p.cacheMux.Lock()
	p.accessTokens[accessToken] = tokenSession
	p.refreshTokens[refreshToken] = tokenSession
	p.cacheMux.Unlock()

	return &flexauth.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.accessTokenExpiry.Seconds()),
	}, nil
}

func (p *EmailProvider) Send2FACode(ctx context.Context, tempToken string) error {
	p.cacheMux.RLock()
	session, exists := p.codeCache[tempToken]
	p.cacheMux.RUnlock()

	if !exists || time.Now().After(session.ExpiresAt) {
		return fmt.Errorf("invalid or expired temp token")
	}

	return p.emailSender.SendCode(ctx, session.Email, session.Code)
}

func (p *EmailProvider) Register(ctx context.Context, email, password string) (*flexauth.UserInfo, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user, err := p.storage.CreateUser(ctx, email, string(hashedPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user.ToUserInfo(), nil
}

// Helper methods
func generateSecureToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

func generate2FACode() string {
	code, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", code.Int64())
}

func (p *EmailProvider) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		p.cacheMux.Lock()
		// Clean up expired 2FA codes
		for token, session := range p.codeCache {
			if now.After(session.ExpiresAt) {
				delete(p.codeCache, token)
			}
		}

		// Clean up expired temp tokens
		for token, session := range p.tokenCache {
			if now.After(session.ExpiresAt) {
				delete(p.tokenCache, token)
			}
		}

		// Clean up expired access tokens
		for token, session := range p.accessTokens {
			if now.After(session.ExpiresAt) {
				delete(p.accessTokens, token)
				// Remove corresponding refresh token
				delete(p.refreshTokens, session.RefreshToken)
			}
		}
		p.cacheMux.Unlock()
	}
}

// Now implement the required methods properly

func (p *EmailProvider) verify2FAByCode(context.Context, string) (*flexauth.TokenResponse, error) {
	// This is a fallback method - in practice, you'd need both temp token and code
	// For the interface compatibility, we'll return an error suggesting the proper method
	return nil, fmt.Errorf("use Verify2FA method with temp token instead")
}

func (p *EmailProvider) getUserByAccessToken(ctx context.Context, accessToken string) (*flexauth.UserInfo, error) {
	p.cacheMux.RLock()
	session, exists := p.accessTokens[accessToken]
	p.cacheMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid access token")
	}

	// Check if token is expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired token
		p.cacheMux.Lock()
		delete(p.accessTokens, accessToken)
		delete(p.refreshTokens, session.RefreshToken)
		p.cacheMux.Unlock()
		return nil, fmt.Errorf("access token expired")
	}

	// Get user info from storage
	user, err := p.storage.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return user.ToUserInfo(), nil
}

func (p *EmailProvider) refreshAccessToken(_ context.Context, refreshToken string) (*flexauth.TokenResponse, error) {
	p.cacheMux.RLock()
	session, exists := p.refreshTokens[refreshToken]
	p.cacheMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Generate new access token
	newAccessToken := generateSecureToken()
	newRefreshToken := generateSecureToken()

	// Create new token session
	newSession := &TokenSession{
		UserID:       session.UserID,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    time.Now().Add(p.accessTokenExpiry),
		CreatedAt:    time.Now(),
	}

	p.cacheMux.Lock()
	// Remove old tokens
	delete(p.accessTokens, session.AccessToken)
	delete(p.refreshTokens, refreshToken)

	// Store new tokens
	p.accessTokens[newAccessToken] = newSession
	p.refreshTokens[newRefreshToken] = newSession
	p.cacheMux.Unlock()

	return &flexauth.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.accessTokenExpiry.Seconds()),
	}, nil
}
