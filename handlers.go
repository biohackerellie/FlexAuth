package flexauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type FlexAuthHandlers struct {
	providers   ProviderRegistry
	onSuccess   func(w http.ResponseWriter, r *http.Request, userInfo *UserInfo, tokens *TokenResponse)
	onError     func(w http.ResponseWriter, r *http.Request, err error)
	providersMu sync.RWMutex
	basePath    string

	// For multi-step authentication providers
	onAuthStep func(w http.ResponseWriter, r *http.Request, authResponse *AuthResponse)
}

// NewFlexAuthHandlers creates a new FlexAuthHandlers instance.
func NewFlexAuthHandlers(basePath string) *FlexAuthHandlers {
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}

	return &FlexAuthHandlers{
		providers: make(ProviderRegistry),
		basePath:  basePath,
		onSuccess: defaultSuccessHandler,
		onError:   defaultErrorHandler,
	}
}

// RegisterProvider registers a new OAuth provider
func (h *FlexAuthHandlers) RegisterProvider(name string, provider Provider) {
	h.providersMu.Lock()
	defer h.providersMu.Unlock()
	h.providers[name] = provider
}

// SetSuccessHandler sets a custom success handler
func (h *FlexAuthHandlers) SetSuccessHandler(handler func(w http.ResponseWriter, r *http.Request, userInfo *UserInfo, tokens *TokenResponse)) {
	h.onSuccess = handler
}

// SetErrorHandler sets a custom error handler
func (h *FlexAuthHandlers) SetErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error)) {
	h.onError = handler
}

// AuthHandler handles the {basePath}{provider} endpoint
func (h *FlexAuthHandlers) AuthHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		h.onError(w, r, fmt.Errorf("provider not found"))
		return
	}

	h.providersMu.RLock()
	defer h.providersMu.RUnlock()
	provider, exists := h.providers[providerName]
	if !exists {
		h.onError(w, r, fmt.Errorf("provider not found"))
		return
	}
	h.providersMu.RUnlock()

	state := generateState()

	scopes := r.URL.Query()["scope"]

	authURL, err := provider.GetAuthURL(state, scopes...)
	if err != nil {
		h.onError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("oauth_state_%s", providerName),
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)

}

// CallbackHandler handles the {basePath}{provider}/callback endpoint
// It exchanges the authorization code for an access token and user info
// and then calls the success handler. This is where you can add your own logic like
// storing the tokens and user info in a database or in a jwt.
func (h *FlexAuthHandlers) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		h.onError(w, r, fmt.Errorf("provder not specified"))
		return
	}

	h.providersMu.RLock()
	defer h.providersMu.RUnlock()
	provider, exists := h.providers[providerName]
	if !exists {
		h.onError(w, r, fmt.Errorf("provider not found"))
		return
	}
	h.providersMu.RUnlock()

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		h.onError(w, r, fmt.Errorf("code or state not found"))
		return
	}
	if err := h.verifyState(r, providerName, state); err != nil {
		h.onError(w, r, err)
		return
	}

	tokens, err := provider.ExchangeCodeForToken(r.Context(), code)
	if err != nil {
		h.onError(w, r, err)
		return
	}

	userInfo, err := provider.GetUserInfo(r.Context(), tokens.AccessToken)
	if err != nil {
		h.onError(w, r, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     fmt.Sprintf("oauth_state_%s", providerName),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	h.onSuccess(w, r, userInfo, tokens)
}

// RefreshToken refreshes the access token using the refresh token that is stored by you in a database, cookie, jwt etc
// Some providers do not have a refresh token, so this will simply return an error if none is found.
func (h *FlexAuthHandlers) RefreshToken(ctx context.Context, providerName, refreshToken string) (*TokenResponse, error) {
	h.providersMu.RLock()
	defer h.providersMu.RUnlock()
	provider, exists := h.providers[providerName]
	if !exists {
		return nil, fmt.Errorf("provider not found")
	}
	h.providersMu.RUnlock()

	return provider.RefreshToken(ctx, refreshToken)
}

// SetAuthStepHandler sets a custom auth step handler
func (h *FlexAuthHandlers) SetAuthStepHandler(handler func(w http.ResponseWriter, r *http.Request, authResponse *AuthResponse)) {
	h.onAuthStep = handler
}

// LoginHandler handles Email/Password login - POST {basePath}{provider}/login
func (h *FlexAuthHandlers) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		h.onError(w, r, fmt.Errorf("provider not found"))
		return
	}
	h.providersMu.RLock()
	defer h.providersMu.RUnlock()
	provider, exists := h.providers[providerName]
	if !exists {
		h.onError(w, r, fmt.Errorf("provider not found"))
		return
	}
	h.providersMu.RUnlock()

	passwordProvider, ok := provider.(PasswordProvider)
	if !ok {
		h.onError(w, r, fmt.Errorf("provider does not support password login"))
		return
	}

	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.onError(w, r, err)
		return
	}
	if req.Email == "" || req.Password == "" {
		h.onError(w, r, fmt.Errorf("email or password not found"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authResponse, err := passwordProvider.Authenticate(ctx, req.Email, req.Password)
	if err != nil {
		h.onError(w, r, err)
		return
	}

	if authResponse.Requires2FA {
		if h.onAuthStep != nil {
			h.onAuthStep(w, r, authResponse)
		} else {
			defaultAuthStepHandler(w, r, authResponse)
		}

		return
	}
	h.onSuccess(w, r, authResponse.UserInfo, authResponse.Tokens)
}

// Verify2FAHandler handles 2FA verification - POST {basePath}{provider}/verify
func (h *FlexAuthHandlers) Verify2FAHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		h.onError(w, r, fmt.Errorf("provider not specified"))
		return
	}

	provider, exists := h.providers[providerName]
	if !exists {
		h.onError(w, r, fmt.Errorf("provider '%s' not found", providerName))
		return
	}

	passwordProvider, ok := provider.(PasswordProvider)
	if !ok {
		h.onError(w, r, fmt.Errorf("provider '%s' does not support password authentication", providerName))
		return
	}

	// Parse verification request
	var req Verify2FARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.onError(w, r, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if req.TempToken == "" || req.Code == "" {
		h.onError(w, r, fmt.Errorf("temp_token and code are required"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Verify 2FA
	tokens, err := passwordProvider.Verify2FA(ctx, req.TempToken, req.Code)
	if err != nil {
		h.onError(w, r, fmt.Errorf("2FA verification failed: %w", err))
		return
	}

	// Get user info using the new access token
	userInfo, err := passwordProvider.GetUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		h.onError(w, r, fmt.Errorf("failed to get user info: %w", err))
		return
	}

	// Complete login
	h.onSuccess(w, r, userInfo, tokens)
}

func (h *FlexAuthHandlers) ResendCodeHandler(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		h.onError(w, r, fmt.Errorf("provider not specified"))
		return
	}

	provider, exists := h.providers[providerName]
	if !exists {
		h.onError(w, r, fmt.Errorf("provider '%s' not found", providerName))
		return
	}

	passwordProvider, ok := provider.(PasswordProvider)
	if !ok {
		h.onError(w, r, fmt.Errorf("provider '%s' does not support password authentication", providerName))
		return
	}

	var req ResendCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.onError(w, r, fmt.Errorf("invalid request body: %w", err))
		return
	}

	if req.TempToken == "" {
		h.onError(w, r, fmt.Errorf("temp_token is required"))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := passwordProvider.Send2FACode(ctx, req.TempToken); err != nil {
		h.onError(w, r, fmt.Errorf("failed to resend code: %w", err))
		return
	}

	// Success response
	response := map[string]any{
		"success": true,
		"message": "2FA code resent successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.onError(w, r, err)
		return
	}
}

// Default auth step handler
func defaultAuthStepHandler(w http.ResponseWriter, _ *http.Request, authResponse *AuthResponse) {
	response := map[string]any{
		"success":      true,
		"requires_2fa": authResponse.Requires2FA,
		"temp_token":   authResponse.TempToken,
		"message":      "2FA code sent to your email",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

/*
* Helper functions
 */

func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *FlexAuthHandlers) verifyState(r *http.Request, providerName, receivedState string) error {
	cookie, err := r.Cookie(fmt.Sprintf("oauth_state_%s", providerName))
	if err != nil {
		return fmt.Errorf("state cookie not found")
	}

	if cookie.Value != receivedState {
		return fmt.Errorf("state mismatch")
	}

	return nil
}

func defaultSuccessHandler(w http.ResponseWriter, r *http.Request, userInfo *UserInfo, tokens *TokenResponse) {
	response := map[string]any{
		"success": true,
		"user":    userInfo,
		"tokens":  tokens,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	response := map[string]any{
		"success": false,
		"error":   err.Error(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Verify2FARequest struct {
	TempToken string `json:"temp_token"`
	Code      string `json:"code"`
}

type ResendCodeRequest struct {
	TempToken string `json:"temp_token"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
