package email

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/biohackerellie/flexauth"
	"golang.org/x/crypto/bcrypt"
)

// Mock implementations for testing
type mockUserStorage struct {
	users map[string]*StoredUser
	err   error
}

func (m *mockUserStorage) GetUserByEmail(ctx context.Context, email string) (*StoredUser, error) {
	if m.err != nil {
		return nil, m.err
	}

	user, exists := m.users[email]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (m *mockUserStorage) CreateUser(ctx context.Context, email, hashedPassword string) (*StoredUser, error) {
	if m.err != nil {
		return nil, m.err
	}

	user := &StoredUser{
		ID:       "new-user-id",
		Email:    email,
		Password: hashedPassword,
		Name:     "",
	}

	m.users[email] = user
	return user, nil
}

func (m *mockUserStorage) UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error {
	if m.err != nil {
		return m.err
	}

	// Find user by ID and update password
	for _, user := range m.users {
		if user.ID == userID {
			user.Password = hashedPassword
			return nil
		}
	}

	return errors.New("user not found")
}

type mockEmailSender struct {
	sentCodes map[string]string // email -> code
	err       error
}

func (m *mockEmailSender) SendCode(ctx context.Context, email, code string) error {
	if m.err != nil {
		return m.err
	}

	if m.sentCodes == nil {
		m.sentCodes = make(map[string]string)
	}

	m.sentCodes[email] = code
	return nil
}

func createTestProvider() (*EmailProvider, *mockUserStorage, *mockEmailSender) {
	storage := &mockUserStorage{
		users: make(map[string]*StoredUser),
	}

	emailSender := &mockEmailSender{
		sentCodes: make(map[string]string),
	}

	provider := NewEmailProvider(storage, emailSender)
	return provider, storage, emailSender
}

func TestNewEmailProvider(t *testing.T) {
	provider, _, _ := createTestProvider()

	if provider.GetAuthType() != flexauth.AuthTypePassword {
		t.Errorf("Expected auth type to be %v, got %v", flexauth.AuthTypePassword, provider.GetAuthType())
	}

	if provider.storage == nil {
		t.Error("Expected storage to be set")
	}

	if provider.emailSender == nil {
		t.Error("Expected emailSender to be set")
	}

	if provider.codeCache == nil {
		t.Error("Expected codeCache to be initialized")
	}

	if provider.tokenCache == nil {
		t.Error("Expected tokenCache to be initialized")
	}
}

func TestAuthenticate_Success(t *testing.T) {
	provider, storage, emailSender := createTestProvider()

	// Create test user with hashed password
	password := "testpassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}

	storage.users["test@example.com"] = testUser

	// Test authentication
	ctx := context.Background()
	authResponse, err := provider.Authenticate(ctx, "test@example.com", password)

	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if !authResponse.Requires2FA {
		t.Error("Expected 2FA to be required")
	}

	if authResponse.TempToken == "" {
		t.Error("Expected temp token to be generated")
	}

	// Check if 2FA code was sent
	if code, exists := emailSender.sentCodes["test@example.com"]; !exists || code == "" {
		t.Error("Expected 2FA code to be sent")
	}

	// Check if temp token and 2FA session are cached
	provider.cacheMux.RLock()
	if _, exists := provider.tokenCache[authResponse.TempToken]; !exists {
		t.Error("Expected temp token to be cached")
	}
	if _, exists := provider.codeCache[authResponse.TempToken]; !exists {
		t.Error("Expected 2FA session to be cached")
	}
	provider.cacheMux.RUnlock()
}

func TestAuthenticate_InvalidCredentials(t *testing.T) {
	provider, storage, _ := createTestProvider()

	// Create test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}
	storage.users["test@example.com"] = testUser

	ctx := context.Background()

	// Test with wrong password
	_, err := provider.Authenticate(ctx, "test@example.com", "wrongpassword")
	if err == nil {
		t.Error("Expected authentication to fail with wrong password")
	}

	// Test with non-existent user
	_, err = provider.Authenticate(ctx, "nonexistent@example.com", "password")
	if err == nil {
		t.Error("Expected authentication to fail with non-existent user")
	}
}

func TestVerify2FA_Success(t *testing.T) {
	provider, storage, _ := createTestProvider()

	// Setup test user and authenticate first
	password := "testpassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}
	storage.users["test@example.com"] = testUser

	ctx := context.Background()
	authResponse, err := provider.Authenticate(ctx, "test@example.com", password)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// Get the 2FA code from cache
	provider.cacheMux.RLock()
	session := provider.codeCache[authResponse.TempToken]
	provider.cacheMux.RUnlock()

	if session == nil {
		t.Fatal("Expected 2FA session to exist")
	}

	// Verify 2FA
	tokens, err := provider.Verify2FA(ctx, authResponse.TempToken, session.Code)
	if err != nil {
		t.Fatalf("2FA verification failed: %v", err)
	}

	if tokens.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}

	if tokens.RefreshToken == "" {
		t.Error("Expected refresh token to be generated")
	}

	if tokens.TokenType != "Bearer" {
		t.Errorf("Expected token type to be 'Bearer', got %s", tokens.TokenType)
	}

	// Check that cache entries are cleaned up
	provider.cacheMux.RLock()
	if _, exists := provider.codeCache[authResponse.TempToken]; exists {
		t.Error("Expected 2FA session to be cleaned up after verification")
	}
	if _, exists := provider.tokenCache[authResponse.TempToken]; exists {
		t.Error("Expected temp token to be cleaned up after verification")
	}
	provider.cacheMux.RUnlock()
}

func TestVerify2FA_InvalidCode(t *testing.T) {
	provider, storage, _ := createTestProvider()

	// Setup test user and authenticate first
	password := "testpassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}
	storage.users["test@example.com"] = testUser

	ctx := context.Background()
	authResponse, err := provider.Authenticate(ctx, "test@example.com", password)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// Try to verify with wrong code
	_, err = provider.Verify2FA(ctx, authResponse.TempToken, "wrong-code")
	if err == nil {
		t.Error("Expected 2FA verification to fail with wrong code")
	}

	// Try to verify with invalid temp token
	_, err = provider.Verify2FA(ctx, "invalid-temp-token", "123456")
	if err == nil {
		t.Error("Expected 2FA verification to fail with invalid temp token")
	}
}

func TestVerify2FA_ExpiredCode(t *testing.T) {
	provider, storage, _ := createTestProvider()

	// Set very short expiry for testing
	provider.codeExpiry = 1 * time.Millisecond

	// Setup test user and authenticate first
	password := "testpassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}
	storage.users["test@example.com"] = testUser

	ctx := context.Background()
	authResponse, err := provider.Authenticate(ctx, "test@example.com", password)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// Get the code before it expires
	provider.cacheMux.RLock()
	session := provider.codeCache[authResponse.TempToken]
	provider.cacheMux.RUnlock()

	if session == nil {
		t.Fatal("Expected 2FA session to exist")
	}

	code := session.Code

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to verify expired code
	_, err = provider.Verify2FA(ctx, authResponse.TempToken, code)
	if err == nil {
		t.Error("Expected 2FA verification to fail with expired code")
	}

	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected error message to contain 'expired', got: %v", err)
	}
}

func TestSend2FACode(t *testing.T) {
	provider, storage, emailSender := createTestProvider()

	// Setup test user and authenticate first
	password := "testpassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	testUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: string(hashedPassword),
		Name:     "Test User",
	}
	storage.users["test@example.com"] = testUser

	ctx := context.Background()
	authResponse, err := provider.Authenticate(ctx, "test@example.com", password)
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// Clear sent codes to test resend
	emailSender.sentCodes = make(map[string]string)

	// Resend 2FA code
	err = provider.Send2FACode(ctx, authResponse.TempToken)
	if err != nil {
		t.Fatalf("Failed to resend 2FA code: %v", err)
	}

	// Check if code was sent
	if code, exists := emailSender.sentCodes["test@example.com"]; !exists || code == "" {
		t.Error("Expected 2FA code to be resent")
	}
}

func TestRegister(t *testing.T) {
	provider, storage, _ := createTestProvider()

	ctx := context.Background()
	email := "newuser@example.com"
	password := "newpassword123"

	// Register new user
	userInfo, err := provider.Register(ctx, email, password)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	if userInfo.Email != email {
		t.Errorf("Expected email to be %s, got %s", email, userInfo.Email)
	}

	if userInfo.ID == "" {
		t.Error("Expected user ID to be set")
	}

	// Check if user was stored
	storedUser, exists := storage.users[email]
	if !exists {
		t.Error("Expected user to be stored")
	}

	// Check if password was hashed
	err = bcrypt.CompareHashAndPassword([]byte(storedUser.Password), []byte(password))
	if err != nil {
		t.Error("Expected password to be properly hashed")
	}
}

func TestGetAuthURL(t *testing.T) {
	provider, _, _ := createTestProvider()

	authURL, err := provider.GetAuthURL("test-state")
	if err != nil {
		t.Fatalf("Failed to get auth URL: %v", err)
	}

	expected := "/login?state=test-state"
	if authURL != expected {
		t.Errorf("Expected auth URL to be %s, got %s", expected, authURL)
	}
}

func TestStoredUserToUserInfo(t *testing.T) {
	storedUser := &StoredUser{
		ID:       "test-user-id",
		Email:    "test@example.com",
		Password: "hashed-password",
		Name:     "Test User",
	}

	userInfo := storedUser.ToUserInfo()

	if userInfo.ID != storedUser.ID {
		t.Errorf("Expected ID to be %s, got %s", storedUser.ID, userInfo.ID)
	}

	if userInfo.Email != storedUser.Email {
		t.Errorf("Expected email to be %s, got %s", storedUser.Email, userInfo.Email)
	}

	if userInfo.Name != storedUser.Name {
		t.Errorf("Expected name to be %s, got %s", storedUser.Name, userInfo.Name)
	}

	if userInfo.Raw == nil {
		t.Error("Expected raw data to be set")
	}

	if _, exists := userInfo.Raw["stored_user"]; !exists {
		t.Error("Expected stored_user to be in raw data")
	}
}
