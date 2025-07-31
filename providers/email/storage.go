package email

import (
	"context"
	"github.com/biohackerellie/flexauth"
)

type UserStorage interface {
	// GetUserByEmail retrieves user by email
	GetUserByEmail(ctx context.Context, email string) (*StoredUser, error)

	// CreateUser creates a new user (for registration)
	CreateUser(ctx context.Context, email, hashedPassword string) (*StoredUser, error)

	// UpdateUserPassword updates user's password
	UpdateUserPassword(ctx context.Context, userID, hashedPassword string) error
}

// StoredUser represents a user as stored in the database
type StoredUser struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Name     string   `json:"name,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// Convert to flexauth.UserInfo
func (u *StoredUser) ToUserInfo() *flexauth.UserInfo {
	return &flexauth.UserInfo{
		ID:    u.ID,
		Email: u.Email,
		Name:  u.Name,
		Raw: map[string]any{
			"stored_user": u,
		},
	}
}
