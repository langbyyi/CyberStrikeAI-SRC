package security

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Predefined errors for authentication operations.
var (
	ErrInvalidPassword = errors.New("invalid password")
)

// Session represents an authenticated user session.
type Session struct {
	Token     string
	ExpiresAt time.Time
}

// AuthManager manages password-based authentication and session lifecycle.
type AuthManager struct {
	password        string
	sessionDuration time.Duration

	mu       sync.RWMutex
	sessions map[string]Session
}

// NewAuthManager creates a new AuthManager instance.
func NewAuthManager(password string, sessionDurationHours int) (*AuthManager, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("auth password must be configured")
	}

	if sessionDurationHours <= 0 {
		sessionDurationHours = 12
	}

	return &AuthManager{
		password:        password,
		sessionDuration: time.Duration(sessionDurationHours) * time.Hour,
		sessions:        make(map[string]Session),
	}, nil
}

// Authenticate validates the password and creates a new session.
func (a *AuthManager) Authenticate(password string) (string, time.Time, error) {
	if password != a.password {
		return "", time.Time{}, ErrInvalidPassword
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(a.sessionDuration)

	a.mu.Lock()
	a.sessions[token] = Session{
		Token:     token,
		ExpiresAt: expiresAt,
	}
	a.mu.Unlock()

	return token, expiresAt, nil
}

// ValidateToken checks whether the provided token is still valid.
func (a *AuthManager) ValidateToken(token string) (Session, bool) {
	if strings.TrimSpace(token) == "" {
		return Session{}, false
	}

	a.mu.RLock()
	session, ok := a.sessions[token]
	a.mu.RUnlock()
	if !ok {
		return Session{}, false
	}

	if time.Now().After(session.ExpiresAt) {
		a.mu.Lock()
		delete(a.sessions, token)
		a.mu.Unlock()
		return Session{}, false
	}

	return session, true
}

// CheckPassword verifies whether the provided password matches the current password.
func (a *AuthManager) CheckPassword(password string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return password == a.password
}

// RevokeToken invalidates the specified token.
func (a *AuthManager) RevokeToken(token string) {
	if strings.TrimSpace(token) == "" {
		return
	}

	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

// SessionDurationHours returns the configured session duration in hours.
func (a *AuthManager) SessionDurationHours() int {
	return int(a.sessionDuration / time.Hour)
}

// UpdateConfig updates the password and session duration, revoking existing sessions.
func (a *AuthManager) UpdateConfig(password string, sessionDurationHours int) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return errors.New("auth password must be configured")
	}

	if sessionDurationHours <= 0 {
		sessionDurationHours = 12
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.password = password
	a.sessionDuration = time.Duration(sessionDurationHours) * time.Hour
	a.sessions = make(map[string]Session)
	return nil
}
