// Package auth provides session management for the WebUI.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const (
	// SessionLifetime is how long a session remains valid after creation.
	SessionLifetime = 24 * time.Hour

	// CookieName is the HTTP cookie name used to store the session token.
	CookieName = "aiproxy_session"
)

// ValidateResult is the outcome of a session validation check.
type ValidateResult int

const (
	// SessionValid means the token matches the current active session and has not expired.
	SessionValid ValidateResult = iota
	// SessionInvalid means there is no active session, the token does not match an active
	// session, or the session has expired naturally. The user should be redirected to login.
	SessionInvalid
	// SessionKicked means a different non-expired session is currently active — someone else
	// has logged in and displaced this session. This is the intrusion-detection signal.
	SessionKicked
)

// session holds the token and expiry for a single active session.
type session struct {
	Token  string
	Expiry time.Time
}

// SessionStore holds at most one active session in memory.
//
// Only one session may be active at any time. Creating a new session atomically
// replaces any existing session, immediately invalidating the previous token.
// Sessions are not persisted — a proxy restart clears all sessions.
type SessionStore struct {
	mu      sync.RWMutex
	current *session
}

// NewSessionStore creates an empty SessionStore with no active session.
func NewSessionStore() *SessionStore {
	return &SessionStore{}
}

// Create generates a new 32-byte random session token (hex-encoded), stores it
// as the single active session (replacing any previous session), and returns
// the token string. The previous session, if any, is immediately invalidated.
func (s *SessionStore) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.current = &session{Token: token, Expiry: time.Now().Add(SessionLifetime)}
	s.mu.Unlock()

	return token, nil
}

// Validate checks whether the given token corresponds to the current active session.
//
// Returns:
//   - SessionValid    — token matches current session and has not expired.
//   - SessionKicked   — a different non-expired session is active; the caller was displaced
//     by a new login (intrusion-detection signal).
//   - SessionInvalid  — no active session, the session has expired, or the token does not
//     match and there is no active session to displace from.
func (s *SessionStore) Validate(token string) ValidateResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current == nil {
		return SessionInvalid
	}

	now := time.Now()

	if s.current.Token != token {
		// A different session exists. Only signal "kicked" if that session is still active.
		if now.Before(s.current.Expiry) {
			return SessionKicked
		}
		return SessionInvalid
	}

	// Token matches — check expiry.
	if now.After(s.current.Expiry) {
		return SessionInvalid
	}

	return SessionValid
}

// Delete removes the current session if its token matches the provided token.
// This is a no-op if the token does not match the active session (e.g., the
// session was already replaced by a new login).
func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	if s.current != nil && s.current.Token == token {
		s.current = nil
	}
	s.mu.Unlock()
}
