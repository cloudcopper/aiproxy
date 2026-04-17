package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Create ---

func TestSessionStore_Create_ReturnsHexToken(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	s := NewSessionStore()
	token, err := s.Create()

	must.NoError(err)
	is.Len(token, 64, "token must be 64 hex chars (32 bytes)")
	is.Regexp(`^[0-9a-f]+$`, token, "token must be lowercase hex")
}

func TestSessionStore_Create_TokensAreUnique(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	s := NewSessionStore()
	token1, err := s.Create()
	must.NoError(err)

	token2, err := s.Create()
	must.NoError(err)

	is.NotEqual(token1, token2, "each Create must return a unique token")
}

func TestSessionStore_Create_ReplacesExistingSession(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token1, err := s.Create()
	must.NoError(err)

	token2, err := s.Create()
	must.NoError(err)

	is.Equal(SessionValid, s.Validate(token2), "new token must be valid")
	// old token is kicked — a different non-expired session is now active
	is.Equal(SessionKicked, s.Validate(token1), "old token must be kicked by new login")
}

// --- Validate ---

func TestSessionStore_Validate_Valid(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token, err := s.Create()
	must.NoError(err)

	is.Equal(SessionValid, s.Validate(token))
}

func TestSessionStore_Validate_NoCurrent(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	s := NewSessionStore()
	is.Equal(SessionInvalid, s.Validate("doesnotexist"))
	is.Equal(SessionInvalid, s.Validate(""))
}

func TestSessionStore_Validate_Expired(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token, err := s.Create()
	must.NoError(err)

	// Backdate the expiry to simulate natural expiration.
	s.mu.Lock()
	s.current.Expiry = time.Now().Add(-time.Second)
	s.mu.Unlock()

	is.Equal(SessionInvalid, s.Validate(token), "own expired session must be SessionInvalid")
}

func TestSessionStore_Validate_Kicked(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token1, err := s.Create()
	must.NoError(err)

	// Second login while first session is still active.
	_, err = s.Create()
	must.NoError(err)

	is.Equal(SessionKicked, s.Validate(token1),
		"old token must return SessionKicked when a different non-expired session is active")
}

func TestSessionStore_Validate_KickedButNewSessionAlsoExpired(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token1, err := s.Create()
	must.NoError(err)

	// Second login replaces first.
	_, err = s.Create()
	must.NoError(err)

	// Now expire the new (current) session too.
	s.mu.Lock()
	s.current.Expiry = time.Now().Add(-time.Second)
	s.mu.Unlock()

	// The current session is expired, so there is no active session to "kick" from.
	is.Equal(SessionInvalid, s.Validate(token1),
		"old token must return SessionInvalid when current session is also expired")
}

// --- Delete ---

func TestSessionStore_Delete_ClearsSession(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token, err := s.Create()
	must.NoError(err)

	s.Delete(token)

	is.Equal(SessionInvalid, s.Validate(token), "token must be SessionInvalid after Delete")
}

func TestSessionStore_Delete_WrongToken_NoOp(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	is := assert.New(t)

	s := NewSessionStore()
	token, err := s.Create()
	must.NoError(err)

	// Delete with a different token must not clear the active session.
	is.NotPanics(func() { s.Delete("wrong-token") })
	is.Equal(SessionValid, s.Validate(token), "active session must be unaffected by deleting wrong token")
}

// --- Concurrent access ---

func TestSessionStore_Concurrent(t *testing.T) {
	t.Parallel()

	s := NewSessionStore()
	done := make(chan struct{})
	for range 20 {
		go func() {
			defer func() { done <- struct{}{} }()
			token, err := s.Create()
			if err != nil {
				return
			}
			s.Validate(token)
			s.Delete(token)
		}()
	}
	for range 20 {
		<-done
	}
}
