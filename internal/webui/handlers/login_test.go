package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/webui/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestLoginConfig returns a LoginConfig with a fast MinDelay so tests don't block.
func newTestLoginConfig(secret string) *LoginConfig {
	return &LoginConfig{
		AdminSecret: secret,
		Sessions:    auth.NewSessionStore(),
		MinDelay:    time.Millisecond,
	}
}

// postForm builds a POST request with url-encoded form body.
func postForm(t *testing.T, target string, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// --- AuthMiddleware ---

func TestAuthMiddleware(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		makeReq         func(store *auth.SessionStore) *http.Request
		wantStatus      int
		wantLocContains string
		wantNextCalled  bool
	}{
		{
			name: "no cookie redirects to login",
			makeReq: func(_ *auth.SessionStore) *http.Request {
				return httptest.NewRequest(http.MethodGet, "/pending", nil)
			},
			wantStatus:      http.StatusFound,
			wantLocContains: "/login",
		},
		{
			name: "invalid token redirects to login",
			makeReq: func(_ *auth.SessionStore) *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/pending", nil)
				req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: "bad-token"})
				return req
			},
			wantStatus:      http.StatusFound,
			wantLocContains: "/login",
		},
		{
			name: "valid token calls next handler",
			makeReq: func(store *auth.SessionStore) *http.Request {
				tok, _ := store.Create()
				req := httptest.NewRequest(http.MethodGet, "/pending", nil)
				req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
				return req
			},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			store := auth.NewSessionStore()
			called := false
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			h := AuthMiddleware(store, inner)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tt.makeReq(store))

			is.Equal(tt.wantStatus, rec.Code)
			if tt.wantLocContains != "" {
				is.Contains(rec.Header().Get("Location"), tt.wantLocContains)
			}
			is.Equal(tt.wantNextCalled, called)
		})
	}
}

// --- GET /login page ---

func TestLoginPageHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		secret          string
		target          string
		wantStatus      int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:         "auth enabled shows password form",
			secret:       "secret",
			target:       "/login",
			wantStatus:   http.StatusOK,
			wantContains: []string{`type="password"`, `name="password"`},
		},
		{
			name:            "auth disabled shows notice without form",
			secret:          "",
			target:          "/login",
			wantStatus:      http.StatusOK,
			wantContains:    []string{"disabled"},
			wantNotContains: []string{`type="password"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			h := NewLoginPageHandler(newTestLoginConfig(tt.secret))
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			is.Equal(tt.wantStatus, rec.Code)
			body := rec.Body.String()
			for _, s := range tt.wantContains {
				is.Contains(body, s)
			}
			for _, s := range tt.wantNotContains {
				is.NotContains(body, s)
			}
		})
	}
}

// --- POST /login submit ---

func TestLoginSubmitHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		secret           string
		password         string
		wantStatus       int
		wantLocation     string
		wantBodyContains string
		wantCookie       bool
	}{
		{
			name:         "correct password redirects to /",
			secret:       "hunter2",
			password:     "hunter2",
			wantStatus:   http.StatusSeeOther,
			wantLocation: "/",
			wantCookie:   true,
		},
		{
			name:             "wrong password returns 401 with error message",
			secret:           "hunter2",
			password:         "wrong",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "Invalid password",
		},
		{
			name:             "auth disabled returns 403 with disabled message",
			secret:           "",
			password:         "anything",
			wantStatus:       http.StatusForbidden,
			wantBodyContains: "disabled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			cfg := newTestLoginConfig(tt.secret)
			h := NewLoginSubmitHandler(cfg)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, postForm(t, "/login", url.Values{"password": {tt.password}}))

			is.Equal(tt.wantStatus, rec.Code)
			if tt.wantLocation != "" {
				is.Equal(tt.wantLocation, rec.Header().Get("Location"))
			}
			if tt.wantBodyContains != "" {
				is.Contains(rec.Body.String(), tt.wantBodyContains)
			}
			if tt.wantCookie {
				var sessionCookie *http.Cookie
				for _, c := range rec.Result().Cookies() {
					if c.Name == auth.CookieName {
						sessionCookie = c
					}
				}
				must.NotNil(sessionCookie, "session cookie must be set on successful login")
				is.True(cfg.Sessions.Validate(sessionCookie.Value) == auth.SessionValid, "cookie must hold a valid session token")
			}
		})
	}
}

func TestLoginSubmitHandler_MinDelayEnforced(t *testing.T) {
	t.Parallel()

	cfg := newTestLoginConfig("secret")
	cfg.MinDelay = 50 * time.Millisecond
	h := NewLoginSubmitHandler(cfg)

	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, postForm(t, "/login", url.Values{"password": {"secret"}}))
	elapsed := time.Since(start)

	assert.GreaterOrEqual(t, elapsed, 50*time.Millisecond, "handler must respect MinDelay")
}

// --- GET /logout ---

func TestLogoutHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		setupCookie func(cfg *LoginConfig) string // returns cookie value; "" means no cookie
	}{
		{
			name: "with session cookie: invalidates session and clears cookie",
			setupCookie: func(cfg *LoginConfig) string {
				tok, _ := cfg.Sessions.Create()
				return tok
			},
		},
		{
			name:        "without cookie: still redirects without panic",
			setupCookie: func(_ *LoginConfig) string { return "" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			cfg := newTestLoginConfig("secret")
			token := tt.setupCookie(cfg)
			h := NewLogoutHandler(cfg)

			req := httptest.NewRequest(http.MethodGet, "/logout", nil)
			if token != "" {
				req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
			}
			rec := httptest.NewRecorder()

			is.NotPanics(func() { h.ServeHTTP(rec, req) })
			is.Equal(http.StatusSeeOther, rec.Code)
			is.Equal("/", rec.Header().Get("Location"))

			if token != "" {
				is.False(cfg.Sessions.Validate(token) == auth.SessionValid, "session must be invalidated on logout")

				var sessionCookie *http.Cookie
				for _, c := range rec.Result().Cookies() {
					if c.Name == auth.CookieName {
						sessionCookie = c
					}
				}
				if is.NotNil(sessionCookie, "cleared cookie must be present in response") {
					is.Equal(-1, sessionCookie.MaxAge, "MaxAge must be -1 to clear cookie")
				}
			}
		})
	}
}
