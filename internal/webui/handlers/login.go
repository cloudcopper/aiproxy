package handlers

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

	"github.com/cloudcopper/aiproxy/internal/webui/auth"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
)

// LoginConfig holds dependencies for login, logout, and auth middleware.
type LoginConfig struct {
	// AdminSecret is the password checked on POST /login.
	// Empty string means auth is disabled; all login attempts fail.
	AdminSecret string

	// Sessions is the in-memory session store shared across handlers.
	Sessions *auth.SessionStore

	// Logger is the slog logger for authentication events.
	// If nil, logging is disabled (test-only).
	Logger *slog.Logger

	// MinDelay is the minimum response time enforced on POST /login.
	// Zero (default) uses the production value of 1 second.
	// Set to a shorter duration in tests only.
	MinDelay time.Duration
}

func (c *LoginConfig) minDelay() time.Duration {
	if c.MinDelay > 0 {
		return c.MinDelay
	}
	return time.Second
}

func (c *LoginConfig) authEnabled() bool {
	return c.AdminSecret != ""
}

// AuthMiddleware wraps a handler requiring a valid session cookie.
//
// On a valid session it calls next. On an invalid or missing session it
// redirects to /login. On SessionKicked (a different session is now active),
// it redirects to /login?msg=kicked so the login page can display the
// intrusion-detection notice.
//
// Logger is optional; if nil, no logging occurs (test-only scenario).
func AuthMiddleware(store *auth.SessionStore, next http.Handler) http.Handler {
	return authMiddleware(store, next, slog.Default())
}

// authMiddleware is the internal implementation allowing logger injection for testing.
func authMiddleware(store *auth.SessionStore, next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(auth.CookieName)
		if err != nil {
			// No cookie present — user hasn't logged in yet (normal, don't log)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		switch store.Validate(cookie.Value) {
		case auth.SessionValid:
			next.ServeHTTP(w, r)
		case auth.SessionKicked:
			// Log kicked session attempt (WARN level — potential intrusion/hijacking)
			if logger != nil {
				logger.Warn("Session displaced by new login",
					slog.String("event", "session_kicked"),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("user_agent", r.UserAgent()),
					slog.String("path", r.URL.Path),
				)
			}
			http.Redirect(w, r, "/login?msg=kicked", http.StatusFound)
		default: // SessionInvalid
			// Cookie present but invalid — session expired, was kicked then deleted,
			// or attacker using old/stolen cookie. Log for security monitoring.
			if logger != nil {
				logger.Warn("Invalid session attempt",
					slog.String("event", "session_invalid"),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("user_agent", r.UserAgent()),
					slog.String("path", r.URL.Path),
				)
			}
			http.Redirect(w, r, "/login?msg=expired", http.StatusFound)
		}
	})
}

// --- Login page (GET /login) ---

type loginPageHandler struct{ cfg *LoginConfig }

// NewLoginPageHandler returns an http.Handler for GET /login.
func NewLoginPageHandler(cfg *LoginConfig) http.Handler { return &loginPageHandler{cfg: cfg} }

func (h *loginPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := templates.LoginData{
		Nav:         templates.NavData{IsAuthenticated: false, AuthEnabled: h.cfg.authEnabled()},
		AuthEnabled: h.cfg.authEnabled(),
	}
	switch r.URL.Query().Get("msg") {
	case "kicked":
		data.ErrorMsg = "Session expired or logged out from another location."
		data.ErrorKind = "warning"
	case "expired":
		data.ErrorMsg = "Your session has expired. Please log in again."
		data.ErrorKind = "warning"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.LoginPage(data).Render(r.Context(), w); err != nil {
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

// --- Login submit (POST /login) ---

type loginSubmitHandler struct{ cfg *LoginConfig }

// NewLoginSubmitHandler returns an http.Handler for POST /login.
func NewLoginSubmitHandler(cfg *LoginConfig) http.Handler { return &loginSubmitHandler{cfg: cfg} }

// For security reasons the handler MUST enforce
// a minimum response time for ALL outcomes — success and failure alike.
func (h *loginSubmitHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	submitted := r.FormValue("password")

	// Determine the outcome without writing any response yet.
	var errMsg string
	var statusCode int
	var sessionToken string
	var logReason string

	switch {
	case !h.cfg.authEnabled():
		errMsg = "Authentication disabled — no admin secret configured."
		statusCode = http.StatusForbidden
		logReason = "auth_disabled"
	case subtle.ConstantTimeCompare([]byte(submitted), []byte(h.cfg.AdminSecret)) != 1:
		// Constant-time comparison. Length-mismatch leakage is mitigated by
		// the hard minDelay floor applied unconditionally below.
		errMsg = "Invalid password."
		statusCode = http.StatusUnauthorized
		logReason = "invalid_password"
	default:
		var err error
		sessionToken, err = h.cfg.Sessions.Create()
		if err != nil {
			time.Sleep(h.cfg.minDelay())
			if h.cfg.Logger != nil {
				h.cfg.Logger.Error("Failed to create session",
					slog.String("event", "login_error"),
					slog.String("remote_addr", r.RemoteAddr),
					slog.String("user_agent", r.UserAgent()),
					slog.String("error", err.Error()),
				)
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// Enforce minimum delay for EVERY outcome — success and failure alike —
	// BEFORE writing any response to the wire. This makes the response timing
	// unconditional and eliminates timing oracle attacks.
	time.Sleep(h.cfg.minDelay())

	if errMsg != "" {
		// Log failed login attempt (WARN level — security-relevant)
		if h.cfg.Logger != nil {
			h.cfg.Logger.Warn("Failed login attempt",
				slog.String("event", "login_failed"),
				slog.String("remote_addr", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
				slog.String("reason", logReason),
			)
		}
		h.renderLoginError(w, r, errMsg, statusCode)
		return
	}

	// Log successful login (INFO level — normal operational event)
	if h.cfg.Logger != nil {
		h.cfg.Logger.Info("Admin login successful",
			slog.String("event", "login_success"),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
		)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   int(auth.SessionLifetime.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *loginSubmitHandler) renderLoginError(w http.ResponseWriter, r *http.Request, msg string, code int) {
	data := templates.LoginData{
		Nav:         templates.NavData{IsAuthenticated: false, AuthEnabled: h.cfg.authEnabled()},
		AuthEnabled: h.cfg.authEnabled(),
		ErrorMsg:    msg,
		ErrorKind:   "error",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	templates.LoginPage(data).Render(r.Context(), w) //nolint:errcheck
}

// --- Logout (GET /logout) ---

type logoutHandler struct{ cfg *LoginConfig }

// NewLogoutHandler returns an http.Handler for GET /logout.
// Must be wrapped with AuthMiddleware.
func NewLogoutHandler(cfg *LoginConfig) http.Handler { return &logoutHandler{cfg: cfg} }

func (h *logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.CookieName); err == nil {
		h.cfg.Sessions.Delete(cookie.Value)
	}

	// Log logout event (INFO level — normal operational event)
	if h.cfg.Logger != nil {
		h.cfg.Logger.Info("Admin logout",
			slog.String("event", "logout"),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("user_agent", r.UserAgent()),
		)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
