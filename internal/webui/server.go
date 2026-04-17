package webui

import (
	"context"
	"crypto/x509"
	"embed"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cloudcopper/aiproxy/internal/pending"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/cloudcopper/aiproxy/internal/webui/auth"
	"github.com/cloudcopper/aiproxy/internal/webui/handlers"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
)

//go:embed static
var staticFiles embed.FS

// ServerConfig holds all configuration for the WebUI server.
type ServerConfig struct {
	Listen          string
	StartTime       time.Time
	GlobalRateLimit int
	Cert            *x509.Certificate
	Metrics         handlers.ProxyMetrics
	AdminSecret     string
	Pending         handlers.PendingSource // nil → nullPendingSource (empty list)
	Rules           handlers.RulesSource   // nil → nullRulesSource (empty stores)

	// LoginMinDelay overrides the minimum response time enforced on POST /login.
	// Zero (default) uses the production value of 1 second.
	// This field exists primarily for testing; do not set in production.
	LoginMinDelay time.Duration
}

// Server is the WebUI HTTP server.
type Server struct {
	cfg           *ServerConfig
	listenerReady chan struct{}
	listener      net.Listener
}

// NewServer creates a new WebUI Server with the given config.
func NewServer(cfg *ServerConfig) *Server {
	return &Server{
		cfg:           cfg,
		listenerReady: make(chan struct{}),
	}
}

// Start binds the listener, registers routes, and serves HTTP until ctx is cancelled.
// It returns nil on clean shutdown (context cancellation).
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	actualAddr := listener.Addr().String()
	slog.Info("starting webui server", "addr", actualAddr)
	s.listener = listener
	// Signal that listener is ready. Close happens-after assignment,
	// guaranteeing visibility to Addr() via channel receive.
	close(s.listenerReady)

	sessions := auth.NewSessionStore()
	authEnabled := s.cfg.AdminSecret != ""
	protectedNav := templates.NavData{IsAuthenticated: true, AuthEnabled: authEnabled}

	// Pending source: use a no-op stub if none supplied.
	pendingSrc := s.cfg.Pending
	if pendingSrc == nil {
		pendingSrc = nullPendingSource{}
	}

	// Rules source: use a no-op stub if none supplied.
	rulesSrc := s.cfg.Rules
	if rulesSrc == nil {
		rulesSrc = nullRulesSource{}
	}

	dashCfg := &handlers.DashboardConfig{
		StartTime:       s.cfg.StartTime,
		GlobalRateLimit: s.cfg.GlobalRateLimit,
		Cert:            s.cfg.Cert,
		Metrics:         s.cfg.Metrics,
		AuthEnabled:     authEnabled,
		Sessions:        sessions,
	}
	loginCfg := &handlers.LoginConfig{
		AdminSecret: s.cfg.AdminSecret,
		Sessions:    sessions,
		Logger:      slog.Default(),
		MinDelay:    s.cfg.LoginMinDelay,
	}
	pendingCfg := &handlers.PendingConfig{
		Source: pendingSrc,
		Nav:    protectedNav,
	}

	rulesCfg := &handlers.RulesConfig{
		Source:  rulesSrc,
		Pending: pendingSrc,
		Nav:     protectedNav,
	}

	mux := http.NewServeMux()

	// Public routes — no authentication required.
	mux.Handle("GET /", handlers.NewDashboardHandler(dashCfg))
	mux.Handle("GET /api/dashboard/stream", handlers.NewSSEHandler(dashCfg))
	mux.Handle("GET /download-cert", handlers.NewCertDownloadHandler(s.cfg.Cert))
	mux.Handle("GET /static/", http.FileServerFS(staticFiles))
	mux.Handle("GET /login", handlers.NewLoginPageHandler(loginCfg))
	mux.Handle("POST /login", handlers.NewLoginSubmitHandler(loginCfg))

	// Protected routes — require valid session cookie.
	protect := func(h http.Handler) http.Handler { return handlers.AuthMiddleware(sessions, h) }
	mux.Handle("GET /logout", protect(handlers.NewLogoutHandler(loginCfg)))
	mux.Handle("GET /pending", protect(handlers.NewPendingPageHandler(pendingCfg)))
	mux.Handle("GET /api/pending/stream", protect(handlers.NewPendingSSEHandler(pendingCfg)))
	mux.Handle("GET /rules", protect(handlers.NewRulesPageHandler(rulesCfg)))
	mux.Handle("POST /api/rules/whitelist", protect(handlers.NewRulesAddHandler(rulesCfg, "whitelist")))
	mux.Handle("DELETE /api/rules/whitelist/{id}", protect(handlers.NewRulesDeleteHandler(rulesCfg, "whitelist")))
	mux.Handle("PUT /api/rules/whitelist/{id}", protect(handlers.NewRulesEditHandler(rulesCfg, "whitelist")))
	mux.Handle("POST /api/rules/blacklist", protect(handlers.NewRulesAddHandler(rulesCfg, "blacklist")))
	mux.Handle("DELETE /api/rules/blacklist/{id}", protect(handlers.NewRulesDeleteHandler(rulesCfg, "blacklist")))
	mux.Handle("PUT /api/rules/blacklist/{id}", protect(handlers.NewRulesEditHandler(rulesCfg, "blacklist")))

	server := &http.Server{Handler: mux}

	// Start server in background.
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error.
	select {
	case <-ctx.Done():
		slog.Info("shutting down webui server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}

// Addr blocks until the server is ready and returns the listener address.
// Returns an error if ctx expires before the server is ready.
func (s *Server) Addr(ctx context.Context) (net.Addr, error) {
	select {
	case <-s.listenerReady:
		return s.listener.Addr(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// nullPendingSource is a no-op PendingSource used when no real queue is wired.
type nullPendingSource struct{}

// Compile-time check: nullPendingSource must satisfy handlers.PendingSource.
var _ handlers.PendingSource = nullPendingSource{}

func (nullPendingSource) PendingItems() []*pending.Entry { return nil }
func (nullPendingSource) ReevaluatePending()             {}

// nullRulesSource is a no-op RulesSource used when no real proxy is wired.
type nullRulesSource struct{}

// Compile-time check: nullRulesSource must satisfy handlers.RulesSource.
var _ handlers.RulesSource = nullRulesSource{}

func (nullRulesSource) Whitelist() *reqrules.ReqRules { return reqrules.New() }
func (nullRulesSource) Blacklist() *reqrules.ReqRules { return reqrules.New() }
