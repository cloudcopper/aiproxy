package proxy

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/cloudcopper/aiproxy/internal/pending"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/elazarl/goproxy"
)

// Config holds proxy configuration.
type Config struct {
	Listen            string
	ConnectionTimeout time.Duration
	RequestTimeout    time.Duration
	GlobalRateLimit   int           // req/min (0 = unlimited)
	PendingTimeout    time.Duration // 0 = immediate rejection mode (queue always active)

	// DisableConnectBlocking disables CONNECT method blocking (TEST ONLY).
	// This should NEVER be set to true in production code.
	// It exists only to allow tests to establish CONNECT tunnels for testing.
	DisableConnectBlocking bool

	// DisableLocalhostBlocking disables SSRF protection (TEST ONLY).
	// This should NEVER be set to true in production code.
	// It exists only to allow tests to use httptest.NewServer (which uses 127.0.0.1).
	DisableLocalhostBlocking bool

	// BlockDelay overrides the delay applied when blocking localhost or CONNECT
	// requests. Zero means use the production default (1 second).
	// This field exists primarily for testing; do not set in production.
	BlockDelay time.Duration
}

// blockDelay returns the delay to apply when blocking requests.
// Falls back to the 1-second production default when BlockDelay is zero.
func (cfg *Config) blockDelay() time.Duration {
	if cfg.BlockDelay > 0 {
		return cfg.BlockDelay
	}
	return time.Second
}

// Proxy manages the HTTP/HTTPS proxy server.
type Proxy struct {
	config   *Config
	goproxy  *goproxy.ProxyHttpServer
	server   *http.Server
	listener net.Listener

	// Access control
	blacklist *reqrules.ReqRules // blacklist rules; nil means no blacklist registered
	whitelist *reqrules.ReqRules // whitelist rules; nil means no whitelist registered
	queue     *pending.Queue     // pending queue; nil when disabled or no whitelist

	// listenerReady is closed when the listener is ready.
	// Provides synchronization between Start() and Addr().
	listenerReady chan struct{}

	// nextID generates sequential request IDs for all proxied requests.
	nextID atomic.Uint64

	// globalRL is the global rate limiter; nil when rate limiting is disabled.
	globalRL *GlobalRateLimiter

	// tlsBump holds per-instance TLS bumping state (CA-derived ConnectActions).
	// nil when TLS bumping is disabled.
	tlsBump *tlsBumpConfig
}

// NewProxy creates a new proxy instance with TLS bumping enabled.
// caCert and caKey are the CA certificate and private key used for MITM TLS interception.
// blacklist contains request blocking rules; pass nil or an empty ReqRules to disable.
// whitelist contains request allowing rules; pass nil or an empty ReqRules to disable.
func NewProxy(cfg *Config, caCert *x509.Certificate, caKey crypto.PrivateKey, blacklist *reqrules.ReqRules, whitelist *reqrules.ReqRules) *Proxy {
	// Normalize nil stores to empty stores so handlers can always call Match
	// without a nil-receiver panic, and so rules added at runtime (via WebUI)
	// are always visible to the registered handlers.
	if blacklist == nil {
		blacklist = reqrules.New()
	}
	if whitelist == nil {
		whitelist = reqrules.New()
	}
	// Initialize goproxy
	goproxyInstance := goproxy.NewProxyHttpServer()
	goproxyInstance.Verbose = false // We'll use slog, not goproxy's built-in logging
	// TODO We may need to configure proxy.Logger for better integration
	//      and potentially filter unnecessary messages

	// Configure outbound TLS with proper certificate validation
	// By default, goproxy uses InsecureSkipVerify=true, which we override here
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// Use system CA trust store for upstream certificate validation
			// InsecureSkipVerify is false by default (strict validation)
		},
		Proxy: http.ProxyFromEnvironment,
	}
	goproxyInstance.Tr = transport

	// Build per-instance TLS bumping config (if CA provided).
	// Does NOT mutate goproxy globals — safe for parallel tests.
	var tlsBump *tlsBumpConfig
	if caCert != nil && caKey != nil {
		tlsBump = newTLSBumpConfig(caCert, caKey)
		slog.Info("tls bumping enabled", "ca_subject", caCert.Subject.CommonName)
	} else {
		slog.Warn("tls bumping disabled: ca certificate or key not provided")
	}

	// Create Proxy instance (needed for handlers that reference p)
	p := &Proxy{
		config:        cfg,
		goproxy:       goproxyInstance,
		blacklist:     blacklist,
		whitelist:     whitelist,
		listenerReady: make(chan struct{}),
		tlsBump:       tlsBump,
	}

	// Create a single RoundTripper instance to intercept certificate errors
	// This wraps the standard transport and provides proper error responses
	certValidatingRT := &certValidatingRoundTripper{
		transport: transport,
		proxy:     p,
	}

	// Set the custom RoundTripper on each request context
	// Note: goproxy requires setting ctx.RoundTripper per-request (it's stored in ProxyCtx),
	// but we reuse the same RoundTripper instance (no allocation per request)
	goproxyInstance.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = certValidatingRT
		return req, nil
	})

	// Register request handler (logging + RequestID assignment)
	goproxyInstance.OnRequest().DoFunc(p.onRequest)

	// Register CONNECT handlers:
	// Strategy: Allow CONNECT to :443 (HTTPS/TLS bumping), block all other ports
	//
	// Handler registration order (first non-nil result wins):
	// 1. Block CONNECT to non-443 ports (if blocking enabled)
	// 2. TLS bump CONNECT to :443 (if TLS certs provided)
	//
	// This allows:
	// - HTTPS via TLS bumping (CONNECT to :443 → MITM → inspect)
	// - Blocks arbitrary TCP tunnels (CONNECT to other ports → reject)

	if !cfg.DisableConnectBlocking {
		// Block CONNECT to all ports EXCEPT :443
		// Pattern: NOT(host ends with :443)
		port443Pattern := regexp.MustCompile(`:443$`)
		goproxyInstance.OnRequest(goproxy.Not(goproxy.ReqHostMatches(port443Pattern))).
			HandleConnect(p.blockConnectHandler())
		slog.Info("CONNECT blocking enabled (non-443 ports blocked)")
	}

	// TLS bumping for HTTPS (CONNECT to :443)
	// This runs AFTER the blocker, so :443 CONNECT requests pass through to here
	if tlsBump != nil {
		goproxyInstance.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return p.tlsBump.mitmConnect, host
			},
		))
		// Note: If blocking enabled, only :443 reaches here (others blocked above)
		// If blocking disabled, all CONNECT requests reach here
	}

	// Register localhost IP blocker (SSRF protection) unless disabled for tests
	if !cfg.DisableLocalhostBlocking {
		goproxyInstance.OnRequest().DoFunc(p.blockLocalhost)
	}

	// Always register blacklist handler.
	// When the store is empty, Match returns no match and the handler is a
	// no-op pass-through. Always registering ensures rules added at runtime
	// (via WebUI) take effect without a proxy restart.
	goproxyInstance.OnRequest().DoFunc(p.blockBlacklist)
	if n := blacklist.Count(); n > 0 {
		slog.Info("blacklist enabled", "rule_count", n)
	} else {
		slog.Info("blacklist empty (rules may be added at runtime)")
	}

	// Create pending queue unconditionally.
	// PendingTimeout == 0 means immediate rejection — NOT pass-through.
	// There is no configuration that bypasses the pending queue for unclassified requests.
	p.queue = pending.NewQueue(cfg.PendingTimeout)
	if cfg.PendingTimeout == 0 {
		slog.Info("pending queue enabled (immediate rejection mode)")
	} else {
		slog.Info("pending queue enabled", "timeout", cfg.PendingTimeout)
	}

	// Always register allowWhitelist.
	// On match → forward to upstream. On no match → holdPending.
	// When the store is empty, all non-blacklisted requests go to the pending
	// queue (same behaviour as the old holdPending catch-all). Rules added at
	// runtime (via WebUI) take effect immediately without a restart.
	goproxyInstance.OnRequest().DoFunc(p.allowWhitelist)
	if n := whitelist.Count(); n > 0 {
		slog.Info("whitelist enabled", "rule_count", n)
	} else {
		slog.Info("whitelist empty, all requests held pending (rules may be added at runtime)")
	}

	// Register global rate limiter middleware (only if configured)
	if cfg.GlobalRateLimit > 0 {
		interval := time.Duration(float64(time.Minute) / float64(cfg.GlobalRateLimit))
		store := NewDelayedRequestStore()
		globalRL := NewGlobalRateLimiter(interval, store)
		p.globalRL = globalRL
		goproxyInstance.OnRequest().DoFunc(globalRL.Handle)
		slog.Info("global rate limiter enabled", "rpm", cfg.GlobalRateLimit, "interval", interval.Round(time.Millisecond))
	}

	// Register response handler
	goproxyInstance.OnResponse().DoFunc(p.onResponse)

	return p
}

// SetUpstreamTLSConfig configures the TLS settings for upstream connections.
// This is primarily used for testing to trust test server certificates.
func (p *Proxy) SetUpstreamTLSConfig(tlsConfig *tls.Config) {
	if p.goproxy.Tr != nil {
		p.goproxy.Tr.TLSClientConfig = tlsConfig
	}
}

// Start starts the proxy server.
// Blocks until context is cancelled or server fails.
func (p *Proxy) Start(ctx context.Context) error {
	// Create listener to get actual address (especially important for ":0")
	listener, err := net.Listen("tcp", p.config.Listen)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	actualAddr := listener.Addr().String()
	slog.Info("starting proxy server", "addr", actualAddr)
	p.listener = listener
	// Signal that listener is ready. Close happens-after assignment,
	// guaranteeing visibility to Addr() via channel receive.
	close(p.listenerReady)

	server := &http.Server{
		Handler:      p.goproxy,
		ReadTimeout:  p.config.ConnectionTimeout,
		WriteTimeout: p.config.RequestTimeout,
	}
	p.server = server

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		slog.Info("shutting down proxy server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errChan:
		return err
	}
}

// Addr returns the address the proxy is listening on.
// Blocks until the listener is ready or context is cancelled.
// Returns nil addr and error if context cancelled before listener ready.
//
// Note: If Start() fails before creating the listener (e.g., bind error),
// this method will block indefinitely unless the caller also monitors
// the error channel from Start(). The caller should use a select statement
// that checks both Addr() completion and the Start() error channel.
func (p *Proxy) Addr(ctx context.Context) (net.Addr, error) {
	// Wait for listener to be ready or context cancellation
	select {
	case <-p.listenerReady:
		// Listener is ready, safe to read p.listener.
		// The channel receive happens-before this read, guaranteeing visibility.
		// p.listener is guaranteed non-nil (assigned before channel close).
		return p.listener.Addr(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RequestCount returns the total number of requests that have been assigned an ID.
func (p *Proxy) RequestCount() uint64 {
	return p.nextID.Load()
}

