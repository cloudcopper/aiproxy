package handlers

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cloudcopper/aiproxy/internal/webui/auth"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
)

// ProxyMetrics provides live counters from the proxy for display on the dashboard.
// It is defined here (consumer side) so the proxy package has no dependency on webui.
type ProxyMetrics interface {
	RequestCount() uint64
	RateLimitedCount() int
	PendingCount() int
}

// DashboardConfig holds everything the dashboard handlers need.
type DashboardConfig struct {
	StartTime       time.Time
	GlobalRateLimit int // 0 = unlimited
	Cert            *x509.Certificate
	Metrics         ProxyMetrics
	SSEInterval     time.Duration      // defaults to 1s if zero
	AuthEnabled     bool               // true when --admin-secret is set
	Sessions        *auth.SessionStore // used to determine IsAuthenticated per request
}

func (c *DashboardConfig) sseInterval() time.Duration {
	if c.SSEInterval > 0 {
		return c.SSEInterval
	}
	return 1 * time.Second
}

// dashboardHandler serves the main dashboard page.
type dashboardHandler struct {
	cfg *DashboardConfig
}

// NewDashboardHandler returns an http.Handler for the dashboard page.
func NewDashboardHandler(cfg *DashboardConfig) http.Handler {
	return &dashboardHandler{cfg: cfg}
}

func (h *dashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := buildDashboardData(h.cfg, h.navForRequest(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.DashboardPage(data).Render(r.Context(), w); err != nil {
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

// navForRequest checks the session cookie on the current request and builds
// the correct NavData. Called once per page render (not per SSE tick).
func (h *dashboardHandler) navForRequest(r *http.Request) templates.NavData {
	isAuthenticated := false
	if h.cfg.Sessions != nil {
		if cookie, err := r.Cookie(auth.CookieName); err == nil {
			isAuthenticated = h.cfg.Sessions.Validate(cookie.Value) == auth.SessionValid
		}
	}
	return templates.NavData{IsAuthenticated: isAuthenticated, AuthEnabled: h.cfg.AuthEnabled}
}

// buildDashboardData snapshots the current config and live metrics into a DashboardData value.
// nav is computed per-request by the page handler; SSE only sends the status fragment (no nav).
func buildDashboardData(cfg *DashboardConfig, nav templates.NavData) templates.DashboardData {
	return templates.DashboardData{
		Nav:              nav,
		StartTime:        cfg.StartTime,
		GlobalRateLimit:  cfg.GlobalRateLimit,
		Cert:             cfg.Cert,
		RequestCount:     cfg.Metrics.RequestCount(),
		PendingCount:     cfg.Metrics.PendingCount(),
		RateLimitedCount: cfg.Metrics.RateLimitedCount(),
	}
}

// sseHandler streams live stats as SSE unnamed messages (htmx v4 pattern).
type sseHandler struct {
	cfg *DashboardConfig
}

// NewSSEHandler returns an http.Handler for the SSE live-stats stream.
func NewSSEHandler(cfg *DashboardConfig) http.Handler {
	return &sseHandler{cfg: cfg}
}

func (h *sseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	tick := time.NewTicker(h.cfg.sseInterval())
	defer tick.Stop()

	// Send an initial message immediately
	h.sendStats(w, flusher, r)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			h.sendStats(w, flusher, r)
		}
	}
}

// sseData encodes s for safe SSE transmission.
// The SSE spec (WHATWG) requires that each line of data be prefixed with "data: ".
// A bare \n inside a single data field ends that field early; subsequent content is
// parsed as a new (unknown) field and silently discarded by clients.
// This function trims any trailing newline produced by the template renderer, then
// replaces every embedded \n with "\ndata: " so the full payload arrives intact.
func sseData(s string) string {
	s = strings.TrimRight(s, "\n")
	return strings.ReplaceAll(s, "\n", "\ndata: ")
}

// sendStats renders StatusFragment and sends it as an unnamed SSE message.
func (h *sseHandler) sendStats(w http.ResponseWriter, flusher http.Flusher, r *http.Request) {
	data := buildDashboardData(h.cfg, templates.NavData{})

	var buf bytes.Buffer
	if err := templates.StatusFragment(data).Render(r.Context(), &buf); err != nil {
		return
	}

	// htmx v4 SSE: unnamed message = no "event:" line; auto-swaps element's content
	fmt.Fprintf(w, "data: %s\n\n", sseData(buf.String()))
	flusher.Flush()
}

// certDownloadHandler serves the CA certificate as a PEM-encoded download.
type certDownloadHandler struct {
	cert *x509.Certificate
}

// NewCertDownloadHandler returns an http.Handler that serves the CA cert PEM file.
// If cert is nil, the handler returns 404.
func NewCertDownloadHandler(cert *x509.Certificate) http.Handler {
	return &certDownloadHandler{cert: cert}
}

func (h *certDownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cert == nil {
		http.NotFound(w, r)
		return
	}

	// Re-encode from memory — never reads a file. This guarantees we never
	// accidentally serve a combined cert+key file.
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: h.cert.Raw,
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, pemBlock); err != nil {
		http.Error(w, "failed to encode certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca-cert.pem"`)
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
