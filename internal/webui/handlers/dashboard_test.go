package handlers

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMetrics implements a minimal ProxyMetrics for testing.
type mockMetrics struct {
	requestCount     uint64
	rateLimitedCount int
	pendingCount     int
}

func (m *mockMetrics) RequestCount() uint64  { return m.requestCount }
func (m *mockMetrics) RateLimitedCount() int { return m.rateLimitedCount }
func (m *mockMetrics) PendingCount() int     { return m.pendingCount }

// newTestCert generates a minimal self-signed certificate for testing.
func newTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newTestConfig(t *testing.T) *DashboardConfig {
	t.Helper()
	return &DashboardConfig{
		StartTime:       time.Now().Add(-2 * time.Hour),
		GlobalRateLimit: 60,
		Cert:            newTestCert(t),
		Metrics: &mockMetrics{
			requestCount:     42,
			rateLimitedCount: 1,
			pendingCount:     3,
		},
	}
}

// --- Dashboard page handler ---

func TestDashboardHandler_ReturnsOK(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := newTestConfig(t)
	h := NewDashboardHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	must.Equal(http.StatusOK, rec.Code)
	is.Contains(rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	is.Contains(body, "aiproxy")
	is.Contains(body, "Status")                // single merged block header
	is.Contains(body, "Uptime")                // uptime row in the dl
	is.Contains(body, "Test CA")               // cert subject
	is.Contains(body, "/download-cert")        // cert download link
	is.Contains(body, "live-stats")            // SSE target element
	is.Contains(body, "/api/dashboard/stream") // SSE connect URL
}

func TestDashboardHandler_NoCert(t *testing.T) {
	is := assert.New(t)

	cfg := newTestConfig(t)
	cfg.Cert = nil // no cert
	h := NewDashboardHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	is.Equal(http.StatusOK, rec.Code)
	is.NotContains(rec.Body.String(), "/download-cert", "cert section should not appear when no cert")
}

// --- SSE stream handler ---

func TestSSEHandler_SendsUnnamedDataMessage(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := newTestConfig(t)
	h := NewSSEHandler(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(rec, req)
	}()

	// Give the handler a moment to write at least one SSE message, then cancel
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE handler did not exit in time")
	}

	body := rec.Body.String()

	// Must contain at least one SSE unnamed message (no "event:" line)
	must.Contains(body, "data:", "SSE response must contain data: line")
	is.NotContains(body, "event:", "SSE response must NOT contain event: line (htmx v4 unnamed message)")

	// Content-Type must be text/event-stream
	must.Equal("text/event-stream", rec.Header().Get("Content-Type"))

	// The data line should contain the full StatusFragment (dl with uptime + counters)
	is.Contains(body, "<dl>", "SSE data should contain rendered StatusFragment HTML")
	is.Contains(body, "Uptime", "SSE data should include live uptime row")
}

func TestSSEHandler_SendsMultipleMessages(t *testing.T) {
	is := assert.New(t)

	cfg := newTestConfig(t)
	cfg.SSEInterval = 50 * time.Millisecond // override for fast test
	h := NewSSEHandler(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(rec, req)
	}()

	// Wait for 3+ messages at 50ms each, then cancel
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	// Count the number of "data:" lines
	count := strings.Count(rec.Body.String(), "data:")
	is.GreaterOrEqual(count, 2, "Should have received at least 2 SSE messages")
}

// --- Cert download handler ---

func TestCertDownloadHandler_ReturnsPEM(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := newTestConfig(t)
	h := NewCertDownloadHandler(cfg.Cert)

	req := httptest.NewRequest(http.MethodGet, "/download-cert", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	must.Equal(http.StatusOK, rec.Code)
	is.Equal("application/x-pem-file", rec.Header().Get("Content-Type"))
	is.Contains(rec.Header().Get("Content-Disposition"), "ca-cert.pem")

	body := rec.Body.String()
	is.Contains(body, "-----BEGIN CERTIFICATE-----")
	is.Contains(body, "-----END CERTIFICATE-----")
	is.NotContains(body, "PRIVATE KEY", "cert download must never expose private key")
}

func TestCertDownloadHandler_NoCert_Returns404(t *testing.T) {
	must := require.New(t)

	h := NewCertDownloadHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/download-cert", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	must.Equal(http.StatusNotFound, rec.Code)
}

// --- SSE message format validation ---

func TestSSEHandler_MessageFormat(t *testing.T) {
	must := require.New(t)

	cfg := newTestConfig(t)
	h := NewSSEHandler(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(rec, req)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	// Parse SSE lines: must be "data: <html>" followed by blank line
	scanner := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Find a data: line
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, "data:") {
			found = true
			// Next line should be empty (SSE message terminator)
			if i+1 < len(lines) {
				must.Empty(lines[i+1], "SSE message must be followed by empty line")
			}
			break
		}
	}
	must.True(found, "SSE response must contain at least one data: line")
}
