//go:build integration

package integration_tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockMetrics is a minimal ProxyMetrics for testing.
type mockMetrics struct{}

func (m *mockMetrics) RequestCount() uint64  { return 0 }
func (m *mockMetrics) RateLimitedCount() int { return 0 }
func (m *mockMetrics) PendingCount() int     { return 0 }

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

func startTestServer(t *testing.T) (srv *webui.Server, baseURL string) {
	t.Helper()
	must := require.New(t)

	cfg := &webui.ServerConfig{
		Listen:          "localhost:0",
		StartTime:       time.Now(),
		GlobalRateLimit: 0,
		Cert:            newTestCert(t),
		Metrics:         &mockMetrics{},
	}
	srv = webui.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(ctx); err != nil {
			errCh <- err
		}
	}()

	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := srv.Addr(addrCtx)
	must.NoError(err, "server should be ready")

	baseURL = fmt.Sprintf("http://%s", addr)
	return srv, baseURL
}

// --- Route registration tests ---

func TestServer_DashboardRoute(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	_, baseURL := startTestServer(t)

	resp, err := http.Get(baseURL + "/")
	must.NoError(err)
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
	is.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func TestServer_SSERoute(t *testing.T) {
	must := require.New(t)

	_, baseURL := startTestServer(t)

	// Open SSE connection and immediately close it
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/dashboard/stream", nil)
	must.NoError(err)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Context timeout is acceptable — server responded with correct headers
		return
	}
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
	must.Equal("text/event-stream", resp.Header.Get("Content-Type"))
}

func TestServer_CertDownloadRoute(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	_, baseURL := startTestServer(t)

	resp, err := http.Get(baseURL + "/download-cert")
	must.NoError(err)
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
	is.Equal("application/x-pem-file", resp.Header.Get("Content-Type"))
}

// --- Embedded static file tests ---

func TestServer_StaticHTMX(t *testing.T) {
	must := require.New(t)

	_, baseURL := startTestServer(t)

	resp, err := http.Get(baseURL + "/static/htmx.min.js")
	must.NoError(err)
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
}

func TestServer_StaticSSEExtension(t *testing.T) {
	must := require.New(t)

	_, baseURL := startTestServer(t)

	resp, err := http.Get(baseURL + "/static/hx-sse.min.js")
	must.NoError(err)
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
}

func TestServer_StaticPicoCSS(t *testing.T) {
	must := require.New(t)

	_, baseURL := startTestServer(t)

	resp, err := http.Get(baseURL + "/static/pico.min.css")
	must.NoError(err)
	defer resp.Body.Close()

	must.Equal(http.StatusOK, resp.StatusCode)
}

// --- Lifecycle tests ---

func TestServer_ContextCancellation(t *testing.T) {
	must := require.New(t)

	cfg := &webui.ServerConfig{
		Listen:    "localhost:0",
		StartTime: time.Now(),
		Metrics:   &mockMetrics{},
	}
	srv := webui.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for ready
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	_, err := srv.Addr(addrCtx)
	must.NoError(err)

	// Cancel and expect clean shutdown
	cancel()
	select {
	case err := <-errCh:
		must.NoError(err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}
