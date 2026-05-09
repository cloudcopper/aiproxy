//go:build integration

package integration_tests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/proxy/testdata"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_HTTPSTunnel tests HTTPS CONNECT tunneling with TLS bump.
func TestProxy_Integration_HTTPSTunnel(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Create test HTTPS server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from HTTPS backend"))
	}))
	defer backend.Close()

	caCert, caKey := testdata.GenerateTestCA(t)

	// Whitelist the backend so requests pass through.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))

	// Start proxy with TLS bumping
	p := proxy.NewProxy(&proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableLocalhostBlocking: true,
	}, caCert, caKey, nil, wl)

	// Configure proxy to trust the test backend's certificate.
	backendCertPool := x509.NewCertPool()
	backendCertPool.AddCert(backend.Certificate())
	p.SetUpstreamTLSConfig(&tls.Config{
		RootCAs: backendCertPool,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	// Wait for proxy to start
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := p.Addr(addrCtx)
	must.NoError(err, "Failed to get proxy address")
	must.NotEmpty(addr, "Proxy should have a listening address")

	// Create cert pool with test CA certificate (for proxy trust)
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// Make HTTPS request through proxy (tunnel mode with TLS bump)
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
			DisableKeepAlives: true, // disable keep-alive to prevent persistConn goroutine leaks
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	must.NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	is.Equal(http.StatusOK, resp.StatusCode)
	is.Equal("Hello from HTTPS backend", string(body))

	// Close idle connections to prevent goroutine leaks in subsequent tests.
	client.CloseIdleConnections()
}

// TestProxy_Integration_RealHTTPS tests against a real external HTTPS site
// using TLS bumping with a test CA.
func TestProxy_Integration_RealHTTPS(t *testing.T) {
	defer goleak.VerifyNone(t)

	if testing.Short() {
		t.Skip("Skipping real external HTTPS test in short mode")
	}

	must := require.New(t)
	is := assert.New(t)

	// Generate test CA for proxy TLS bumping
	caCert, caKey := testdata.GenerateTestCA(t)

	// Whitelist github.com so requests pass through.
	wl := reqrules.New()
	wl.Add(reqrules.Rule{
		ID:     "allow-github",
		Method: "GET",
		Scheme: "https",
		Host:   "github.com",
		Path:   "/**",
	})

	// Start proxy with TLS bumping enabled
	p := proxy.NewProxy(&proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        10 * time.Second,
		RequestTimeout:           30 * time.Second,
		DisableLocalhostBlocking: true,
	}, caCert, caKey, nil, wl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	// Wait for proxy to start
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := p.Addr(addrCtx)
	must.NoError(err, "Failed to get proxy address")
	must.NotEmpty(addr, "Proxy should have a listening address")

	// Create cert pool with test CA certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
			DisableKeepAlives: true, // disable keep-alive to prevent persistConn goroutine leaks
		},
		Timeout: 10 * time.Second,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get("https://github.com")
	must.NoError(err, "Should successfully proxy HTTPS request to github.com")
	defer resp.Body.Close()

	// GitHub should return 200 OK for GET /
	is.True(resp.StatusCode >= 200 && resp.StatusCode < 400,
		"Expected success status code, got %d", resp.StatusCode)

	// Verify we got actual content (not just tunnel success)
	body, err := io.ReadAll(resp.Body)
	must.NoError(err)
	is.Greater(len(body), 0, "Should receive response body from github.com")

	// Close idle connections to prevent goroutine leaks in subsequent tests.
	client.CloseIdleConnections()
}
