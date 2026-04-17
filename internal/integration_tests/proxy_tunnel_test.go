//go:build integration

package integration_tests

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_HTTPSTunnel tests HTTPS CONNECT tunneling (no TLS bump).
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

	// Start proxy
	cfg := &proxy.Config{
		Listen:                   "localhost:0", // random port
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableLocalhostBlocking: true, // Allow test server on 127.0.0.1
		DisableConnectBlocking:   true, // Allow CONNECT for HTTPS tunneling test
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	// Wait for proxy to start (blocks until listener ready)
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := p.Addr(addrCtx)
	must.NoError(err, "Failed to get proxy address")
	must.NotEmpty(addr, "Proxy should have a listening address")

	// Make HTTPS request through proxy (tunnel mode)
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For test server
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	must.NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	is.Equal(http.StatusOK, resp.StatusCode)
	is.Equal("Hello from HTTPS backend", string(body))
}

// TestProxy_Integration_RealHTTPS tests against a real external HTTPS site.
func TestProxy_Integration_RealHTTPS(t *testing.T) {
	defer goleak.VerifyNone(t)

	if testing.Short() {
		t.Skip("Skipping real external HTTPS test in short mode")
	}

	must := require.New(t)
	is := assert.New(t)

	// Start proxy
	cfg := &proxy.Config{
		Listen:                   "localhost:0", // random port
		ConnectionTimeout:        10 * time.Second,
		RequestTimeout:           30 * time.Second,
		DisableLocalhostBlocking: true, // Allow test server on 127.0.0.1
		DisableConnectBlocking:   true, // Allow CONNECT for HTTPS tests
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = p.Start(ctx)
	}()

	// Wait for proxy to start (blocks until listener ready)
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := p.Addr(addrCtx)
	must.NoError(err, "Failed to get proxy address")
	must.NotEmpty(addr, "Proxy should have a listening address")

	// Test against GitHub (reliable, public HTTPS endpoint)
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
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
}
