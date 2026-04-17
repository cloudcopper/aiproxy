//go:build integration

package integration_tests

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_HTTPForwarding tests basic HTTP proxying with local server.
func TestProxy_Integration_HTTPForwarding(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Create test HTTP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from backend"))
	}))
	defer backend.Close()

	// Start proxy on random port
	cfg := &proxy.Config{
		Listen:                   "localhost:0", // random port
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified requests
		DisableLocalhostBlocking: true, // Allow test server on 127.0.0.1
		DisableConnectBlocking:   true, // Allow CONNECT for HTTPS tests
	}

	// Whitelist the backend so requests pass through.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))
	p := proxy.NewProxy(cfg, nil, nil, nil, wl)

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

	// Make request through proxy
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	must.NoError(err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	is.Equal(http.StatusOK, resp.StatusCode)
	is.Equal("Hello from backend", string(body))
}
