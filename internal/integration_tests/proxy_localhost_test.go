//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_LocalhostBlocking verifies that the proxy rejects
// HTTP requests targeting localhost addresses with 403 and the configured delay.
//
// Covers:
//   - http://localhost:<port> is blocked
//   - http://127.0.0.1:<port> is blocked
//   - Error response carries correct JSON fields
//   - Rejection includes the configured delay (≥ blockDelay)
func TestProxy_Integration_LocalhostBlocking(t *testing.T) {
	defer goleak.VerifyNone(t)

	const blockDelay = 20 * time.Millisecond

	must := require.New(t)
	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:            "localhost:0",
		ConnectionTimeout: 5 * time.Second,
		RequestTimeout:    10 * time.Second,
		BlockDelay:        blockDelay,
	}
	p := proxy.NewProxy(cfg, caCert, caKey, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- p.Start(ctx)
	}()

	proxyAddr, err := p.Addr(context.Background())
	must.NoError(err)
	must.NotNil(proxyAddr)

	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	t.Run("blocks localhost requests", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get("http://localhost:8080/test")
		elapsed := time.Since(start)

		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errorResp map[string]string
		must.NoError(json.Unmarshal(body, &errorResp))
		is.Equal("localhost_blocked", errorResp["error"])
		is.Equal("requests to localhost are not allowed", errorResp["reason"])
		is.NotEmpty(errorResp["request_id"])

		is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
	})

	t.Run("blocks 127.0.0.1 requests", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get("http://127.0.0.1:8080/test")
		elapsed := time.Since(start)

		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errorResp map[string]string
		must.NoError(json.Unmarshal(body, &errorResp))
		is.Equal("localhost_blocked", errorResp["error"])

		is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
	})

	cancel()
	select {
	case err := <-proxyErrChan:
		is.NoError(err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy shutdown timeout")
	}
}

// TestProxy_Integration_LocalhostIPv6 verifies that the proxy blocks HTTP
// requests targeting the IPv6 loopback address [::1].
func TestProxy_Integration_LocalhostIPv6(t *testing.T) {
	defer goleak.VerifyNone(t)

	const blockDelay = 20 * time.Millisecond

	must := require.New(t)
	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:            "localhost:0",
		ConnectionTimeout: 5 * time.Second,
		RequestTimeout:    10 * time.Second,
		BlockDelay:        blockDelay,
	}
	p := proxy.NewProxy(cfg, caCert, caKey, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- p.Start(ctx)
	}()

	proxyAddr, err := p.Addr(context.Background())
	must.NoError(err)
	must.NotNil(proxyAddr)

	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	t.Run("blocks ::1 requests", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get("http://[::1]:8080/test")
		elapsed := time.Since(start)

		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errorResp map[string]string
		must.NoError(json.Unmarshal(body, &errorResp))
		is.Equal("localhost_blocked", errorResp["error"])

		is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
	})

	cancel()
	select {
	case err := <-proxyErrChan:
		is.NoError(err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy shutdown timeout")
	}
}
