//go:build integration

package integration_tests

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

// TestProxy_Integration_ConnectBlocking verifies that the proxy blocks CONNECT
// requests to non-443 ports with a 403 response and the configured delay.
//
// Covers:
//   - CONNECT to a non-443 port is rejected
//   - CONNECT to localhost is rejected by the CONNECT blocker (not the localhost blocker)
//   - The rejection delay is applied (≥ blockDelay)
func TestProxy_Integration_ConnectBlocking(t *testing.T) {
	defer goleak.VerifyNone(t)

	const blockDelay = 20 * time.Millisecond

	must := require.New(t)
	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableLocalhostBlocking: true, // isolate CONNECT blocking from localhost blocking
		BlockDelay:               blockDelay,
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

	t.Run("blocks CONNECT to non-443 ports", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get("https://example.com:8443/test")
		elapsed := time.Since(start)

		if err != nil {
			is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
			return
		}

		must.NotNil(resp)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errorResp map[string]string
		must.NoError(json.Unmarshal(body, &errorResp))
		is.Equal("connect_blocked", errorResp["error"])
		is.Equal("CONNECT method is not allowed", errorResp["reason"])
		is.NotEmpty(errorResp["request_id"])

		is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
	})

	t.Run("blocks CONNECT to localhost", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get("https://localhost:8080/test")
		elapsed := time.Since(start)

		if err != nil {
			is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
			return
		}

		must.NotNil(resp)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errorResp map[string]string
		must.NoError(json.Unmarshal(body, &errorResp))
		// CONNECT blocker fires before localhost blocker.
		is.Equal("connect_blocked", errorResp["error"])
		is.Equal("CONNECT method is not allowed", errorResp["reason"])

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

// TestProxy_Integration_ConnectDisabled verifies that when DisableConnectBlocking
// is set, HTTPS CONNECT requests are not rejected by the CONNECT blocker.
func TestProxy_Integration_ConnectDisabled(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableConnectBlocking:   true,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, caCert, caKey, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyErrChan := make(chan error, 1)
	go func() {
		proxyErrChan <- p.Start(ctx)
	}()

	proxyAddr, err := p.Addr(context.Background())
	require.New(t).NoError(err)
	require.New(t).NotNil(proxyAddr)

	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	t.Run("allows CONNECT when disabled", func(t *testing.T) {
		resp, err := client.Get("https://example.com/test")

		// The request may fail (example.com unreachable), but it must NOT be
		// rejected with a connect_blocked error.
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				var errorResp map[string]string
				if json.Unmarshal(body, &errorResp) == nil {
					is.NotEqual("connect_blocked", errorResp["error"],
						"should not be blocked by CONNECT blocker when disabled")
				}
			}
		}
	})

	cancel()
	select {
	case err := <-proxyErrChan:
		is.NoError(err)
	case <-time.After(2 * time.Second):
		t.Fatal("proxy shutdown timeout")
	}
}

// TestProxy_Integration_CONNECTBlockingWithTLSBumping tests the production
// scenario: CONNECT blocking enabled for non-443 ports, TLS bumping active.
// Expected: CONNECT to a non-443 httptest TLS server is blocked with a delay.
func TestProxy_Integration_CONNECTBlockingWithTLSBumping(t *testing.T) {
	defer goleak.VerifyNone(t)

	const blockDelay = 20 * time.Millisecond

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from HTTPS backend"))
	}))
	defer backend.Close()

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableConnectBlocking:   false, // production default: non-443 CONNECT blocked
		DisableLocalhostBlocking: true,  // allow httptest servers on 127.0.0.1
		BlockDelay:               blockDelay,
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
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test-only
			},
		},
		Timeout: 5 * time.Second,
	}

	t.Run("blocks CONNECT to non-443 port", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get(backend.URL)
		elapsed := time.Since(start)

		if err != nil {
			is.GreaterOrEqual(elapsed, blockDelay, "should delay for at least blockDelay")
			t.Logf("CONNECT to non-443 port blocked as expected: %v", err)
			return
		}

		must.NotNil(resp)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode, "should be blocked with 403")
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
