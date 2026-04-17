//go:build integration

package integration_tests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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

// TestProxy_Integration_InvalidUpstreamCertificate tests that the proxy properly handles
// upstream servers with invalid (expired) certificates.
// Expected behavior:
// - Log error at ERROR level
// - Close connection to upstream server
// - Return HTTP 502 Bad Gateway to client
// - Return generic JSON error (no certificate details leaked)
func TestProxy_Integration_InvalidUpstreamCertificate(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Generate test CA certificate for proxy TLS bumping
	caCert, caKey := testdata.GenerateTestCA(t)

	// Create HTTPS backend server with EXPIRED certificate
	expiredCert, expiredKey := testdata.GenerateExpiredCert(t)

	// Create backend server with custom expired TLS certificate
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("This should never be returned"))
	}))

	// Configure backend with expired certificate
	backend.TLS = &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{expiredCert.Raw},
				PrivateKey:  expiredKey,
				Leaf:        expiredCert,
			},
		},
	}
	backend.StartTLS()
	defer backend.Close()

	// Start proxy with TLS bumping enabled
	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
		DisableLocalhostBlocking: true, // Allow test server on 127.0.0.1
		DisableConnectBlocking:   true, // Allow CONNECT for HTTPS tests
	}

	// Whitelist the backend so the request reaches the upstream TLS check.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))
	p := proxy.NewProxy(cfg, caCert, caKey, nil, wl)

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

	// Make HTTPS request through proxy
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
				// Do NOT skip verification - we want normal certificate validation
			},
		},
		Timeout: 5 * time.Second,
	}
	defer client.CloseIdleConnections()

	// Attempt to access the backend with expired certificate
	resp, err := client.Get(backend.URL)

	// The proxy should return a proper 502 Bad Gateway response
	must.NoError(err, "Should receive HTTP response (not connection error)")
	must.NotNil(resp, "Expected HTTP response from proxy")
	defer resp.Body.Close()

	// Verify 502 Bad Gateway status code
	is.Equal(http.StatusBadGateway, resp.StatusCode,
		"Expected 502 Bad Gateway for invalid upstream certificate")

	// Read and verify JSON error response
	body, err := io.ReadAll(resp.Body)
	must.NoError(err, "Should be able to read response body")

	// Verify response is JSON
	is.Equal("application/json", resp.Header.Get("Content-Type"),
		"Response should be JSON")

	// Parse JSON error response
	var errorResp map[string]string
	err = json.Unmarshal(body, &errorResp)
	must.NoError(err, "Response should be valid JSON")

	// Verify error response structure
	is.Equal("bad_gateway", errorResp["error"],
		"Error type should be 'bad_gateway'")
	is.Equal("upstream connection failed", errorResp["reason"],
		"Reason should be generic (no cert details)")
	is.Contains(errorResp["request_id"], "req_",
		"Should include request ID")

	// Verify that NO certificate details are leaked
	bodyStr := string(body)
	is.NotContains(bodyStr, "expired", "Should not expose certificate expiry details")
	is.NotContains(bodyStr, "x509", "Should not expose x509 error details")
	is.NotContains(bodyStr, "certificate", "Should not expose certificate details in response body")
	is.NotContains(bodyStr, "This should never be returned",
		"Should not return upstream content")
}
