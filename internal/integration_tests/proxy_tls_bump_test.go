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

// TestProxy_Integration_TLSBumping tests HTTPS interception (TLS bumping/MITM).
func TestProxy_Integration_TLSBumping(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Generate test CA certificate for proxy
	caCert, caKey := testdata.GenerateTestCA(t)

	// Create test HTTPS backend server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from HTTPS backend"))
	}))
	defer backend.Close()

	// Start proxy with TLS bumping enabled
	cfg := &proxy.Config{
		Listen:                   "localhost:0", // random port
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
		DisableLocalhostBlocking: true, // Allow test server on 127.0.0.1
		DisableConnectBlocking:   true, // Allow CONNECT for HTTPS tests
	}

	// Whitelist the TLS backend so requests pass through the pending queue.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))
	p := proxy.NewProxy(cfg, caCert, caKey, nil, wl)

	// Configure proxy to trust the test backend's certificate
	// httptest.TLSServer uses its own self-signed certificate
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

	// Wait for proxy to start (blocks until listener ready)
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := p.Addr(addrCtx)
	must.NoError(err, "Failed to get proxy address")
	must.NotEmpty(addr, "Proxy should have a listening address")

	// Create cert pool with test CA certificate
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

	// Make HTTPS request through proxy with CA trust
	proxyURL, err := url.Parse("http://" + addr.String())
	must.NoError(err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(backend.URL)
	must.NoError(err, "HTTPS request through TLS bumping proxy should succeed")
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	is.Equal(http.StatusOK, resp.StatusCode)
	is.Equal("Hello from HTTPS backend", string(body))

	// Note: The header injection test would require modifying the proxy
	// to add a custom header during interception. For v1, we verify that
	// the request succeeds with TLS bumping enabled, which proves interception
	// is working (not just CONNECT tunneling).
	// The fact that we get a valid response with a trusted CA proves TLS bumping works.
}
