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
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_ConnectMITM_PlainHTTPViaTunnel verifies that CONNECT
// to a non-443 port is accepted and plain HTTP traffic flows through the
// normal pipeline (whitelist/blacklist/pending).
func TestProxy_Integration_ConnectMITM_PlainHTTPViaTunnel(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Plain HTTP backend on a random port (not 443).
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from plain HTTP backend"))
	}))
	defer backend.Close()

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
		DisableLocalhostBlocking: true,
	}

	// Whitelist the backend so requests pass through.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))
	p := proxy.NewProxy(cfg, caCert, caKey, nil, wl)

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

	resp, err := client.Get(backend.URL)
	must.NoError(err)
	defer resp.Body.Close()

	is.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	must.NoError(err)
	is.Equal("Hello from plain HTTP backend", string(body))
}

// TestProxy_Integration_ConnectMITM_BlacklistedViaTunnel verifies that a
// CONNECT to a non-443 port is accepted but a blacklisted request is still
// blocked (403 forbidden).
func TestProxy_Integration_ConnectMITM_BlacklistedViaTunnel(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Should not reach backend"))
	}))
	defer backend.Close()

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0,
		DisableLocalhostBlocking: true,
	}

	// Whitelist the backend.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))

	// Blacklist the same backend.
	bl := reqrules.New()
	bl.Add(ruleFromServer(t, "block-backend", "", backend.URL))

	p := proxy.NewProxy(cfg, caCert, caKey, bl, wl)

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

	resp, err := client.Get(backend.URL)
	must.NoError(err)
	defer resp.Body.Close()

	is.Equal(http.StatusForbidden, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	must.NoError(err)

	var errorResp map[string]string
	must.NoError(json.Unmarshal(body, &errorResp))
	is.Equal("forbidden", errorResp["error"])
	is.NotEmpty(errorResp["request_id"])
}

// TestProxy_Integration_ConnectMITM_NonStandardTLSPort verifies that CONNECT
// to a non-443 HTTPS port is accepted and TLS MITM works correctly.
func TestProxy_Integration_ConnectMITM_NonStandardTLSPort(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// HTTPS backend on a random port (not 443).
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from HTTPS non-standard port"))
	}))
	defer backend.Close()

	caCert, caKey := generateTestCA(t)

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0,
		DisableLocalhostBlocking: true,
	}

	// Whitelist the backend.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))
	p := proxy.NewProxy(cfg, caCert, caKey, nil, wl)

	// Configure proxy to trust the test backend's certificate.
	backendCertPool := x509.NewCertPool()
	backendCertPool.AddCert(backend.Certificate())
	p.SetUpstreamTLSConfig(&tls.Config{
		RootCAs: backendCertPool,
	})

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

	// Create cert pool with test CA certificate.
	certPool := x509.NewCertPool()
	certPool.AddCert(caCert)

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
	must.NoError(err)
	defer resp.Body.Close()

	is.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	must.NoError(err)
	is.Equal("Hello from HTTPS non-standard port", string(body))
}
