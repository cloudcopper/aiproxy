package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestNewProxy(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}

	p := NewProxy(cfg, nil, nil, nil, nil)

	must.NotNil(p)
	is.NotNil(p.config)
	is.NotNil(p.goproxy)
	is.Equal(cfg.Listen, p.config.Listen)
}

func TestProxy_Configuration(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
	}{
		{
			name: "default timeouts",
			config: &Config{
				Listen:            ":8080",
				ConnectionTimeout: 30 * time.Second,
				RequestTimeout:    300 * time.Second,
			},
		},
		{
			name: "custom timeouts",
			config: &Config{
				Listen:            ":9090",
				ConnectionTimeout: 10 * time.Second,
				RequestTimeout:    60 * time.Second,
			},
		},
		{
			name: "random port",
			config: &Config{
				Listen:            "localhost:0",
				ConnectionTimeout: 5 * time.Second,
				RequestTimeout:    10 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			must := require.New(t)
			is := assert.New(t)

			p := NewProxy(tt.config, nil, nil, nil, nil)
			must.NotNil(p)
			is.Equal(tt.config.Listen, p.config.Listen)
			is.Equal(tt.config.ConnectionTimeout, p.config.ConnectionTimeout)
			is.Equal(tt.config.RequestTimeout, p.config.RequestTimeout)
		})
	}
}

func TestProxy_Start_ContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	cfg := &Config{
		Listen:            "localhost:0", // random port
		ConnectionTimeout: 5 * time.Second,
		RequestTimeout:    10 * time.Second,
	}

	p := NewProxy(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		errChan <- p.Start(ctx)
	}()

	// Wait for proxy to start (blocks until listener ready)
	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	_, err := p.Addr(addrCtx)
	must.NoError(err, "Proxy should start successfully before testing cancellation")

	// Cancel context to trigger shutdown
	cancel()

	// Should return without error
	select {
	case err := <-errChan:
		is.NoError(err, "Proxy should shut down cleanly on context cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("Proxy did not shut down within timeout")
	}
}

// generateTestCA creates a test CA certificate and private key for testing.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate ECDSA private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate private key")

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "Failed to generate serial number")

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Valid for 1 day
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err, "Failed to create certificate")

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err, "Failed to parse certificate")

	return cert, key
}

// TestNewProxy_WithCertificate tests proxy initialization with CA certificate and key.
func TestNewProxy_WithCertificate(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}

	// Generate test CA certificate
	cert, key := generateTestCA(t)

	// Create proxy with certificate
	p := NewProxy(cfg, cert, key, nil, nil)

	must.NotNil(p)
	is.NotNil(p.config)
	is.NotNil(p.goproxy)
	is.Equal(cfg.Listen, p.config.Listen)
}

// TestNewProxy_WithoutCertificate tests proxy initialization without TLS bumping.
func TestNewProxy_WithoutCertificate(t *testing.T) {
	must := require.New(t)
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}

	// Create proxy without certificate (TLS bumping disabled)
	p := NewProxy(cfg, nil, nil, nil, nil)

	must.NotNil(p)
	is.NotNil(p.config)
	is.NotNil(p.goproxy)
	is.Equal(cfg.Listen, p.config.Listen)
}

// TestNewProxy_TLSBumpingConfiguration tests that TLS bumping is properly configured.
func TestNewProxy_TLSBumpingConfiguration(t *testing.T) {
	must := require.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}

	// Generate test CA certificate
	cert, key := generateTestCA(t)

	// Create proxy with certificate
	p := NewProxy(cfg, cert, key, nil, nil)

	must.NotNil(p)
	must.NotNil(p.goproxy)

	// Verify the proxy is initialized (goproxy internals are private,
	// so we can only verify the proxy was created successfully)
	// Full TLS bumping functionality is tested in integration tests
}

// TestProxy_RequestCount verifies that RequestCount returns the current nextID value.
func TestProxy_RequestCount(t *testing.T) {
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}
	p := NewProxy(cfg, nil, nil, nil, nil)

	is.Equal(uint64(0), p.RequestCount(), "Initial RequestCount should be 0")

	// Simulate ID assignments
	p.nextID.Add(1)
	is.Equal(uint64(1), p.RequestCount(), "RequestCount should reflect nextID increments")

	p.nextID.Add(4)
	is.Equal(uint64(5), p.RequestCount(), "RequestCount should reflect multiple increments")
}

// TestProxy_RateLimitedCount_NoRateLimiter verifies RateLimitedCount returns 0 when no rate limiter is configured.
func TestProxy_RateLimitedCount_NoRateLimiter(t *testing.T) {
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
		GlobalRateLimit:   0, // disabled
	}
	p := NewProxy(cfg, nil, nil, nil, nil)

	is.Equal(0, p.RateLimitedCount(), "RateLimitedCount should be 0 when rate limiter is disabled")
	is.Nil(p.globalRL, "globalRL should be nil when rate limiting is disabled")
}

// TestProxy_RateLimitedCount_WithRateLimiter verifies RateLimitedCount delegates to the limiter.
func TestProxy_RateLimitedCount_WithRateLimiter(t *testing.T) {
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
		GlobalRateLimit:   60, // 1 req/sec interval
	}
	p := NewProxy(cfg, nil, nil, nil, nil)

	is.NotNil(p.globalRL, "globalRL should be set when rate limiting is enabled")
	is.Equal(0, p.RateLimitedCount(), "RateLimitedCount should be 0 with empty store")
}

// TestProxy_PendingCount_NoWhitelist verifies the queue is created even when
// no whitelist is configured, registering holdPending as the catch-all handler.
func TestProxy_PendingCount_NoWhitelist(t *testing.T) {
	is := assert.New(t)

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
	}
	p := NewProxy(cfg, nil, nil, nil, nil)

	is.NotNil(p.queue, "queue must always be created, even with no whitelist")
	is.Equal(0, p.PendingCount(), "PendingCount must be 0 for an empty queue")
}

// TestProxy_PendingCount_ZeroTimeout verifies that PendingCount returns 0 for
// an empty queue even when PendingTimeout is zero (immediate-rejection mode).
// The queue is always created; timeout=0 means instant rejection, not disabled.
func TestProxy_PendingCount_ZeroTimeout(t *testing.T) {
	is := assert.New(t)

	wl := reqrules.New()
	wl.Add(reqrules.Rule{ID: "allow", Scheme: "https", Host: "example.com"})

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
		PendingTimeout:    0, // immediate rejection mode
	}
	p := NewProxy(cfg, nil, nil, nil, wl)

	is.NotNil(p.queue, "queue must always be created (timeout=0 means instant rejection, not disabled)")
	is.Equal(0, p.PendingCount(), "PendingCount must be 0 for an empty queue")
}

// TestProxy_PendingCount_WithQueue verifies PendingCount returns 0 for an empty
// queue when both whitelist and PendingTimeout are configured.
func TestProxy_PendingCount_WithQueue(t *testing.T) {
	is := assert.New(t)

	wl := reqrules.New()
	wl.Add(reqrules.Rule{ID: "allow", Scheme: "https", Host: "example.com"})

	cfg := &Config{
		Listen:            ":8080",
		ConnectionTimeout: 30 * time.Second,
		RequestTimeout:    300 * time.Second,
		PendingTimeout:    120 * time.Second,
	}
	p := NewProxy(cfg, nil, nil, nil, wl)

	is.NotNil(p.queue, "queue must be non-nil when whitelist and PendingTimeout are set")
	is.Equal(0, p.PendingCount(), "PendingCount must be 0 for an empty queue")
}
