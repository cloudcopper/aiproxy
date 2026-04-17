package proxy

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

// certValidatingRoundTripper wraps http.RoundTripper and intercepts certificate validation errors.
// Returns proper error responses instead of raw connection errors.
type certValidatingRoundTripper struct {
	transport http.RoundTripper
	proxy     *Proxy
}

// RoundTrip executes the HTTP request and intercepts certificate validation errors.
func (rt *certValidatingRoundTripper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
	// Execute the request through the underlying transport
	resp, err := rt.transport.RoundTrip(req)

	// Check for certificate validation errors
	if err != nil && isCertificateError(err) {
		id, _ := ctx.UserData.(RequestID)

		// Log certificate error at ERROR level with details for operator debugging
		slog.Error("upstream certificate validation failed",
			"request_id", id,
			"url", req.URL.String(),
			"error", err,
		)

		// Return 502 Bad Gateway with generic JSON error
		// Security: Do NOT expose certificate details to client
		return rt.proxy.errorResponse(req, http.StatusBadGateway, "bad_gateway", "upstream connection failed", id), nil
	}

	return resp, err
}

// isCertificateError checks if the error is a certificate validation error.
func isCertificateError(err error) bool {
	// Unwrap errors to find x509 certificate errors
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}

	// Check for common certificate error patterns in error string
	// This catches errors that don't use the typed CertificateVerificationError
	errStr := err.Error()
	return strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "tls:")
}

// tlsBumpConfig holds per-instance TLS bumping state.
// Created by newTLSBumpConfig to avoid mutating goproxy package-level globals,
// which would race when multiple Proxy instances exist (e.g., parallel tests).
type tlsBumpConfig struct {
	mitmConnect   *goproxy.ConnectAction
	rejectConnect *goproxy.ConnectAction
}

// newTLSBumpConfig creates per-instance ConnectAction values from the given CA.
// Unlike the old setCA(), this does NOT mutate any goproxy globals.
func newTLSBumpConfig(caCert *x509.Certificate, caKey crypto.PrivateKey) *tlsBumpConfig {
	tlsCert := tls.Certificate{
		Certificate: [][]byte{caCert.Raw},
		PrivateKey:  caKey,
		Leaf:        caCert,
	}

	tlsConfigFn := goproxy.TLSConfigFromCA(&tlsCert)

	return &tlsBumpConfig{
		mitmConnect:   &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsConfigFn},
		rejectConnect: &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: tlsConfigFn},
	}
}
