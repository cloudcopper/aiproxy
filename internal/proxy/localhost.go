package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
)

// blockLocalhost is a handler that blocks requests targeting localhost IPs.
// Prevents SSRF attacks by rejecting requests to 127.0.0.0/8 or ::1.
func (p *Proxy) blockLocalhost(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Extract RequestID from context (set by onRequest handler)
	id, _ := ctx.UserData.(RequestID)

	// Check if request targets localhost IP
	if isLocalhostTarget(req) {
		// Log the blocked request at ERROR level (potential SSRF attempt)
		slog.Error("localhost request blocked (SSRF protection)",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"host", req.URL.Host,
			"remote_addr", req.RemoteAddr,
		)

		// Sleep to rate-limit scanner behavior
		time.Sleep(p.config.blockDelay())

		// Return 403 Forbidden with JSON error
		return req, p.errorResponse(req, http.StatusForbidden, "localhost_blocked", "requests to localhost are not allowed", id)
	}

	// Pass through to next handler
	return req, nil
}

// isLocalhostTarget checks if the request targets a localhost IP address.
// Returns true if the host resolves to 127.0.0.0/8 (IPv4) or ::1 (IPv6).
func isLocalhostTarget(req *http.Request) bool {
	host := req.URL.Hostname()

	// Empty host should not happen in valid requests, but handle defensively
	if host == "" {
		return false
	}

	// Resolve hostname to IP addresses
	// Note: This performs DNS resolution, which may block briefly
	ips, err := net.LookupIP(host)
	if err != nil {
		// DNS resolution failed - allow the request to proceed
		// The upstream connection will fail with a proper error
		slog.Debug("dns resolution failed for localhost check",
			"host", host,
			"error", err,
		)
		return false
	}

	// Check each resolved IP
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
	}

	return false
}
