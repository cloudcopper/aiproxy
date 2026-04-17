package proxy

import (
	"log/slog"
	"net"
	"net/http"

	"github.com/cloudcopper/aiproxy/internal/pending"
	"github.com/elazarl/goproxy"
)

// holdPending holds the request in the pending queue until it is resolved
// (approved, denied, or timed out), then returns an appropriate response.
//
// Resolution outcomes:
//   - ResolutionApproved → return (req, nil) so goproxy forwards the request
//   - ResolutionDenied or ResolutionTimeout → HTTP 403 (reason: blacklisted)
//   - ResolutionDisconnected → HTTP 403 (client already gone)
//
// Called by allowWhitelist when no whitelist rule matches.
// Blocks for up to --pending-timeout (default 120 s) unless resolved early.
func (p *Proxy) holdPending(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	id, _ := ctx.UserData.(RequestID)

	// Best-effort extraction of host IP for logging only; no error handling needed.
	clientIP, _, _ := net.SplitHostPort(req.RemoteAddr)
	if clientIP == "" {
		clientIP = req.RemoteAddr
	}

	slog.Info("request pending",
		"request_id", id,
		"method", req.Method,
		"url", req.URL.String(),
		"remote_addr", req.RemoteAddr,
	)

	// Blocks until the entry is resolved or the client disconnects.
	resolution := p.queue.Hold(req.Context(), req.Method, req.URL.String())

	switch resolution {
	case pending.ResolutionApproved:
		slog.Info("pending request approved by whitelist rule",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"client_ip", clientIP,
		)
		// Return (req, nil) so goproxy forwards the request to the upstream.
		return req, nil

	case pending.ResolutionDenied:
		slog.Warn("pending request denied by blacklist rule",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"client_ip", clientIP,
			"reason", "pending_denied",
		)

	case pending.ResolutionTimeout:
		slog.Warn("pending request timed out",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"client_ip", clientIP,
			"reason", "pending_timeout",
		)

	default: // ResolutionDisconnected
		slog.Debug("pending request: client disconnected",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
		)
	}

	// All non-approved resolutions result in the same HTTP 403 response body
	// as a blacklist rejection (Decision 60).
	return req, p.errorResponse(req, http.StatusForbidden, "forbidden", "blacklisted", id)
}

// PendingCount returns the number of requests currently held in the pending queue.
// Returns 0 when the pending queue is disabled.
func (p *Proxy) PendingCount() int {
	if p.queue == nil {
		return 0
	}
	return p.queue.ActiveCount()
}

// PendingItems returns a snapshot of all entries currently held in the
// pending queue. Satisfies handlers.PendingSource; used by the WebUI to
// display live pending request data. Returns nil when the queue is nil.
func (p *Proxy) PendingItems() []*pending.Entry {
	if p.queue == nil {
		return nil
	}
	return p.queue.ActiveEntries()
}

// ReevaluatePending checks all active pending entries against the current
// blacklist and whitelist and resolves any that now have a matching rule.
//
// Call this after adding a rule to either store so that pending requests
// matching the new rule are resolved immediately rather than waiting for
// their timeout to expire.
//
// Resolution order mirrors the request flow (IDEA.md §Request Flow):
//  1. Blacklist is checked first — matching entries are denied immediately.
//  2. Whitelist is checked second — matching entries are approved and forwarded.
//
// Entries that do not match any rule are left untouched.
func (p *Proxy) ReevaluatePending() {
	if p.queue == nil {
		return
	}
	entries := p.queue.ActiveEntries()
	for _, e := range entries {
		req, err := http.NewRequest(e.Method, e.URL, nil)
		if err != nil {
			// URL was already parsed when the original request arrived;
			// error here is highly unlikely — skip and leave the entry alone.
			continue
		}
		if _, matched := p.blacklist.Match(req); matched {
			p.queue.Resolve(e.Method, e.URL, pending.ResolutionDenied)
			continue
		}
		if _, matched := p.whitelist.Match(req); matched {
			p.queue.Resolve(e.Method, e.URL, pending.ResolutionApproved)
		}
	}
}
