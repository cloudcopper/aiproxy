package proxy

import (
	"log/slog"
	"net/http"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/elazarl/goproxy"
)

// blockBlacklist is a goproxy OnRequest handler that rejects requests matching
// the configured blacklist rules.
//
// Request flow position:
//   - Runs AFTER localhost blocker (SSRF protection checks first)
//   - Runs BEFORE global rate limiter (no point rate-limiting blocked requests)
//
// On match:
//   - Returns HTTP 403 Forbidden immediately (no delay — blacklist is explicit
//     policy, not attack detection like the SSRF or CONNECT blockers)
//   - JSON body: {"error":"forbidden","reason":"blacklisted","request_id":"req_N"}
//   - Logs at WARN level: security-relevant but expected behavior
//
// On no match:
//   - Returns (req, nil), passing the request to the next handler.
//
// TODO: when access logging is implemented, record "blocked_blacklist" action.
func (p *Proxy) blockBlacklist(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// RequestID is set by onRequest (which runs before every other handler).
	id, _ := ctx.UserData.(RequestID)

	if matchedRule, matched := p.blacklist.Match(req); matched {
		slog.Warn("request blocked by blacklist",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"matched_rule", matchedRule.ID,
			"remote_addr", req.RemoteAddr,
		)

		return req, p.errorResponse(req, http.StatusForbidden, "forbidden", "blacklisted", id)
	}

	return req, nil
}

// Blacklist returns the live merged blacklist rule store.
// The returned *reqrules.ReqRules is the same instance used for request
// matching — mutations are reflected immediately in proxy decisions.
func (p *Proxy) Blacklist() *reqrules.ReqRules {
	return p.blacklist
}
