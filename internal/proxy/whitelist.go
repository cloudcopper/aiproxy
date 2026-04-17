package proxy

import (
	"log/slog"
	"net/http"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/elazarl/goproxy"
)

// allowWhitelist is a goproxy OnRequest handler that allows requests matching
// the configured whitelist rules.
//
// On match: returns (req, nil) to forward to upstream.
// On no match: calls holdPending — which blocks until the pending timeout fires
// then returns HTTP 403 (reason: "blacklisted"). There is no immediate
// "not_whitelisted" rejection path; all unclassified requests go through
// the pending queue.
func (p *Proxy) allowWhitelist(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	id, _ := ctx.UserData.(RequestID)

	if matchedRule, matched := p.whitelist.Match(req); matched {
		slog.Debug("request allowed by whitelist",
			"request_id", id,
			"method", req.Method,
			"url", req.URL.String(),
			"matched_rule", matchedRule.ID,
		)
		return req, nil
	}

	// No whitelist match — send to pending queue.
	return p.holdPending(req, ctx)
}

// Whitelist returns the live merged whitelist rule store.
// The returned *reqrules.ReqRules is the same instance used for request
// matching — mutations are reflected immediately in proxy decisions.
func (p *Proxy) Whitelist() *reqrules.ReqRules {
	return p.whitelist
}
