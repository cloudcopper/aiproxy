package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
)

// blockConnectHandler returns a goproxy handler that blocks CONNECT requests.
// Prevents establishing arbitrary TCP tunnels through the proxy.
// Cannot be disabled in production (test-only override via Config.DisableConnectBlocking).
func (p *Proxy) blockConnectHandler() goproxy.HttpsHandler {
	return goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		// Extract RequestID from context (set by onRequest handler)
		// Note: For CONNECT requests, onRequest runs first, then this handler
		id, _ := ctx.UserData.(RequestID)

		// Log the blocked request at WARN level (security-relevant)
		slog.Warn("CONNECT request blocked (anti-tunneling protection)",
			"request_id", id,
			"method", "CONNECT",
			"host", host,
			"remote_addr", ctx.Req.RemoteAddr,
		)

		// Sleep to rate-limit scanner behavior
		time.Sleep(p.config.blockDelay())

		// Return reject action with error response
		ctx.Resp = p.errorResponse(ctx.Req, http.StatusForbidden, "connect_blocked", "CONNECT method is not allowed", id)
		// Use per-instance rejectConnect when TLS bumping is configured;
		// fall back to the goproxy global when it is not (plain-HTTP proxy mode).
		reject := goproxy.RejectConnect
		if p.tlsBump != nil {
			reject = p.tlsBump.rejectConnect
		}
		return reject, host
	})
}
