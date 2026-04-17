package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/elazarl/goproxy"
)

// onRequest handles incoming HTTP requests through the proxy.
// Logs request details at INFO level.
// Returns the unmodified request and nil response to continue proxying.
func (p *Proxy) onRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	id := RequestID(p.nextID.Add(1))
	ctx.UserData = id

	slog.Info("request",
		"request_id", id,
		"method", req.Method,
		"url", req.URL.String(),
		"remote_addr", req.RemoteAddr,
	)

	return req, nil
}

// onResponse handles responses received from upstream servers.
// Logs response details at DEBUG level.
// Handles upstream connection errors (including certificate validation failures).
// Returns the unmodified response or a 502 Bad Gateway error response.
func (p *Proxy) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	id, _ := ctx.UserData.(RequestID)

	// Check for upstream connection errors (including certificate validation failures)
	if ctx.Error != nil {
		slog.Error("upstream connection error",
			"request_id", id,
			"url", ctx.Req.URL.String(),
			"error", ctx.Error,
		)

		// Return 502 Bad Gateway with generic JSON error
		// Security: Do NOT expose certificate details to client (prevents info disclosure)
		return p.errorResponse(ctx.Req, http.StatusBadGateway, "bad_gateway", "upstream connection failed", id)
	}

	if resp != nil {
		// TODO Shall we generate error on resp.StatusCode >= 400?
		slog.Debug("response",
			"request_id", id,
			"url", ctx.Req.URL.String(),
			"status", resp.StatusCode,
		)
	}

	return resp
}

// errorResponse creates a JSON error response.
// Used for returning standardized error responses to clients.
func (p *Proxy) errorResponse(req *http.Request, statusCode int, errorType, reason string, requestID RequestID) *http.Response {
	// Create JSON error response body
	errorBody := map[string]string{
		"error":      errorType,
		"reason":     reason,
		"request_id": requestID.String(),
	}

	bodyJSON, err := json.Marshal(errorBody)
	if err != nil {
		// Fallback to plain text if JSON marshaling fails
		slog.Error("failed to marshal error response", "error", err)
		return goproxy.NewResponse(req, "text/plain", statusCode, "Internal Server Error")
	}

	return goproxy.NewResponse(req, "application/json", statusCode, string(bodyJSON))
}
