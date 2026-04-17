package handlers

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/cloudcopper/aiproxy/internal/pending"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
)

// PendingSource provides live pending request data to the WebUI.
// Defined on the consumer side (handlers) so the proxy package has no
// dependency on webui. handlers imports internal/pending directly — no
// import cycle: pending → nothing; proxy → pending; handlers → pending.
type PendingSource interface {
	PendingItems() []*pending.Entry
	// ReevaluatePending re-checks all active pending entries against the
	// current whitelist and blacklist and resolves any that now have a
	// matching rule. Must be called after adding a rule to either store.
	ReevaluatePending()
}

// PendingConfig holds dependencies for the pending page and SSE handlers.
type PendingConfig struct {
	Source      PendingSource
	Nav         templates.NavData
	SSEInterval time.Duration // defaults to 1s if zero
}

func (c *PendingConfig) sseInterval() time.Duration {
	if c.SSEInterval > 0 {
		return c.SSEInterval
	}
	return 1 * time.Second
}

// buildPendingItems converts pending.Entry snapshots to template data,
// computing elapsed and remaining display strings.
func buildPendingItems(src PendingSource) []templates.PendingItemData {
	items := src.PendingItems()
	if len(items) == 0 {
		return []templates.PendingItemData{}
	}
	out := make([]templates.PendingItemData, len(items))
	for i, e := range items {
		elapsed := time.Since(e.Since).Truncate(time.Second)
		remaining := e.Timeout - time.Since(e.Since)

		var remainingStr string
		if remaining <= 0 {
			remainingStr = "expired"
		} else {
			remainingStr = remaining.Truncate(time.Second).String()
		}

		out[i] = templates.PendingItemData{
			Method:       e.Method,
			URL:          e.URL,
			WaitersCount: e.Waiters(),
			Elapsed:      elapsed.String(),
			Remaining:    remainingStr,
		}
	}
	return out
}

// --- Pending page (GET /pending) ---

type pendingPageHandler struct{ cfg *PendingConfig }

// NewPendingPageHandler returns an http.Handler for GET /pending.
// Must be wrapped with AuthMiddleware.
func NewPendingPageHandler(cfg *PendingConfig) http.Handler { return &pendingPageHandler{cfg: cfg} }

func (h *pendingPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data := templates.PendingData{
		Nav:   h.cfg.Nav,
		Items: buildPendingItems(h.cfg.Source),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.PendingPage(data).Render(r.Context(), w); err != nil {
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

// --- Pending SSE stream (GET /api/pending/stream) ---

type pendingSSEHandler struct{ cfg *PendingConfig }

// NewPendingSSEHandler returns an http.Handler for GET /api/pending/stream.
// Must be wrapped with AuthMiddleware.
func NewPendingSSEHandler(cfg *PendingConfig) http.Handler { return &pendingSSEHandler{cfg: cfg} }

func (h *pendingSSEHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	tick := time.NewTicker(h.cfg.sseInterval())
	defer tick.Stop()

	// Send an initial push immediately.
	h.sendRows(w, flusher, r)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			h.sendRows(w, flusher, r)
		}
	}
}

// sendRows renders PendingRowsFragment and sends it as an unnamed SSE message.
func (h *pendingSSEHandler) sendRows(w http.ResponseWriter, flusher http.Flusher, r *http.Request) {
	items := buildPendingItems(h.cfg.Source)

	var buf bytes.Buffer
	if err := templates.PendingRowsFragment(items).Render(r.Context(), &buf); err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", sseData(buf.String()))
	flusher.Flush()
}
