package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/pending"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPendingSource is a PendingSource returning a fixed entry list.
type stubPendingSource struct {
	items            []*pending.Entry
	reevaluateCalled int // counts ReevaluatePending calls for assertions
}

func (s *stubPendingSource) PendingItems() []*pending.Entry { return s.items }
func (s *stubPendingSource) ReevaluatePending()             { s.reevaluateCalled++ }

var _ PendingSource = (*stubPendingSource)(nil)
var testNav = templates.NavData{IsAuthenticated: true, AuthEnabled: true}

func newTestPendingConfig(items []*pending.Entry) *PendingConfig {
	return &PendingConfig{
		Source:      &stubPendingSource{items: items},
		Nav:         testNav,
		SSEInterval: 50 * time.Millisecond,
	}
}

// sseResult runs the SSE handler for a short duration and returns the captured body.
func sseResult(t *testing.T, h http.Handler, wait time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/pending/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(rec, req) }()
	time.Sleep(wait)
	cancel()
	<-done
	return rec.Body.String()
}

// --- buildPendingItems ---

func TestBuildPendingItems(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		items      []*pending.Entry
		wantLen    int
		wantEmpty  bool
		checkFirst func(t *testing.T, item templates.PendingItemData)
	}{
		{
			name:      "empty source returns empty slice",
			items:     nil,
			wantLen:   0,
			wantEmpty: true,
		},
		{
			name: "active item has correct fields and non-expired remaining",
			items: []*pending.Entry{
				{
					Method:  "GET",
					URL:     "https://api.example.com/v1/chat",
					Since:   time.Now().Add(-10 * time.Second),
					Timeout: 120 * time.Second,
				},
			},
			wantLen: 1,
			checkFirst: func(t *testing.T, item templates.PendingItemData) {
				t.Helper()
				is := assert.New(t)
				is.Equal("GET", item.Method)
				is.Equal("https://api.example.com/v1/chat", item.URL)
				is.Equal(0, item.WaitersCount) // zero: no goroutine is calling Hold on this stub entry
				is.Contains(item.Elapsed, "s")
				is.NotEqual("expired", item.Remaining)
			},
		},
		{
			name: "expired item shows 'expired' remaining",
			items: []*pending.Entry{
				{
					Method:  "POST",
					URL:     "https://api.example.com/v1",
					Since:   time.Now().Add(-200 * time.Second),
					Timeout: 120 * time.Second,
				},
			},
			wantLen: 1,
			checkFirst: func(t *testing.T, item templates.PendingItemData) {
				t.Helper()
				assert.Equal(t, "expired", item.Remaining)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			result := buildPendingItems(&stubPendingSource{items: tt.items})

			is.NotNil(result, "result must never be nil")
			is.Len(result, tt.wantLen)
			if tt.wantEmpty {
				is.Empty(result)
			}
			if tt.checkFirst != nil {
				must.Len(result, 1, "expected exactly one item for checkFirst")
				tt.checkFirst(t, result[0])
			}
		})
	}
}

// --- Pending page handler ---

func TestPendingPageHandler(t *testing.T) {
	t.Parallel()

	oneItem := []*pending.Entry{
		{Method: "GET", URL: "https://api.openai.com/v1/models", Since: time.Now(), Timeout: 120 * time.Second},
	}

	tests := []struct {
		name            string
		items           []*pending.Entry
		wantStatus      int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:       "empty queue: 200, html, no-requests message, table structure present",
			items:      nil,
			wantStatus: http.StatusOK,
			wantContains: []string{
				"text/html",           // checked via Content-Type below
				"No pending requests",
				"pending-rows",        // SSE target id
				"/api/pending/stream", // SSE connect URL
				"Method", "URL", "Waiters", "Elapsed", "Remaining",
			},
		},
		{
			name:       "with items: shows row content, hides no-requests message",
			items:      oneItem,
			wantStatus: http.StatusOK,
			wantContains:    []string{"api.openai.com"},
			wantNotContains: []string{"No pending requests"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			h := NewPendingPageHandler(newTestPendingConfig(tt.items))
			req := httptest.NewRequest(http.MethodGet, "/pending", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			is.Equal(tt.wantStatus, rec.Code)
			is.Contains(rec.Header().Get("Content-Type"), "text/html")
			body := rec.Body.String()
			for _, s := range tt.wantContains {
				if s == "text/html" {
					continue // already checked via Content-Type header
				}
				is.Contains(body, s)
			}
			for _, s := range tt.wantNotContains {
				is.NotContains(body, s)
			}
		})
	}
}

// --- Pending SSE handler ---

func TestPendingSSEHandler(t *testing.T) {
	t.Parallel()

	oneItem := []*pending.Entry{
		{Method: "GET", URL: "https://api.example.com/test", Since: time.Now(), Timeout: 120 * time.Second},
	}

	tests := []struct {
		name            string
		items           []*pending.Entry
		wantContentType string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:            "sets text/event-stream content type",
			items:           nil,
			wantContentType: "text/event-stream",
		},
		{
			name:         "empty queue sends no-requests message",
			items:        nil,
			wantContains: []string{"data:", "No pending requests"},
		},
		{
			name:         "with items sends row content",
			items:        oneItem,
			wantContains: []string{"api.example.com"},
		},
		{
			name:            "messages are unnamed (no event: line) for htmx v4 auto-swap",
			items:           nil,
			wantContains:    []string{"data:"},
			wantNotContains: []string{"event:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			cfg := newTestPendingConfig(tt.items)
			cfg.SSEInterval = 30 * time.Millisecond
			body := sseResult(t, NewPendingSSEHandler(cfg), 20*time.Millisecond)

			if tt.wantContentType != "" {
				// Content-Type is on the recorder — re-run just to grab headers.
				ctx, cancel := context.WithCancel(context.Background())
				req := httptest.NewRequest(http.MethodGet, "/api/pending/stream", nil).WithContext(ctx)
				rec := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); NewPendingSSEHandler(cfg).ServeHTTP(rec, req) }()
				time.Sleep(20 * time.Millisecond)
				cancel()
				<-done
				is.Equal(tt.wantContentType, rec.Header().Get("Content-Type"))
				return
			}
			for _, s := range tt.wantContains {
				is.Contains(body, s)
			}
			for _, s := range tt.wantNotContains {
				is.NotContains(body, s)
			}
		})
	}
}

func TestPendingSSEHandler_SendsMultipleMessages(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	cfg := newTestPendingConfig(nil)
	cfg.SSEInterval = 30 * time.Millisecond
	body := sseResult(t, NewPendingSSEHandler(cfg), 120*time.Millisecond)

	count := strings.Count(body, "data:")
	is.GreaterOrEqual(count, 2, "must send multiple SSE messages over time")
}
