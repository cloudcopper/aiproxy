//go:build integration

package integration_tests

// TestProxy_RuntimeRules_AddedAfterStartup is the regression test for the bug
// where blockBlacklist and allowWhitelist were only registered in goproxy's
// handler chain when the corresponding store was non-empty at startup.
//
// Consequence of the bug: rules added via the WebUI (which mutate the live
// *reqrules.ReqRules store) were silently ignored — requests continued going
// to the pending queue regardless of matching rules.
//
// The fix: always register both handlers unconditionally. Both already handle
// an empty store correctly (Match returns no match → pass-through / holdPending).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestProxy_RuntimeRules_AddedAfterStartup(t *testing.T) {
	defer goleak.VerifyNone(t)

	const (
		pendingTimeout = 200 * time.Millisecond
		// Blacklist rejection is immediate; allow generous margin for CI load.
		fastThreshold = 100 * time.Millisecond
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start proxy with completely empty stores and a short pending timeout so
	// we can distinguish "went to pending" (slow) from "matched a rule" (fast).
	bl := reqrules.New()
	wl := reqrules.New()
	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           pendingTimeout,
		DisableLocalhostBlocking: true, // allow httptest servers on 127.0.0.1
	}
	p := proxy.NewProxy(cfg, nil, nil, bl, wl)
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	require.NoError(t, err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}

	t.Run("blacklist rule added after startup blocks requests immediately", func(t *testing.T) {
		is := assert.New(t)
		must := require.New(t)

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer backend.Close()

		// Before rule: request is unclassified → pending → 403 after pendingTimeout.
		start := time.Now()
		resp, err := client.Get(backend.URL + "/probe")
		elapsed := time.Since(start)
		must.NoError(err)
		resp.Body.Close()
		is.Equal(http.StatusForbidden, resp.StatusCode, "unclassified request must be rejected")
		is.GreaterOrEqual(elapsed, pendingTimeout,
			"pending rejection must not arrive before the pending timeout elapses")

		// Add a blacklist rule targeting this backend — simulates WebUI POST /api/rules/blacklist.
		p.Blacklist().Add(ruleFromServer(t, "block-backend", "GET", backend.URL))

		// After rule: same request is matched by blacklist → 403 immediately (no pending wait).
		start = time.Now()
		resp, err = client.Get(backend.URL + "/probe")
		elapsed = time.Since(start)
		must.NoError(err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		is.Equal(http.StatusForbidden, resp.StatusCode, "blacklisted request must be rejected")
		is.Less(elapsed, fastThreshold,
			"blacklist rejection must be immediate, not wait for pending timeout (%s elapsed, want < %s)",
			elapsed, fastThreshold)
		_ = body // JSON error body; content verified in unit tests
	})

	t.Run("whitelist rule added after startup allows requests", func(t *testing.T) {
		is := assert.New(t)
		must := require.New(t)

		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello")) //nolint:errcheck
		}))
		defer backend.Close()

		// Before rule: unclassified → pending → 403.
		resp, err := client.Get(backend.URL + "/probe")
		must.NoError(err)
		resp.Body.Close()
		is.Equal(http.StatusForbidden, resp.StatusCode, "unclassified request must be rejected before whitelist rule added")

		// Add a whitelist rule — simulates WebUI POST /api/rules/whitelist.
		p.Whitelist().Add(ruleFromServer(t, "allow-backend", "GET", backend.URL))

		// After rule: request is matched by whitelist → forwarded → 200 OK.
		resp, err = client.Get(backend.URL + "/probe")
		must.NoError(err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		is.Equal(http.StatusOK, resp.StatusCode, "whitelisted request must be forwarded to backend")
		is.Equal("hello", string(body))
	})
}
