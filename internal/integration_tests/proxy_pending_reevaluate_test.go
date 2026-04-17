//go:build integration

package integration_tests

// TestProxy_PendingApprovedByWhitelist and TestProxy_PendingDeniedByBlacklist
// verify that adding a rule to the whitelist or blacklist at runtime immediately
// resolves all matching pending requests, without waiting for the pending timeout.
//
// These tests exercise the re-evaluation mechanism described in IDEA.md
// decisions D-REEVALUATE-1 through D-REEVALUATE-10.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// reevaluatePendingTimeout is generous enough to survive CI load while still
// being short enough that the test doesn't stall when things go wrong.
const reevaluatePendingTimeout = 2 * time.Second

// TestProxy_PendingApprovedByWhitelist verifies that:
//   - An unknown request is held in the pending queue.
//   - Adding a matching whitelist rule and calling ReevaluatePending() unblocks
//     the request immediately and forwards it to the backend (HTTP 200).
//   - The pending queue is empty after resolution.
func TestProxy_PendingApprovedByWhitelist(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Backend that the client wants to reach.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from backend"))
	}))
	defer backend.Close()

	// Proxy starts with no rules at all — every request goes to pending.
	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           30 * time.Second,
		PendingTimeout:           reevaluatePendingTimeout,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	must.NoError(err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}

	// Launch the client request in the background — it will block in pending.
	type clientResult struct {
		statusCode int
		body       string
		err        error
	}
	resultCh := make(chan clientResult, 1)
	go func() {
		c := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   reevaluatePendingTimeout + 5*time.Second,
		}
		resp, err := c.Get(backend.URL + "/hello")
		if err != nil {
			resultCh <- clientResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resultCh <- clientResult{statusCode: resp.StatusCode, body: string(body)}
	}()

	// Wait for the request to enter the pending queue.
	must.Eventually(func() bool {
		return p.PendingCount() == 1
	}, 500*time.Millisecond, 10*time.Millisecond,
		"request must enter the pending queue")

	is.Equal(1, p.PendingCount(), "exactly one entry in pending queue")

	// Add a whitelist rule that matches the backend, then re-evaluate.
	rule := ruleFromServer(t, "allow-backend", "GET", backend.URL)
	p.Whitelist().Add(rule)
	p.ReevaluatePending()

	// After ReevaluatePending the pending queue must be drained immediately.
	is.Equal(0, p.PendingCount(), "pending queue must be empty after ReevaluatePending")

	// The client request must complete successfully.
	select {
	case res := <-resultCh:
		must.NoError(res.err)
		is.Equal(http.StatusOK, res.statusCode, "approved request must reach the backend")
		is.Equal("hello from backend", res.body)
	case <-time.After(reevaluatePendingTimeout + 2*time.Second):
		t.Fatal("client request did not complete within the expected window")
	}
}

// TestProxy_PendingDeniedByBlacklist verifies that:
//   - An unknown request is held in the pending queue.
//   - Adding a matching blacklist rule and calling ReevaluatePending() immediately
//     rejects the request with HTTP 403 (reason: "blacklisted").
//   - The pending queue is empty after resolution.
func TestProxy_PendingDeniedByBlacklist(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Backend that the client wants to reach.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("should be blocked"))
	}))
	defer backend.Close()

	// Proxy starts with no rules at all — every request goes to pending.
	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           30 * time.Second,
		PendingTimeout:           reevaluatePendingTimeout,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	must.NoError(err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}

	// Launch the client request in the background — it will block in pending.
	type clientResult struct {
		statusCode int
		reason     string
		err        error
	}
	resultCh := make(chan clientResult, 1)
	go func() {
		c := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			Timeout:   reevaluatePendingTimeout + 5*time.Second,
		}
		resp, err := c.Get(backend.URL + "/secret")
		if err != nil {
			resultCh <- clientResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var errResp map[string]string
		_ = json.Unmarshal(body, &errResp)
		resultCh <- clientResult{statusCode: resp.StatusCode, reason: errResp["reason"]}
	}()

	// Wait for the request to enter the pending queue.
	must.Eventually(func() bool {
		return p.PendingCount() == 1
	}, 500*time.Millisecond, 10*time.Millisecond,
		"request must enter the pending queue")

	is.Equal(1, p.PendingCount(), "exactly one entry in pending queue")

	// Add a blacklist rule that matches the backend, then re-evaluate.
	rule := ruleFromServer(t, "block-backend", "GET", backend.URL)
	p.Blacklist().Add(rule)
	p.ReevaluatePending()

	// After ReevaluatePending the pending queue must be drained immediately.
	is.Equal(0, p.PendingCount(), "pending queue must be empty after ReevaluatePending")

	// The client request must be rejected with HTTP 403 / reason: "blacklisted".
	select {
	case res := <-resultCh:
		must.NoError(res.err)
		is.Equal(http.StatusForbidden, res.statusCode, "denied request must be rejected")
		is.Equal("blacklisted", res.reason, "denial reason must be 'blacklisted'")
	case <-time.After(reevaluatePendingTimeout + 2*time.Second):
		t.Fatal("client request did not complete within the expected window")
	}
}


