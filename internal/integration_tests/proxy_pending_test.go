//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// pendingTimeout is a short timeout used throughout pending queue integration
// tests. Short enough to keep the test suite fast; long enough to avoid races
// on loaded CI machines.
const pendingTimeout = 300 * time.Millisecond

// TestProxy_Integration_PendingTimeout verifies end-to-end that an unknown
// request (not matched by any whitelist rule) is held for the configured
// pending timeout and then rejected with the same HTTP 403 response shape as a
// blacklist hit (reason: "blacklisted").
//
// Covers:
//   - Request held for approximately --pending-timeout before response is sent
//   - Response is HTTP 403 with error="forbidden" and reason="blacklisted"
//   - request_id field is present
func TestProxy_Integration_PendingTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Backend whose URL is in the whitelist — used only to make the whitelist
	// non-empty so the pending queue is activated.
	allowedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer allowedBackend.Close()

	// Backend that is NOT in the whitelist — requests to it go to pending queue.
	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // never reached through proxy
	}))
	defer blockedBackend.Close()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-allowed", "", allowedBackend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           pendingTimeout,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, wl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	must.NoError(err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(blockedBackend.URL + "/some/path")
	elapsed := time.Since(start)
	must.NoError(err)
	defer resp.Body.Close()

	// Timing: request must be held for at least the pending timeout.
	is.GreaterOrEqual(elapsed, pendingTimeout,
		"request must be held for the full pending timeout before rejection")
	// Sanity upper bound — should not take much longer than the timeout.
	is.Less(elapsed, pendingTimeout+2*time.Second,
		"request must not be held significantly longer than the pending timeout")

	// Status code.
	is.Equal(http.StatusForbidden, resp.StatusCode)

	// Response body matches blacklist rejection shape (Decision 60).
	body, err := io.ReadAll(resp.Body)
	must.NoError(err)

	var errResp map[string]string
	must.NoError(json.Unmarshal(body, &errResp), "response body must be valid JSON")

	is.Equal("forbidden", errResp["error"])
	is.Equal("blacklisted", errResp["reason"],
		"pending timeout response must match blacklist rejection (reason: blacklisted)")
	is.Contains(errResp["request_id"], "req_", "request_id must be present")
}

// TestProxy_Integration_PendingDedup verifies that two concurrent requests for
// the same (method, url) share a single queue entry (deduplication) and that
// both receive the 403 response when the shared entry times out.
//
// Covers:
//   - PendingCount returns 1 (not 2) while two identical requests are pending
//   - Both requests unblock simultaneously and receive HTTP 403 / blacklisted
func TestProxy_Integration_PendingDedup(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	allowedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer allowedBackend.Close()

	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer blockedBackend.Close()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-allowed", "", allowedBackend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           pendingTimeout,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, wl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	must.NoError(err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}

	type result struct {
		status int
		reason string
	}
	results := make([]result, 2)
	var wg sync.WaitGroup

	for i := range 2 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine uses its own HTTP client with its own transport to
			// ensure two independent connections are made to the proxy.
			c := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
				Timeout:   5 * time.Second,
			}
			resp, err := c.Get(blockedBackend.URL + "/shared/path")
			if err != nil {
				return
			}
			defer resp.Body.Close()
			results[idx].status = resp.StatusCode
			body, _ := io.ReadAll(resp.Body)
			var errResp map[string]string
			if json.Unmarshal(body, &errResp) == nil {
				results[idx].reason = errResp["reason"]
			}
		}(i)
	}

	// Wait long enough for both requests to arrive at the proxy and enter the
	// pending queue, then check that deduplication has merged them into one entry.
	time.Sleep(pendingTimeout / 3)
	is.Equal(1, p.PendingCount(),
		"dedup: two identical pending requests must share one queue entry")

	// Wait for both requests to complete (pending timeout fires).
	wg.Wait()

	is.Equal(http.StatusForbidden, results[0].status)
	is.Equal(http.StatusForbidden, results[1].status)
	is.Equal("blacklisted", results[0].reason)
	is.Equal("blacklisted", results[1].reason)
	is.Equal(0, p.PendingCount(), "queue must be empty after timeout")
}

// TestProxy_Integration_PendingImmediate verifies that when PendingTimeout is
// zero the pending queue rejects requests immediately (no wait) with the same
// HTTP 403 / reason:"blacklisted" response as a timeout expiry.
// This replaces the old "disabled" semantics: timeout=0 is NOT pass-through.
func TestProxy_Integration_PendingImmediate(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	allowedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer allowedBackend.Close()

	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer blockedBackend.Close()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-allowed", "", allowedBackend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, wl)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	must.NoError(err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   2 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(blockedBackend.URL + "/")
	elapsed := time.Since(start)
	must.NoError(err)
	defer resp.Body.Close()

	// Rejection must be immediate — no hold.
	is.Less(elapsed, 500*time.Millisecond,
		"pending timeout=0 must reject immediately (no wait)")
	is.Equal(http.StatusForbidden, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]string
	must.NoError(json.Unmarshal(body, &errResp))
	is.Equal("blacklisted", errResp["reason"],
		"pending timeout=0 must return blacklisted (same shape as timeout expiry, not not_whitelisted)")
}
