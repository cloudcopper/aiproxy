//go:build integration

package integration_tests

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
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// TestProxy_Integration_WhitelistBlocking verifies that the whitelist feature
// works end-to-end from the public API perspective.
//
// Covers:
//   - Whitelisted URL passes through and receives backend response
//   - Non-whitelisted URL is sent to the pending queue and returns 403
//     with reason "blacklisted" (pending timeout = 0 → immediate rejection)
func TestProxy_Integration_WhitelistBlocking(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Backend whose URL will be added to the whitelist.
	whitelistedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("whitelisted"))
	}))
	defer whitelistedBackend.Close()

	// Backend that is NOT in the whitelist.
	notWhitelistedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach client"))
	}))
	defer notWhitelistedBackend.Close()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-whitelisted", "", whitelistedBackend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified requests
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

	t.Run("whitelisted URL returns 200", func(t *testing.T) {
		resp, err := client.Get(whitelistedBackend.URL + "/")
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)
		is.Equal("whitelisted", string(body))
	})

	t.Run("non-whitelisted URL returns 403 blacklisted (immediate)", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get(notWhitelistedBackend.URL + "/")
		elapsed := time.Since(start)
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errResp map[string]string
		must.NoError(json.Unmarshal(body, &errResp))
		is.Equal("forbidden", errResp["error"])
		// Non-whitelisted requests go through the pending queue; the response
		// is always "blacklisted" (same shape as blacklist + pending timeout).
		is.Equal("blacklisted", errResp["reason"])
		is.Contains(errResp["request_id"], "req_")

		// With PendingTimeout=0 the rejection must be immediate.
		is.Less(elapsed, 500*time.Millisecond, "pending timeout=0 rejection should be immediate")
	})
}

// TestProxy_Integration_WhitelistMethodRule verifies that method-specific
// whitelist rules allow only the specified HTTP method.
// Non-matching methods go to the pending queue (immediate rejection with timeout=0).
func TestProxy_Integration_WhitelistMethodRule(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	// Allow only PUT requests to the backend.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-put", "PUT", backend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
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

	t.Run("PUT is allowed", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPut, backend.URL+"/resource", nil)
		must.NoError(err)

		resp, err := client.Do(req)
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)
	})

	t.Run("GET is blocked (unclassified → pending → immediate)", func(t *testing.T) {
		resp, err := client.Get(backend.URL + "/resource")
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var errResp map[string]string
		must.NoError(json.Unmarshal(body, &errResp))
		is.Equal("forbidden", errResp["error"])
	})

	t.Run("POST is blocked (unclassified → pending → immediate)", func(t *testing.T) {
		resp, err := client.Post(backend.URL+"/resource", "application/json", nil)
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)
	})
}

// TestProxy_Integration_WhitelistEmpty verifies that an empty whitelist (no
// rules) causes all requests to be treated as unclassified and sent to the
// pending queue. With PendingTimeout=0 they are rejected immediately.
func TestProxy_Integration_WhitelistEmpty(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer backend.Close()

	// Empty whitelist — no rules. All requests are unclassified → pending queue.
	wl := reqrules.New()

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
	resp, err := client.Get(backend.URL + "/")
	elapsed := time.Since(start)
	must.NoError(err)
	defer resp.Body.Close()

	// Empty whitelist → no rule matches → pending queue → immediate rejection.
	is.Equal(http.StatusForbidden, resp.StatusCode)
	is.Less(elapsed, 500*time.Millisecond, "immediate rejection must be fast")

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]string
	must.NoError(json.Unmarshal(body, &errResp))
	is.Equal("blacklisted", errResp["reason"])
}

// TestProxy_Integration_WhitelistRequestID verifies that the request_id field
// in the 403 response is a non-empty string of the form "req_N" and that
// successive blocked requests receive unique, incrementing IDs.
func TestProxy_Integration_WhitelistRequestID(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	// Non-empty whitelist — requests NOT matching are unclassified → pending queue.
	wl := reqrules.New()
	wl.Add(reqrules.Rule{ID: "allow-other", Scheme: "http", Host: "other.example.com"})

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
		Timeout:   5 * time.Second,
	}

	var ids []string
	for i := 0; i < 3; i++ {
		resp, err := client.Get(backend.URL + "/")
		must.NoError(err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		var errResp map[string]string
		must.NoError(json.Unmarshal(body, &errResp))

		id := errResp["request_id"]
		is.NotEmpty(id, "request_id must be present")
		is.Contains(id, "req_", "request_id should follow req_N format")
		ids = append(ids, id)
	}

	// All request IDs must be unique (sequential counter).
	is.NotEqual(ids[0], ids[1])
	is.NotEqual(ids[1], ids[2])
}

// TestProxy_Integration_WhitelistNil verifies that a nil whitelist behaves
// identically to an empty whitelist: all requests are unclassified and go to
// the pending queue (immediate rejection with PendingTimeout=0).
func TestProxy_Integration_WhitelistNil(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach client"))
	}))
	defer backend.Close()

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, nil) // nil whitelist

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
	resp, err := client.Get(backend.URL + "/")
	elapsed := time.Since(start)
	must.NoError(err)
	defer resp.Body.Close()

	// Nil whitelist → catch-all holdPending → immediate rejection.
	is.Equal(http.StatusForbidden, resp.StatusCode)
	is.Less(elapsed, 500*time.Millisecond, "immediate rejection must be fast")

	body, _ := io.ReadAll(resp.Body)
	var errResp map[string]string
	must.NoError(json.Unmarshal(body, &errResp))
	is.Equal("blacklisted", errResp["reason"])
}
