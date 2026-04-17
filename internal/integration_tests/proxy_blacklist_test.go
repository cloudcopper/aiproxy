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

// TestProxy_Integration_BlacklistBlocking verifies that the blacklist feature
// works end-to-end from the public API perspective.
//
// Covers:
//   - Blocked URL returns 403 Forbidden with correct JSON body
//   - Non-blocked URL passes through and receives backend response
//   - Blacklist rejection is immediate (no artificial delay)
func TestProxy_Integration_BlacklistBlocking(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	// Backend whose URL will be added to the blacklist.
	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach client"))
	}))
	defer blockedBackend.Close()

	// Backend that is NOT in the blacklist.
	allowedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))
	defer allowedBackend.Close()

	// Build blacklist from public API only.
	bl := reqrules.New()
	bl.Add(ruleFromServer(t, "block-backend", "", blockedBackend.URL))

	// Whitelist allows allowedBackend; blockedBackend is caught by blacklist first.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", allowedBackend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
		DisableLocalhostBlocking: true, // Allow httptest servers on 127.0.0.1
	}
	p := proxy.NewProxy(cfg, nil, nil, bl, wl)

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

	t.Run("blocked URL returns 403", func(t *testing.T) {
		start := time.Now()
		resp, err := client.Get(blockedBackend.URL + "/")
		elapsed := time.Since(start)

		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)

		var errResp map[string]string
		must.NoError(json.Unmarshal(body, &errResp))
		is.Equal("forbidden", errResp["error"])
		is.Equal("blacklisted", errResp["reason"])
		is.Contains(errResp["request_id"], "req_")

		// Rejection must be immediate (no artificial sleep).
		is.Less(elapsed, 500*time.Millisecond, "blacklist rejection should be immediate")
	})

	t.Run("allowed URL passes through", func(t *testing.T) {
		resp, err := client.Get(allowedBackend.URL + "/")
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		must.NoError(err)
		is.Equal("allowed", string(body))
	})
}

// TestProxy_Integration_BlacklistMethodRule verifies that method-specific
// blacklist rules block only the specified HTTP method.
func TestProxy_Integration_BlacklistMethodRule(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	// Block only DELETE requests to the backend.
	bl := reqrules.New()
	bl.Add(ruleFromServer(t, "block-delete", "DELETE", backend.URL))

	// Whitelist allows all non-DELETE methods; DELETE is caught by blacklist first.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-all-methods", "", backend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, bl, wl)

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

	t.Run("DELETE is blocked", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, backend.URL+"/resource", nil)
		must.NoError(err)

		resp, err := client.Do(req)
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		var errResp map[string]string
		must.NoError(json.Unmarshal(body, &errResp))
		is.Equal("forbidden", errResp["error"])
	})

	t.Run("GET is allowed", func(t *testing.T) {
		resp, err := client.Get(backend.URL + "/resource")
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)
	})

	t.Run("POST is allowed", func(t *testing.T) {
		resp, err := client.Post(backend.URL+"/resource", "application/json", nil)
		must.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)
	})
}

// TestProxy_Integration_BlacklistNil verifies that a nil blacklist
// does not block any requests (whitelisted requests still pass through).
func TestProxy_Integration_BlacklistNil(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer backend.Close()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, nil, wl) // nil blacklist

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

	resp, err := client.Get(backend.URL + "/")
	must.NoError(err)
	defer resp.Body.Close()

	is.Equal(http.StatusOK, resp.StatusCode)
}

// TestProxy_Integration_BlacklistRequestID verifies that the request_id field
// in the 403 response is a non-empty string of the form "req_N" and that
// successive blocked requests receive unique, incrementing IDs.
func TestProxy_Integration_BlacklistRequestID(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bl := reqrules.New()
	bl.Add(ruleFromServer(t, "block-backend", "", backend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, bl, nil)

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
func TestProxy_Integration_BlacklistEmpty(t *testing.T) {
	defer goleak.VerifyNone(t)

	must := require.New(t)
	is := assert.New(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response"))
	}))
	defer backend.Close()

	// Empty blacklist — no rules loaded.
	bl := reqrules.New()

	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-backend", "", backend.URL))

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0,
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, bl, wl)

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

	resp, err := client.Get(backend.URL + "/")
	must.NoError(err)
	defer resp.Body.Close()

	is.Equal(http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	must.NoError(err)
	is.Equal("response", string(body))
}
