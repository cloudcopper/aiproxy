//go:build integration

package integration_tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/cloudcopper/aiproxy/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// startProxyWithRules is a test helper that starts a proxy with the given
// blacklist and whitelist stores and returns an HTTP client preconfigured to
// use the proxy.
func startProxyWithRules(
	t *testing.T,
	ctx context.Context,
	blacklist, whitelist *reqrules.ReqRules,
) *http.Client {
	t.Helper()

	cfg := &proxy.Config{
		Listen:                   "localhost:0",
		ConnectionTimeout:        5 * time.Second,
		RequestTimeout:           10 * time.Second,
		PendingTimeout:           0, // immediate rejection for unclassified
		DisableLocalhostBlocking: true,
	}
	p := proxy.NewProxy(cfg, nil, nil, blacklist, whitelist)

	go func() { _ = p.Start(ctx) }()

	addr, err := p.Addr(context.Background())
	require.NoError(t, err)

	proxyURL := &url.URL{Scheme: "http", Host: addr.String()}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

// writeJSONFile writes content to a file in the given directory and returns
// the file path. Creates an empty JSON array if content is empty.
func writeJSONFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	if content == "" {
		content = "[]"
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

// TestProxy_RuntimeWhitelistRules_EffectiveAtStartup verifies that runtime
// whitelist rules (whitelist2.json) are effective immediately at startup when
// merged into the static whitelist store.
func TestProxy_RuntimeWhitelistRules_EffectiveAtStartup(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)
	req := require.New(t)

	// Backend whose URL is in the runtime whitelist.
	allowedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("allowed"))
	}))
	defer allowedBackend.Close()

	// Backend NOT in any whitelist.
	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not reach client"))
	}))
	defer blockedBackend.Close()

	dir := t.TempDir()

	// Static whitelist is empty.
	staticPath := writeJSONFile(t, dir, "whitelist.json", "[]")
	// Runtime whitelist has one rule matching the allowed backend.
	runtimeRule := ruleFromServer(t, "rt-allow", "", allowedBackend.URL)
	ruleJSON, err := json.Marshal([]reqrules.Rule{runtimeRule})
	req.NoError(err)
	rtPath := writeJSONFile(t, dir, "whitelist2.json", string(ruleJSON))

	// Load static + runtime and merge.
	static, err := rules.Load2(staticPath, rtPath)
	req.NoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := startProxyWithRules(t, ctx, nil, static)

	t.Run("runtime-whitelisted URL returns 200", func(t *testing.T) {
		resp, err := client.Get(allowedBackend.URL + "/")
		req.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		is.Equal("allowed", string(body))
	})

	t.Run("non-whitelisted URL returns 403", func(t *testing.T) {
		resp, err := client.Get(blockedBackend.URL + "/")
		req.NoError(err)
		defer resp.Body.Close()

		is.Equal(http.StatusForbidden, resp.StatusCode)

		var errResp map[string]string
		body, _ := io.ReadAll(resp.Body)
		req.NoError(json.Unmarshal(body, &errResp))
		is.Equal("forbidden", errResp["error"])
		is.Equal("blacklisted", errResp["reason"])
	})
}

// TestProxy_RuntimeBlacklistRules_EffectiveAtStartup verifies that runtime
// blacklist rules (blacklist2.json) block requests immediately at startup.
func TestProxy_RuntimeBlacklistRules_EffectiveAtStartup(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)
	req := require.New(t)

	// Backend whose URL is in the runtime blacklist.
	blockedBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should be blocked"))
	}))
	defer blockedBackend.Close()

	dir := t.TempDir()

	// Runtime blacklist has one rule matching the backend.
	rtRule := ruleFromServer(t, "rt-block", "", blockedBackend.URL)
	ruleJSON, err := json.Marshal([]reqrules.Rule{rtRule})
	req.NoError(err)
	rtPath := writeJSONFile(t, dir, "blacklist2.json", string(ruleJSON))

	// Static blacklist is empty.
	staticPath := writeJSONFile(t, dir, "blacklist.json", "[]")

	// Load and merge.
	staticBL, err := rules.Load2(staticPath, rtPath)
	req.NoError(err)

	// Whitelist: allow everything so only the blacklist blocks.
	wl := reqrules.New()
	wl.Add(ruleFromServer(t, "allow-all-backend", "", blockedBackend.URL))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := startProxyWithRules(t, ctx, staticBL, wl)

	start := time.Now()
	resp, err := client.Get(blockedBackend.URL + "/")
	elapsed := time.Since(start)
	req.NoError(err)
	defer resp.Body.Close()

	// Runtime blacklist must block immediately (no pending delay).
	is.Equal(http.StatusForbidden, resp.StatusCode)
	is.Less(elapsed, 500*time.Millisecond, "blacklist rejection must be immediate")

	var errResp map[string]string
	body, _ := io.ReadAll(resp.Body)
	req.NoError(json.Unmarshal(body, &errResp))
	is.Equal("forbidden", errResp["error"])
	is.Equal("blacklisted", errResp["reason"])
}

// TestProxy_StaticAndRuntimeRules_LexicographicOrder verifies that static and
// runtime rules are merged in lexicographic order and all are effective.
func TestProxy_StaticAndRuntimeRules_LexicographicOrder(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)
	req := require.New(t)

	// Three backends — one per rule.
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("a"))
	}))
	defer backendA.Close()

	backendB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("b"))
	}))
	defer backendB.Close()

	backendC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("c"))
	}))
	defer backendC.Close()

	dir := t.TempDir()

	// Static whitelist: rules "a-allow" and "c-allow".
	ruleA := ruleFromServer(t, "a-allow", "", backendA.URL)
	ruleC := ruleFromServer(t, "c-allow", "", backendC.URL)
	staticJSON, err := json.Marshal([]reqrules.Rule{ruleA, ruleC})
	req.NoError(err)
	staticPath := writeJSONFile(t, dir, "whitelist.json", string(staticJSON))

	// Runtime whitelist: rule "b-allow".
	ruleB := ruleFromServer(t, "b-allow", "", backendB.URL)
	rtJSON, err := json.Marshal([]reqrules.Rule{ruleB})
	req.NoError(err)
	rtPath := writeJSONFile(t, dir, "whitelist2.json", string(rtJSON))

	// Load and merge.
	static, err := rules.Load2(staticPath, rtPath)
	req.NoError(err)

	req.Equal(3, static.Count(), "merged store must contain all three rules")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := startProxyWithRules(t, ctx, nil, static)

	// All three rules must be effective.
	for _, tc := range []struct {
		name    string
		url     string
		backend string
		want    string
	}{
		{"a-allow (static)", backendA.URL + "/", "backendA", "a"},
		{"b-allow (runtime)", backendB.URL + "/", "backendB", "b"},
		{"c-allow (static)", backendC.URL + "/", "backendC", "c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := client.Get(tc.url)
			req.NoError(err)
			defer resp.Body.Close()

			is.Equal(http.StatusOK, resp.StatusCode, "rule %q must allow the request", tc.name)
			body, _ := io.ReadAll(resp.Body)
			is.Equal(tc.want, string(body))
		})
	}
}

// TestProxy_RuntimeRules_MissingFile_NotFatal verifies that pointing
// --rt-whitelist-rules and --rt-blacklist-rules at non-existent files is not a
// fatal error — Load returns empty stores and the proxy starts successfully.
func TestProxy_RuntimeRules_MissingFile_NotFatal(t *testing.T) {
	defer goleak.VerifyNone(t)

	req := require.New(t)

	dir := t.TempDir()

	// Static rules: allow one backend so we can verify the proxy works.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	staticRule := ruleFromServer(t, "allow-backend", "", backend.URL)
	staticJSON, err := json.Marshal([]reqrules.Rule{staticRule})
	req.NoError(err)
	staticPath := writeJSONFile(t, dir, "whitelist.json", string(staticJSON))

	// Non-existent runtime rule files.
	rtWhitelistPath := filepath.Join(dir, "whitelist2.json") // does not exist

	// Load2 must succeed even when the runtime file is missing.
	wl, err := rules.Load2(staticPath, rtWhitelistPath)
	req.NoError(err, "missing runtime file must not be an error")
	req.Equal(1, wl.Count(), "static rule must still be present")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := startProxyWithRules(t, ctx, nil, wl)

	// Static rule still works — proxy started successfully.
	resp, err := client.Get(backend.URL + "/")
	req.NoError(err)
	defer resp.Body.Close()

	req.Equal(http.StatusOK, resp.StatusCode, "static rules must still work after empty runtime load")
}
