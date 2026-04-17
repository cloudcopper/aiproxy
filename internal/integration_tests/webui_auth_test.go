//go:build integration

package integration_tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloudcopper/aiproxy/internal/webui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startAuthServer starts a WebUI server with the given admin secret.
// LoginMinDelay is set to a short value to keep integration tests fast.
func startAuthServer(t *testing.T, adminSecret string) string {
	t.Helper()

	const loginDelay = 20 * time.Millisecond

	cfg := &webui.ServerConfig{
		Listen:        "localhost:0",
		StartTime:     time.Now(),
		Metrics:       &mockMetrics{},
		AdminSecret:   adminSecret,
		LoginMinDelay: loginDelay,
	}
	srv := webui.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.Start(ctx) //nolint:errcheck

	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := srv.Addr(addrCtx)
	require.NoError(t, err)

	return fmt.Sprintf("http://%s", addr)
}

// clientWithCookies returns an http.Client that stores cookies (needed for session).
func clientWithCookies(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects
		},
	}
}

// --- Public routes accessible without auth ---

func TestWebUI_LoginPage_PubliclyAccessible(t *testing.T) {
	baseURL := startAuthServer(t, "secret")

	resp, err := http.Get(baseURL + "/login")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "password")
}

func TestWebUI_LoginPage_AuthDisabled_ShowsNotice(t *testing.T) {
	baseURL := startAuthServer(t, "") // no secret

	resp, err := http.Get(baseURL + "/login")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "disabled")
}

// --- Protected routes redirect to login when unauthenticated ---

func TestWebUI_Pending_RedirectsToLoginWhenUnauthenticated(t *testing.T) {
	baseURL := startAuthServer(t, "secret")
	client := clientWithCookies(t)

	resp, err := client.Get(baseURL + "/pending")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/login")
}

func TestWebUI_Logout_RedirectsToLoginWhenUnauthenticated(t *testing.T) {
	baseURL := startAuthServer(t, "secret")
	client := clientWithCookies(t)

	resp, err := client.Get(baseURL + "/logout")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/login")
}

func TestWebUI_PendingStream_RedirectsToLoginWhenUnauthenticated(t *testing.T) {
	baseURL := startAuthServer(t, "secret")
	client := clientWithCookies(t)

	resp, err := client.Get(baseURL + "/api/pending/stream")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Location"), "/login")
}

// --- Login / logout flow ---

func TestWebUI_Login_CorrectPassword_SetsCookieRedirectsToPending(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/", resp.Header.Get("Location"))
}

func TestWebUI_Login_WrongPassword_Returns401(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := &http.Client{} // no cookie jar needed

	form := url.Values{"password": {"wrong"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestWebUI_Login_ThenAccessPending_ReturnsOK(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	// Login
	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	// Access protected page (no redirect following — re-enable for this request)
	client2 := &http.Client{Jar: client.Jar}
	resp2, err := client2.Get(baseURL + "/pending")
	require.NoError(t, err)
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	body, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body), "Pending Requests")
}

func TestWebUI_Logout_InvalidatesSession(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	// Login
	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	resp.Body.Close()

	// Logout (follow redirect manually)
	resp2, err := client.Get(baseURL + "/logout")
	require.NoError(t, err)
	resp2.Body.Close()

	// After logout, /pending must redirect to login again
	noFollow := &http.Client{
		Jar: client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp3, err := noFollow.Get(baseURL + "/pending")
	require.NoError(t, err)
	defer resp3.Body.Close()

	assert.Equal(t, http.StatusFound, resp3.StatusCode)
	assert.Contains(t, resp3.Header.Get("Location"), "/login")
}

// --- Pending page content ---

func TestWebUI_Pending_EmptyQueue_ShowsNoRequestsMessage(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	// Login
	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	resp.Body.Close()

	// Access pending page
	client2 := &http.Client{Jar: client.Jar}
	resp2, err := client2.Get(baseURL + "/pending")
	require.NoError(t, err)
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body), "No pending requests")
}

// --- Navigation bar ---

func TestWebUI_Dashboard_ShowsLogoutAfterLogin(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	// Login
	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	resp.Body.Close()

	// Dashboard visited while authenticated must show Logout, not Login
	client2 := &http.Client{Jar: client.Jar}
	resp2, err := client2.Get(baseURL + "/")
	require.NoError(t, err)
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body), `href="/logout"`, "dashboard must show Logout when authenticated")
	assert.NotContains(t, string(body), `href="/login"`, "dashboard must not show Login when authenticated")
}

func TestWebUI_Dashboard_ShowsLoginLinkWhenAuthEnabled(t *testing.T) {
	baseURL := startAuthServer(t, "secret")

	resp, err := http.Get(baseURL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `href="/login"`)
}

func TestWebUI_Dashboard_HidesLoginLinkWhenAuthDisabled(t *testing.T) {
	baseURL := startAuthServer(t, "") // no secret

	resp, err := http.Get(baseURL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), `href="/login"`)
}

func TestWebUI_Pending_ShowsLogoutLink(t *testing.T) {
	baseURL := startAuthServer(t, "hunter2")
	client := clientWithCookies(t)

	// Login
	form := url.Values{"password": {"hunter2"}}
	resp, err := client.PostForm(baseURL+"/login", form)
	require.NoError(t, err)
	resp.Body.Close()

	// Pending page should have Logout in nav
	client2 := &http.Client{Jar: client.Jar}
	resp2, err := client2.Get(baseURL + "/pending")
	require.NoError(t, err)
	defer resp2.Body.Close()

	body, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body), `href="/logout"`)
	assert.NotContains(t, string(body), `href="/login"`)
}

// --- 1-second delay smoke test ---

func TestWebUI_Login_WrongPassword_TakesAtLeastOneSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	// Use a server with the production 1-second MinDelay (no override).
	cfg := &webui.ServerConfig{
		Listen:      "localhost:0",
		StartTime:   time.Now(),
		Metrics:     &mockMetrics{},
		AdminSecret: "secret",
	}
	srv := webui.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Start(ctx) //nolint:errcheck

	addrCtx, addrCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer addrCancel()
	addr, err := srv.Addr(addrCtx)
	require.NoError(t, err)
	baseURL := fmt.Sprintf("http://%s", addr)

	form := url.Values{"password": {"wrong"}}
	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest(http.MethodPost, baseURL+"/login", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	require.NoError(t, err)
	resp.Body.Close()

	assert.GreaterOrEqual(t, elapsed, time.Second, "failed login must take at least 1 second")
}
