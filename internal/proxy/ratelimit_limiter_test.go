package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

// --- GlobalRateLimiter tests ---

func TestGlobalRateLimiter_FirstRequest_NoDelay(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	rl := NewGlobalRateLimiter(1*time.Second, store)

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	ctx := &goproxy.ProxyCtx{UserData: RequestID(1)}

	start := time.Now()
	gotReq, gotResp := rl.Handle(req, ctx)
	elapsed := time.Since(start)

	is.Equal(req, gotReq, "Request should pass through unchanged")
	is.Nil(gotResp, "Response should be nil (no short-circuit)")
	is.Less(elapsed, 50*time.Millisecond, "First request should not be delayed")
	is.Zero(len(store.requests), "Store should be empty after no-delay request")
}

func TestGlobalRateLimiter_SecondRequest_WithinInterval_Delayed(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 200 * time.Millisecond
	rl := NewGlobalRateLimiter(interval, store)

	// First request — no delay
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
	_, resp1 := rl.Handle(req1, &goproxy.ProxyCtx{UserData: RequestID(1)})
	is.Nil(resp1)

	// Second request immediately — should be delayed
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/2", nil)

	start := time.Now()
	gotReq, gotResp := rl.Handle(req2, &goproxy.ProxyCtx{UserData: RequestID(2)})
	elapsed := time.Since(start)

	is.Equal(req2, gotReq)
	is.Nil(gotResp)
	is.GreaterOrEqual(elapsed, interval-20*time.Millisecond,
		"Second request should be delayed by approximately the interval")
	is.Less(elapsed, interval+100*time.Millisecond,
		"Second request should not be delayed more than interval + tolerance")
}

func TestGlobalRateLimiter_SecondRequest_AfterInterval_NoDelay(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 50 * time.Millisecond
	rl := NewGlobalRateLimiter(interval, store)

	// First request
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
	_, resp1 := rl.Handle(req1, &goproxy.ProxyCtx{UserData: RequestID(1)})
	is.Nil(resp1)

	// Wait for interval to pass
	time.Sleep(interval + 20*time.Millisecond)

	// Second request — should not be delayed
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/2", nil)

	start := time.Now()
	gotReq, gotResp := rl.Handle(req2, &goproxy.ProxyCtx{UserData: RequestID(2)})
	elapsed := time.Since(start)

	is.Equal(req2, gotReq)
	is.Nil(gotResp)
	is.Less(elapsed, 50*time.Millisecond,
		"Request after interval should not be delayed")
}

func TestGlobalRateLimiter_ClientCancellation_AbortsDelay(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 5 * time.Second // Long interval to test cancellation
	rl := NewGlobalRateLimiter(interval, store)

	// First request to set lastReq
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
	_, resp1 := rl.Handle(req1, &goproxy.ProxyCtx{UserData: RequestID(1)})
	is.Nil(resp1)

	// Second request with cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	req2 := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/2", nil)

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	gotReq, gotResp := rl.Handle(req2, &goproxy.ProxyCtx{UserData: RequestID(2)})
	elapsed := time.Since(start)

	is.Equal(req2, gotReq)
	is.Nil(gotResp)
	is.Less(elapsed, 200*time.Millisecond,
		"Cancellation should abort the delay quickly")
}

func TestGlobalRateLimiter_ClientCancellation_RemovesFromStore(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 5 * time.Second // Long interval to test cancellation
	rl := NewGlobalRateLimiter(interval, store)

	// First request to set lastReq
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
	_, resp1 := rl.Handle(req1, &goproxy.ProxyCtx{UserData: RequestID(1)})
	is.Nil(resp1)

	// Second request with cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	req2 := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/2", nil)

	// Cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	gotReq, gotResp := rl.Handle(req2, &goproxy.ProxyCtx{UserData: RequestID(2)})
	elapsed := time.Since(start)

	is.Equal(req2, gotReq)
	is.Nil(gotResp)
	is.Less(elapsed, 200*time.Millisecond,
		"Cancellation should abort the delay quickly")

	// Verify the request was removed from the store
	store.mu.Lock()
	_, exists := store.requests[RequestID(2)]
	store.mu.Unlock()
	is.False(exists, "Cancelled request should be removed from store")
	is.Zero(len(store.requests), "Store should be empty after cancellation")
}

func TestGlobalRateLimiter_StoreCleanup_AfterDelay(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 100 * time.Millisecond
	rl := NewGlobalRateLimiter(interval, store)

	// First request
	req1 := httptest.NewRequest(http.MethodGet, "http://example.com/1", nil)
	_, _ = rl.Handle(req1, &goproxy.ProxyCtx{UserData: RequestID(1)})

	// Second request — will be delayed
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/2", nil)
	_, _ = rl.Handle(req2, &goproxy.ProxyCtx{UserData: RequestID(2)})

	// Store should be empty after delay completes
	store.mu.Lock()
	count := len(store.requests)
	store.mu.Unlock()
	is.Zero(count, "Store should be empty after delay completes")
}

func TestGlobalRateLimiter_ConcurrentRequests(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)

	store := NewDelayedRequestStore()
	interval := 100 * time.Millisecond
	rl := NewGlobalRateLimiter(interval, store)

	const n = 5
	var wg sync.WaitGroup
	results := make([]time.Duration, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			start := time.Now()
			_, _ = rl.Handle(req, &goproxy.ProxyCtx{UserData: RequestID(idx + 1)})
			results[idx] = time.Since(start)
		}(i)
	}

	wg.Wait()

	// At least one request should be fast (the one that grabs the lock first)
	fastCount := 0
	for _, d := range results {
		if d < 50*time.Millisecond {
			fastCount++
		}
	}
	is.GreaterOrEqual(fastCount, 1, "At least one request should be fast")

	// All requests should complete (no deadlock)
	for i, d := range results {
		is.Greater(d, time.Duration(0), "Request %d should have taken some time", i)
	}
}
