package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

// --- DelayedRequestStore tests ---

func TestDelayedRequestStore_Add_WithExternalID(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	dr := &DelayedRequest{
		ID:    RequestID(42),
		Req:   httptest.NewRequest(http.MethodGet, "http://example.com", nil),
		Delay: 100 * time.Millisecond,
	}

	id := store.Add(dr)

	is.Equal(RequestID(42), id, "Returned ID should match the provided ID")
	is.Equal(RequestID(42), dr.ID, "Assigned ID should match the provided ID")
	is.Equal(StatusPending, dr.Status, "Status should be pending after add")
}

func TestDelayedRequestStore_Remove(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	dr := &DelayedRequest{
		ID:    RequestID(1),
		Req:   httptest.NewRequest(http.MethodGet, "http://example.com", nil),
		Delay: 100 * time.Millisecond,
	}

	id := store.Add(dr)
	is.Equal(RequestID(1), id)

	// Verify it's in the store
	store.mu.Lock()
	_, exists := store.requests[id]
	store.mu.Unlock()
	is.True(exists, "Request should be in store after Add")

	store.Remove(id)

	// Verify it's removed
	store.mu.Lock()
	_, exists = store.requests[id]
	store.mu.Unlock()
	is.False(exists, "Request should be removed from store")
}

func TestDelayedRequestStore_Count(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	is.Equal(0, store.Count(), "Empty store should have count 0")

	dr1 := &DelayedRequest{ID: RequestID(1), Req: httptest.NewRequest(http.MethodGet, "http://example.com", nil)}
	dr2 := &DelayedRequest{ID: RequestID(2), Req: httptest.NewRequest(http.MethodGet, "http://example.com", nil)}

	store.Add(dr1)
	is.Equal(1, store.Count(), "Count should be 1 after adding one request")

	store.Add(dr2)
	is.Equal(2, store.Count(), "Count should be 2 after adding two requests")

	store.Remove(dr1.ID)
	is.Equal(1, store.Count(), "Count should be 1 after removing one request")

	store.Remove(dr2.ID)
	is.Equal(0, store.Count(), "Count should be 0 after removing all requests")
}

func TestGlobalRateLimiter_ActiveCount(t *testing.T) {
	is := assert.New(t)

	store := NewDelayedRequestStore()
	rl := NewGlobalRateLimiter(100*time.Millisecond, store)

	is.Equal(0, rl.ActiveCount(), "Empty limiter should have active count 0")

	// Add requests directly to the underlying store (simulates in-flight delayed requests)
	dr1 := &DelayedRequest{ID: RequestID(1), Req: httptest.NewRequest(http.MethodGet, "http://example.com", nil)}
	dr2 := &DelayedRequest{ID: RequestID(2), Req: httptest.NewRequest(http.MethodGet, "http://example.com", nil)}

	store.Add(dr1)
	is.Equal(1, rl.ActiveCount(), "ActiveCount should be 1 after adding one request to store")

	store.Add(dr2)
	is.Equal(2, rl.ActiveCount(), "ActiveCount should be 2 after adding two requests to store")

	store.Remove(dr1.ID)
	is.Equal(1, rl.ActiveCount(), "ActiveCount should be 1 after removing one")
}

func TestDelayedRequestStore_ConcurrentAccess(t *testing.T) {
	defer goleak.VerifyNone(t)

	is := assert.New(t)

	store := NewDelayedRequestStore()
	const n = 100
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			dr := &DelayedRequest{
				ID:    RequestID(idx + 1),
				Req:   httptest.NewRequest(http.MethodGet, "http://example.com", nil),
				Delay: 10 * time.Millisecond,
			}
			store.Add(dr)
		}(i)
	}

	wg.Wait()

	store.mu.Lock()
	count := len(store.requests)
	store.mu.Unlock()

	is.Equal(n, count, "All requests should be in the store")
}
