package pending

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// TestHold_timeout verifies that Hold returns ResolutionTimeout after the configured timeout.
func TestHold_timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(50 * time.Millisecond)

		done := make(chan Resolution, 1)
		go func() {
			done <- q.Hold(context.Background(), "GET", "https://example.com/api")
		}()

		// Advance synthetic time past the timeout.
		time.Sleep(100 * time.Millisecond)

		is.Equal(ResolutionTimeout, <-done, "Hold must return ResolutionTimeout after timeout")
		is.Equal(0, q.ActiveCount(), "entry removed from queue after timeout")
	})
}

// TestHold_ctxCancel verifies that Hold returns ResolutionDisconnected immediately
// when the caller's context is cancelled, without waiting for the entry's timeout.
// The entry stays in the queue so subsequent identical requests can still join it.
func TestHold_ctxCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(100 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())

		done := make(chan Resolution, 1)
		go func() {
			done <- q.Hold(ctx, "POST", "https://example.com/api")
		}()

		// Let the goroutine start and block inside Hold.
		time.Sleep(10 * time.Millisecond)

		// Cancel — Hold must return ResolutionDisconnected immediately.
		cancel()
		is.Equal(ResolutionDisconnected, <-done, "Hold must return ResolutionDisconnected on context cancel")

		// Entry stays in queue: the timeout goroutine keeps it alive for
		// any new identical request that arrives before the deadline.
		is.Equal(1, q.ActiveCount(), "entry stays alive after client cancel")

		// Advance past the timeout to let the timeout goroutine clean up.
		time.Sleep(200 * time.Millisecond)
		is.Equal(0, q.ActiveCount(), "entry removed after timeout goroutine fires")
	})
}

// TestHold_dedup verifies that two concurrent Hold calls for the same
// (method, url) pair share one Entry and both unblock simultaneously on timeout.
func TestHold_dedup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(50 * time.Millisecond)

		var wg sync.WaitGroup
		results := make([]Resolution, 2)
		for i := range 2 {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = q.Hold(context.Background(), "GET", "https://example.com/api")
			}(i)
		}

		// At 25ms both goroutines are blocked inside Hold, sharing one entry.
		time.Sleep(25 * time.Millisecond)
		is.Equal(1, q.ActiveCount(), "dedup: two callers must share one entry")

		// Advance past the timeout — both goroutines unblock simultaneously.
		time.Sleep(50 * time.Millisecond)
		wg.Wait()

		is.Equal(ResolutionTimeout, results[0], "first waiter must receive ResolutionTimeout")
		is.Equal(ResolutionTimeout, results[1], "second waiter must receive ResolutionTimeout")
		is.Equal(0, q.ActiveCount(), "entry removed after timeout")
	})
}

// TestHold_distinct verifies that Hold calls for different (method, url) pairs
// create independent entries that each time out on their own.
func TestHold_distinct(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(50 * time.Millisecond)

		urls := []string{
			"https://example.com/a",
			"https://example.com/b",
			"https://example.com/c",
		}

		var wg sync.WaitGroup
		for _, u := range urls {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				q.Hold(context.Background(), "GET", url) //nolint:errcheck
			}(u)
		}

		time.Sleep(25 * time.Millisecond)
		is.Equal(len(urls), q.ActiveCount(), "distinct URLs create distinct entries")

		time.Sleep(50 * time.Millisecond)
		wg.Wait()
		is.Equal(0, q.ActiveCount())
	})
}

// TestHold_sameURLDifferentMethod verifies that the dedup key is (method + url),
// so the same URL with different HTTP methods creates separate entries.
func TestHold_sameURLDifferentMethod(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(50 * time.Millisecond)

		var wg sync.WaitGroup
		for _, m := range []string{"GET", "POST"} {
			wg.Add(1)
			go func(method string) {
				defer wg.Done()
				q.Hold(context.Background(), method, "https://example.com/api") //nolint:errcheck
			}(m)
		}

		time.Sleep(25 * time.Millisecond)
		is.Equal(2, q.ActiveCount(), "GET and POST for same URL are distinct entries")

		time.Sleep(50 * time.Millisecond)
		wg.Wait()
		is.Equal(0, q.ActiveCount())
	})
}

// TestHold_entryFields verifies that a newly created Entry is initialised with
// the correct method, url, timeout, a non-empty ID, and a recent Since time.
func TestHold_entryFields(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		const timeout = 100 * time.Millisecond
		q := NewQueue(timeout)

		done := make(chan Resolution, 1)
		go func() {
			done <- q.Hold(context.Background(), "GET", "https://api.example.com/v1")
		}()

		// Let the goroutine start and create the entry.
		time.Sleep(10 * time.Millisecond)

		entries := q.ActiveEntries()
		is.Len(entries, 1)

		e := entries[0]
		is.Equal("GET", e.Method)
		is.Equal("https://api.example.com/v1", e.URL)
		is.NotEmpty(e.ID, "entry must have a non-empty ID")
		is.Contains(e.ID, "pnd_", "entry ID should follow pnd_N format")
		is.False(e.Since.IsZero(), "Since must be set")
		is.Equal(timeout, e.Timeout)

		// Clean up — advance past timeout.
		time.Sleep(200 * time.Millisecond)
		<-done
	})
}

// TestActiveCount_emptyQueue verifies that ActiveCount returns 0 for a new queue.
func TestActiveCount_emptyQueue(t *testing.T) {
	is := assert.New(t)
	q := NewQueue(time.Second)
	is.Equal(0, q.ActiveCount())
	is.Empty(q.ActiveEntries())
}

// TestHold_waitersCount verifies that Entry.Waiters() accurately reflects the
// number of goroutines currently blocked inside Hold() for that entry.
func TestHold_waitersCount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(100 * time.Millisecond)

		// First goroutine enters Hold.
		done1 := make(chan Resolution, 1)
		go func() {
			done1 <- q.Hold(context.Background(), "GET", "https://example.com/api")
		}()
		time.Sleep(10 * time.Millisecond)

		entries := q.ActiveEntries()
		is.Len(entries, 1)
		is.Equal(1, entries[0].Waiters(), "one waiter while first Hold is blocked")

		// Second goroutine enters Hold with identical key — shares the same entry.
		done2 := make(chan Resolution, 1)
		go func() {
			done2 <- q.Hold(context.Background(), "GET", "https://example.com/api")
		}()
		time.Sleep(10 * time.Millisecond)

		entries = q.ActiveEntries()
		is.Len(entries, 1, "dedup: still one entry")
		is.Equal(2, entries[0].Waiters(), "two waiters on same entry")

		// Advance past timeout — both goroutines unblock simultaneously.
		time.Sleep(100 * time.Millisecond)
		is.Equal(ResolutionTimeout, <-done1)
		is.Equal(ResolutionTimeout, <-done2)
		is.Equal(0, q.ActiveCount(), "entry removed after timeout")
	})
}

// TestHold_waitersCountDecrement_onContextCancel verifies that cancelling one
// waiter's context decrements Waiters() without removing the entry from the queue.
// The entry stays alive so subsequent identical requests can still join it.
func TestHold_waitersCountDecrement_onContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		q := NewQueue(200 * time.Millisecond)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Two waiters on the same entry.
		done1 := make(chan Resolution, 1)
		done2 := make(chan Resolution, 1)
		go func() {
			done1 <- q.Hold(context.Background(), "GET", "https://example.com/api")
		}()
		go func() {
			done2 <- q.Hold(ctx, "GET", "https://example.com/api")
		}()
		time.Sleep(10 * time.Millisecond)

		entries := q.ActiveEntries()
		is.Len(entries, 1)
		is.Equal(2, entries[0].Waiters(), "two waiters initially")

		// Cancel the second waiter's context.
		cancel()
		is.Equal(ResolutionDisconnected, <-done2, "cancelled waiter returns ResolutionDisconnected")
		// By the time the receive above returns, defer entry.waiters.Add(-1) has
		// already fired inside the goroutine — Hold() returns (running defers)
		// before sending on done2, so no extra sleep is needed.

		entries = q.ActiveEntries()
		is.Len(entries, 1, "entry stays alive after one cancel")
		is.Equal(1, entries[0].Waiters(), "waiter count decrements after cancel")

		// Advance past timeout — remaining waiter unblocks.
		time.Sleep(200 * time.Millisecond)
		is.Equal(ResolutionTimeout, <-done1)
		is.Equal(0, q.ActiveCount(), "entry removed after timeout")
	})
}

// TestResolve_approved verifies that Resolve with ResolutionApproved immediately
// unblocks all waiters and Hold returns ResolutionApproved.
func TestResolve_approved(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		// Use a modest timeout. runTimeout must fire to exit its goroutine;
		// we advance synthetic time past it at the end so the bubble drains.
		const timeout = 50 * time.Millisecond
		q := NewQueue(timeout)

		done := make(chan Resolution, 1)
		go func() {
			done <- q.Hold(context.Background(), "GET", "https://example.com/api")
		}()
		time.Sleep(10 * time.Millisecond)
		is.Equal(1, q.ActiveCount(), "entry must be in queue before Resolve")

		resolved := q.Resolve("GET", "https://example.com/api", ResolutionApproved)
		is.True(resolved, "Resolve must return true for an existing entry")
		is.Equal(0, q.ActiveCount(), "entry must be removed from queue after Resolve")

		is.Equal(ResolutionApproved, <-done, "Hold must return ResolutionApproved")

		// Advance synthetic time past the timeout so runTimeout exits its goroutine
		// and the synctest bubble can drain cleanly.
		time.Sleep(timeout + 10*time.Millisecond)
	})
}

// TestResolve_denied verifies that Resolve with ResolutionDenied immediately
// unblocks all waiters and Hold returns ResolutionDenied.
func TestResolve_denied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		const timeout = 50 * time.Millisecond
		q := NewQueue(timeout)

		done := make(chan Resolution, 1)
		go func() {
			done <- q.Hold(context.Background(), "POST", "https://example.com/secret")
		}()
		time.Sleep(10 * time.Millisecond)

		resolved := q.Resolve("POST", "https://example.com/secret", ResolutionDenied)
		is.True(resolved)
		is.Equal(0, q.ActiveCount())

		is.Equal(ResolutionDenied, <-done, "Hold must return ResolutionDenied")

		// Drain the runTimeout goroutine.
		time.Sleep(timeout + 10*time.Millisecond)
	})
}

// TestResolve_notFound verifies that Resolve returns false for an unknown key
// (entry never created or already resolved).
func TestResolve_notFound(t *testing.T) {
	is := assert.New(t)

	q := NewQueue(time.Second)
	resolved := q.Resolve("GET", "https://nonexistent.example.com/", ResolutionApproved)
	is.False(resolved, "Resolve must return false for unknown entry")
	is.Equal(0, q.ActiveCount())
}

// TestResolve_multipleWaiters verifies that Resolve unblocks all waiters on the
// same entry simultaneously and all receive the same resolution.
func TestResolve_multipleWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		is := assert.New(t)

		const timeout = 50 * time.Millisecond
		q := NewQueue(timeout)
		const numWaiters = 3

		results := make([]Resolution, numWaiters)
		var wg sync.WaitGroup
		for i := range numWaiters {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = q.Hold(context.Background(), "GET", "https://example.com/shared")
			}(i)
		}
		time.Sleep(10 * time.Millisecond)
		is.Equal(1, q.ActiveCount(), "all waiters share one entry")

		q.Resolve("GET", "https://example.com/shared", ResolutionApproved) //nolint:errcheck
		wg.Wait()

		for i, r := range results {
			is.Equal(ResolutionApproved, r, "waiter %d must receive ResolutionApproved", i)
		}
		is.Equal(0, q.ActiveCount())

		// Drain the runTimeout goroutine.
		time.Sleep(timeout + 10*time.Millisecond)
	})
}
