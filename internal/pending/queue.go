// Package pending provides an in-memory pending request queue for AIProxy.
//
// Unknown requests — not matched by the blacklist and not matched by the
// whitelist — are held in the queue until their timeout expires, then rejected.
// Identical requests (same method + url) share one Entry and are all unblocked
// simultaneously when the entry times out.
//
// Phase 3 scope: in-memory only. State is lost on proxy restart.
package pending

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// EntryStatus represents the lifecycle state of a pending queue entry.
// Starts at 1 so the zero value is clearly invalid/unknown.
type EntryStatus int

const (
	StatusPending EntryStatus = iota + 1 // 1 — actively held in queue
	StatusExpired                         // 2 — timed out, removed from active map
)

// Resolution describes why a pending Hold call returned.
type Resolution int32

const (
	// ResolutionTimeout is the zero value: the pending timer fired naturally.
	ResolutionTimeout Resolution = iota
	// ResolutionApproved: an admin added a matching whitelist rule.
	ResolutionApproved
	// ResolutionDenied: an admin added a matching blacklist rule.
	ResolutionDenied
	// ResolutionDisconnected: the client's context was cancelled before resolution.
	ResolutionDisconnected
)

// Entry represents a single deduplicated pending request.
// All concurrent callers with the same (method, url) pair share one Entry.
//
// ClientIP is intentionally absent: the entry is a dedup aggregation for N
// callers from potentially N different IPs; storing any one IP would be
// arbitrary and misleading.
type Entry struct {
	ID      string
	Method  string
	URL     string
	Since   time.Time
	Timeout time.Duration

	// waiters is the number of goroutines currently blocked inside Hold() for
	// this entry. Incremented before blocking, decremented via defer on return.
	// Read by Waiters() for WebUI display.
	waiters atomic.Int64

	// resolution is stored atomically before done is closed so that Hold()
	// can return the correct Resolution after unblocking.
	resolution atomic.Int32

	// cancelTimeout cancels the runTimeout goroutine. Called by Resolve() so
	// the goroutine exits immediately instead of waiting for the full timeout.
	cancelTimeout context.CancelFunc

	// done is closed by runTimeout or Resolve when the entry is resolved,
	// unblocking all goroutines currently blocked in Hold for this entry.
	done chan struct{}
}

// Queue is an in-memory pending request queue, deduplicated by
// (method + " " + url). It is safe for concurrent use.
//
// State is lost on proxy restart (Phase 3 scope).
type Queue struct {
	mu      sync.Mutex // protects active
	timeout time.Duration
	active  map[string]*Entry
	nextID  atomic.Uint64
}

// NewQueue creates an empty in-memory pending queue with the given timeout.
func NewQueue(timeout time.Duration) *Queue {
	return &Queue{
		timeout: timeout,
		active:  make(map[string]*Entry),
	}
}

// Waiters returns the number of goroutines currently blocked inside Hold()
// for this entry. Used by the WebUI pending viewer to display a deduplicated
// count of concurrent clients waiting on the same request.
func (e *Entry) Waiters() int {
	return int(e.waiters.Load())
}

// Hold blocks the caller until the pending entry for (method, url) is resolved
// or the caller's context is cancelled. Returns a Resolution describing why it
// returned:
//   - ResolutionTimeout — timer fired naturally
//   - ResolutionApproved — whitelist rule added and ReevaluatePending called
//   - ResolutionDenied — blacklist rule added and ReevaluatePending called
//   - ResolutionDisconnected — caller's context cancelled
//
// Identical requests (same method and url) share one Entry: all callers block
// on the same done channel and are released simultaneously when the entry resolves.
func (q *Queue) Hold(ctx context.Context, method, url string) Resolution {
	key := method + " " + url

	q.mu.Lock()
	entry, exists := q.active[key]
	if !exists {
		timeoutCtx, cancelTimeout := context.WithCancel(context.Background())
		entry = &Entry{
			ID:            fmt.Sprintf("pnd_%d", q.nextID.Add(1)),
			Method:        method,
			URL:           url,
			Since:         time.Now(),
			Timeout:       q.timeout,
			cancelTimeout: cancelTimeout,
			done:          make(chan struct{}),
		}
		q.active[key] = entry
		// Start the timeout goroutine while holding the lock so it cannot
		// fire and delete the entry before it is visible in the map.
		go q.runTimeout(timeoutCtx, key, entry)
	}
	q.mu.Unlock()

	// Track this goroutine as an active waiter for the duration of Hold.
	// Increment before blocking; defer ensures decrement on every return path.
	// This gives an accurate real-time waiter count for WebUI display.
	entry.waiters.Add(1)
	defer entry.waiters.Add(-1)

	select {
	case <-entry.done:
		return Resolution(entry.resolution.Load())
	case <-ctx.Done():
		// Client disconnected. Return immediately; the timeout goroutine
		// continues so new identical requests can still join this entry.
		return ResolutionDisconnected
	}
}

// Resolve immediately resolves the pending entry identified by (method, url)
// with the given resolution, unblocking all goroutines currently in Hold for
// that entry. Returns true if the entry was found and resolved, false if the
// entry was not found (already resolved or never existed).
//
// Race-safe with runTimeout: exactly one of Resolve or runTimeout will find
// the entry in the active map and close done; the other is a no-op.
func (q *Queue) Resolve(method, url string, r Resolution) bool {
	key := method + " " + url

	q.mu.Lock()
	entry, exists := q.active[key]
	if exists {
		delete(q.active, key)
	}
	q.mu.Unlock()

	if !exists {
		return false
	}

	// Cancel the runTimeout goroutine so it exits immediately rather than
	// waiting for the full timeout duration. This prevents goroutine leaks
	// when rules are added and Resolve is called before the timer fires.
	entry.cancelTimeout()
	entry.resolution.Store(int32(r))
	close(entry.done)
	return true
}

// runTimeout waits for the configured timeout (or context cancellation from
// Resolve), removes the entry from the active map if still present, then closes
// entry.done to unblock all waiters simultaneously.
//
// The context is cancelled by Resolve() when an admin adds a matching rule.
// In that case the goroutine exits immediately without touching done (Resolve
// handles the close).
//
// Race safety with Resolve: both runTimeout and Resolve acquire the lock and
// delete the entry from the active map. Only the one that finds the entry
// still present will close done — the other is a no-op.
func (q *Queue) runTimeout(ctx context.Context, key string, entry *Entry) {
	timer := time.NewTimer(q.timeout)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Timer fired naturally. Check if Resolve beat us to the map deletion.
		q.mu.Lock()
		_, stillActive := q.active[key]
		if stillActive {
			delete(q.active, key)
		}
		q.mu.Unlock()

		if !stillActive {
			// Resolve() already closed done — nothing to do.
			return
		}

		// Close outside the lock — never hold a mutex while unblocking N waiters.
		entry.resolution.Store(int32(ResolutionTimeout))
		close(entry.done)

	case <-ctx.Done():
		// Resolve() was called: it already handled the map deletion and done
		// close. Just return so this goroutine can be garbage collected.
	}
}

// ActiveCount returns the number of entries currently in the active queue.
// Thread-safe.
func (q *Queue) ActiveCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.active)
}

// ActiveEntries returns a snapshot copy of all active entries.
// Used by the WebUI pending viewer (Phase 6).
func (q *Queue) ActiveEntries() []*Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries := make([]*Entry, 0, len(q.active))
	for _, e := range q.active {
		entries = append(entries, e)
	}
	return entries
}
