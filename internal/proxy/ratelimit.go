package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

// RequestID uniquely identifies a proxied request.
type RequestID uint64

func (id RequestID) String() string { return fmt.Sprintf("req_%d", id) }

// DelayedRequestStatus represents the lifecycle state of a rate-limited request.
type DelayedRequestStatus int

const (
	StatusPending DelayedRequestStatus = iota + 1
	StatusSent
	StatusCancelled
)

func (s DelayedRequestStatus) String() string {
	switch s {
	case StatusPending:
		return "pending"
	case StatusSent:
		return "sent"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// DelayedRequest tracks a request held by a rate limiter.
type DelayedRequest struct {
	ID     RequestID
	Req    *http.Request
	Delay  time.Duration
	Status DelayedRequestStatus
}

// DelayedRequestStore holds requests currently being held by rate limiters.
// Shared between global and per-rule rate limiters.
type DelayedRequestStore struct {
	mu       sync.Mutex
	requests map[RequestID]*DelayedRequest
}

// NewDelayedRequestStore creates an empty store.
func NewDelayedRequestStore() *DelayedRequestStore {
	return &DelayedRequestStore{requests: make(map[RequestID]*DelayedRequest)}
}

// Add registers a delayed request with the given ID.
func (s *DelayedRequestStore) Add(dr *DelayedRequest) RequestID {
	s.mu.Lock()
	defer s.mu.Unlock()
	dr.Status = StatusPending
	s.requests[dr.ID] = dr
	return dr.ID
}

// Remove deletes a delayed request from the store.
func (s *DelayedRequestStore) Remove(id RequestID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, id)
}

// Count returns the number of requests currently held in the store.
func (s *DelayedRequestStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// GlobalRateLimiter enforces a minimum interval between all proxied requests.
type GlobalRateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	lastReq  time.Time
	store    *DelayedRequestStore
}

// NewGlobalRateLimiter creates a global rate limiter.
// interval is the minimum time between requests (e.g. 6s for 10 req/min).
func NewGlobalRateLimiter(interval time.Duration, store *DelayedRequestStore) *GlobalRateLimiter {
	return &GlobalRateLimiter{
		interval: interval,
		lastReq:  time.Time{}, // zero value ensures first request passes through immediately
		store:    store,
	}
}

// ActiveCount returns the number of requests currently delayed by this rate limiter.
func (rl *GlobalRateLimiter) ActiveCount() int {
	return rl.store.Count()
}

// Handle is a goproxy request middleware.
// If the rate limit allows, the request passes through immediately.
// Otherwise, it sleeps for the remaining interval, then passes through.
func (rl *GlobalRateLimiter) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Read request_id set by onRequest
	id := ctx.UserData.(RequestID)

	// Calculate delay under lock
	rl.mu.Lock()
	nextAllowed := rl.lastReq.Add(rl.interval)
	delay := time.Until(nextAllowed)
	if delay > 0 {
		rl.lastReq = nextAllowed
	} else {
		rl.lastReq = time.Now()
	}
	rl.mu.Unlock()

	// No delay needed
	if delay <= 0 {
		return req, nil
	}

	// Track in store
	delayed := &DelayedRequest{Req: req, Delay: delay, ID: id}
	rl.store.Add(delayed)
	defer func() {
		rl.store.Remove(id)
	}()

	// Wait for delay or client cancellation
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-req.Context().Done():
		delayed.Status = StatusCancelled
		return req, nil
	}

	// Log delayed request being sent
	slog.Info("delayed",
		"request_id", id,
		"method", req.Method,
		"url", req.URL.String(),
		"remote_addr", req.RemoteAddr,
		"delay", delay.Round(time.Millisecond),
	)
	delayed.Status = StatusSent
	return req, nil
}

// RateLimitedCount returns the number of requests currently being held by the global rate limiter.
// Returns 0 if rate limiting is disabled.
func (p *Proxy) RateLimitedCount() int {
	if p.globalRL == nil {
		return 0
	}
	return p.globalRL.ActiveCount()
}
