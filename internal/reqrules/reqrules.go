package reqrules

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
)

// ReqRules stores and processes request rules for whitelist/blacklist matching.
// It is safe for concurrent use by multiple goroutines.
type ReqRules struct {
	mu       sync.RWMutex
	rules    []Rule // all rules sorted by (priority ASC, id ASC)
	filename string // backing file for runtime rules; empty = no persistence
}

// New creates a new ReqRules instance.
func New() *ReqRules {
	return &ReqRules{
		rules: make([]Rule, 0),
	}
}

// SetFilename sets the backing file path for runtime rule persistence.
// Called by rules.Load2 after merging static and runtime rules.
// The path is used by rules.Save to persist Runtime==true rules without
// requiring callers to know the file location.
func (r *ReqRules) SetFilename(path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.filename = path
}

// Filename returns the backing file path for runtime rule persistence.
// Returns empty string when no file is configured (e.g., stores created with New()).
func (r *ReqRules) Filename() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.filename
}

func (r *ReqRules) Count() int {
	if r == nil {
		return 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.rules)
}

// Add adds a rule to the collection.
// Panics if the rule is invalid (use Validate to check first).
// If a rule with the same ID already exists, it is replaced (idempotent by ID).
func (r *ReqRules) Add(rule Rule) {
	if err := rule.Validate(); err != nil {
		panic(fmt.Sprintf("invalid rule %q: %v", rule.ID, err))
	}

	rule.slashHost = getSlashHost(rule.Host) // pre-compute for hot-path matching

	r.mu.Lock()
	defer r.mu.Unlock()

	// Replace existing rule with same ID, or insert new.
	for i, existing := range r.rules {
		if existing.ID == rule.ID {
			r.rules[i] = rule // replace in-place (idempotent by ID)
			r.sort()          // priority may have changed — must re-sort
			return
		}
	}

	r.rules = append(r.rules, rule)
	r.sort()
}

// sort orders r.rules by (priority ASC, id ASC).
// Must be called with r.mu held.
func (r *ReqRules) sort() {
	sort.Slice(r.rules, func(i, j int) bool {
		if r.rules[i].Priority != r.rules[j].Priority {
			return r.rules[i].Priority < r.rules[j].Priority
		}
		return r.rules[i].ID < r.rules[j].ID
	})
}

// Del removes the rule with the given ID from the collection.
// If no rule with that ID exists, this is a no-op.
func (r *ReqRules) Del(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, rule := range r.rules {
		if rule.ID == id {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
			return
		}
	}
}

// Match finds the first matching rule for the given HTTP request.
// Returns the matched Rule and true if a match is found, or the zero Rule and
// false otherwise.
//
// Rules are checked in (priority ASC, id ASC) order. The first rule whose all
// present (non-zero) fields match the request is returned.
func (r *ReqRules) Match(req *http.Request) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	reqMethod := req.Method
	reqScheme := req.URL.Scheme
	reqSlashHost := getSlashHost(req.URL.Hostname())
	reqPath := req.URL.Path
	reqPort := extractPort(req.URL)

	for _, rule := range r.rules {
		if matchesRule(rule, reqMethod, reqScheme, reqSlashHost, reqPath, reqPort) {
			return rule, true
		}
	}

	return Rule{}, false
}

// extractPort extracts the port number from a URL.
// If no port is explicitly present, returns the scheme default: 80 for http,
// 443 for https, 0 for any other scheme.
func extractPort(u *url.URL) int {
	portStr := u.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0
		}
		return port
	}
	switch u.Scheme {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// Range iterates over all rules in sorted order by (priority ASC, id ASC), calling fn for each rule.
// Iteration stops early if fn returns false.
//
// The rules are read-locked during iteration; fn must not call other ReqRules
// methods to avoid a deadlock.
func (r *ReqRules) Range(fn func(rule Rule) bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, rule := range r.rules {
		if !fn(rule) {
			return
		}
	}
}
