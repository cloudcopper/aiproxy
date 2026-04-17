package reqrules

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testRules = []Rule{
	{ID: "0001", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"},
	{ID: "0002", Method: "POST", Scheme: "https", Host: "api.example.com", Path: "/v1/users"},
	{ID: "0003", Method: "PUT", Scheme: "https", Host: "api.example.com", Path: "/v1/users/*"},
	{ID: "0004", Method: "DELETE", Scheme: "https", Host: "api.example.com", Path: "/v1/users/*"},
	{ID: "0005", Scheme: "https", Host: "trusted.example.com", Path: "/**"},
	{ID: "0006", Method: "GET", Scheme: "https", Host: "api.github.com", Path: "/**"},
	{ID: "0007", Method: "POST", Scheme: "https", Host: "api.openai.com", Path: "/**"},
	{ID: "0008", Method: "PATCH", Scheme: "https", Host: "api.example.com", Path: "/v1/posts/*"},
	{ID: "0009", Method: "HEAD", Scheme: "https", Host: "api.example.com", Path: "/health"},
	{ID: "0010", Method: "OPTIONS", Scheme: "https", Host: "api.example.com", Path: "/"},
}

// TestStressConcurrent tests concurrent access with 20 goroutines.
func TestStressConcurrent(t *testing.T) {
	is := assert.New(t)

	r := New()

	// Pre-populate with some rules.
	for i := 0; i < 5; i++ {
		r.Add(testRules[i])
	}

	const numGoroutines = 20
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	panicChan := make(chan interface{}, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					panicChan <- rec
				}
			}()

			localRng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))

			for j := 0; j < operationsPerGoroutine; j++ {
				op := localRng.Intn(4) // Add, Del, Match, Range

				switch op {
				case 0: // Add
					r.Add(testRules[localRng.Intn(len(testRules))])

				case 1: // Del
					rule := testRules[localRng.Intn(len(testRules))]
					r.Del(rule.ID)

				case 2: // Match
					method := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}[localRng.Intn(5)]
					url := fmt.Sprintf("https://api.example.com/v1/users/%d", localRng.Intn(100))
					req, _ := http.NewRequest(method, url, nil)
					r.Match(req)

				case 3: // Range
					count := 0
					r.Range(func(rule Rule) bool {
						count++
						return count < 5
					})
				}

				if localRng.Intn(10) == 0 {
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()
	close(panicChan)

	for p := range panicChan {
		is.Fail("Goroutine panicked", "panic: %v", p)
	}

	// Verify rules are still in sorted ID order.
	var rules []Rule
	r.Range(func(rule Rule) bool {
		rules = append(rules, rule)
		return true
	})

	for i := 1; i < len(rules); i++ {
		is.Less(rules[i-1].ID, rules[i].ID,
			"Rules not sorted: %q should come before %q", rules[i-1].ID, rules[i].ID)
	}
}

// TestStressAddDelSameRule tests concurrent Add/Del of the same rule.
func TestStressAddDelSameRule(t *testing.T) {
	is := assert.New(t)

	r := New()

	const numGoroutines = 20
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	rule := Rule{ID: "stress-rule", Scheme: "https", Host: "api.example.com", Path: "/test"}

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				if id%2 == 0 {
					r.Add(rule)
				} else {
					r.Del(rule.ID)
				}
			}
		}(i)
	}

	wg.Wait()

	// After all operations, the rule should exist at most once.
	count := 0
	r.Range(func(r Rule) bool {
		if r.ID == rule.ID {
			count++
		}
		return true
	})

	is.LessOrEqual(count, 1, "Rule should exist at most once, got %d", count)
}

// TestStressMatchWhileModifying tests Match operations while rules are being modified.
func TestStressMatchWhileModifying(t *testing.T) {
	is := assert.New(t)

	r := New()

	r.Add(Rule{ID: "0001", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"})
	r.Add(Rule{ID: "0002", Method: "POST", Scheme: "https", Host: "api.example.com", Path: "/v1/users"})
	r.Add(Rule{ID: "0003", Scheme: "https", Host: "trusted.example.com", Path: "/**"})

	const numReaders = 15
	const numWriters = 5
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numReaders + numWriters)

	// Reader goroutines (Match).
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()

			for j := 0; j < operationsPerGoroutine; j++ {
				req, _ := http.NewRequest("GET", "https://api.example.com/v1/users", nil)
				r.Match(req)
			}
		}()
	}

	// Writer goroutines (Add/Del).
	for i := 0; i < numWriters; i++ {
		go func(id int) {
			defer wg.Done()

			extraRules := []Rule{
				{ID: "extra-del", Method: "DELETE", Scheme: "https", Host: "api.example.com", Path: "/v1/*"},
				{ID: "extra-put", Method: "PUT", Scheme: "https", Host: "api.example.com", Path: "/v1/users/*"},
			}

			for j := 0; j < operationsPerGoroutine; j++ {
				rule := extraRules[j%len(extraRules)]
				if j%2 == 0 {
					r.Add(rule)
				} else {
					r.Del(rule.ID)
				}
			}
		}(i)
	}

	wg.Wait()

	// Verify no panics occurred and rules are still in sorted order.
	var rules []Rule
	r.Range(func(rule Rule) bool {
		rules = append(rules, rule)
		return true
	})

	for i := 1; i < len(rules); i++ {
		is.Less(rules[i-1].ID, rules[i].ID,
			"Rules not sorted after concurrent operations: %q should come before %q",
			rules[i-1].ID, rules[i].ID)
	}
}

// TestStressRangeWhileModifying tests Range operations while rules are being modified.
func TestStressRangeWhileModifying(t *testing.T) {
	is := assert.New(t)

	r := New()

	r.Add(Rule{ID: "0001", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"})
	r.Add(Rule{ID: "0002", Method: "POST", Scheme: "https", Host: "api.example.com", Path: "/v1/users"})

	const numRangers = 10
	const numModifiers = 10
	const operationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numRangers + numModifiers)

	panicChan := make(chan interface{}, numRangers+numModifiers)

	for i := 0; i < numRangers; i++ {
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					panicChan <- rec
				}
			}()

			for j := 0; j < operationsPerGoroutine; j++ {
				r.Range(func(rule Rule) bool {
					return true
				})
			}
		}()
	}

	for i := 0; i < numModifiers; i++ {
		go func(id int) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					panicChan <- rec
				}
			}()

			for j := 0; j < operationsPerGoroutine; j++ {
				dynRule := Rule{
					ID:     fmt.Sprintf("dyn-%04d", id),
					Scheme: "https",
					Host:   fmt.Sprintf("dyn%d.example.com", id),
				}
				if j%2 == 0 {
					r.Add(dynRule)
				} else {
					r.Del(dynRule.ID)
				}
			}
		}(i)
	}

	wg.Wait()
	close(panicChan)

	for p := range panicChan {
		is.Fail("Goroutine panicked", "panic: %v", p)
	}
}
