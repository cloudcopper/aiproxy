package reqrules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// loadBenchRules loads rules from testdata/bench_rules.json.
func loadBenchRules(b *testing.B) []Rule {
	b.Helper()

	path := filepath.Join("testdata", "bench_rules.json")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("failed to read %s: %v", path, err)
	}

	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		b.Fatalf("failed to parse %s: %v", path, err)
	}

	return rules
}

// loadBenchRequests loads all requests from testdata/bench_reqs.txt.
func loadBenchRequests(b *testing.B) []string {
	b.Helper()

	path := filepath.Join("testdata", "bench_reqs.txt")
	file, err := os.Open(path)
	if err != nil {
		b.Fatalf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	var requests []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		requests = append(requests, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		b.Fatalf("failed to read %s: %v", path, err)
	}

	return requests
}

// parseRequest parses "METHOD URL" into an *http.Request.
func parseRequest(b *testing.B, reqLine string) *http.Request {
	b.Helper()

	parts := strings.SplitN(reqLine, " ", 2)
	if len(parts) != 2 {
		b.Fatalf("invalid request line: %q", reqLine)
	}

	req, err := http.NewRequest(parts[0], parts[1], nil)
	if err != nil {
		b.Fatalf("failed to create request from %q: %v", reqLine, err)
	}

	return req
}

// buildRuleURL constructs a URL that matches the given rule (for benchmarks).
func buildRuleURL(rule Rule) string {
	scheme := rule.Scheme
	if scheme == "" {
		scheme = "https"
	}

	host := rule.Host
	if host == "" || host == "*" || host == "**" {
		host = "api.example.com"
	}

	path := rule.Path
	path = strings.ReplaceAll(path, "/**", "/data/items")
	path = strings.ReplaceAll(path, "/*", "/123")
	if strings.HasSuffix(path, "*") {
		path = path[:len(path)-1] + "test"
	}
	if path == "" {
		path = "/"
	}

	return scheme + "://" + host + path
}

// BenchmarkMatch benchmarks core matching scenarios.
func BenchmarkMatch(b *testing.B) {
	allRules := loadBenchRules(b)

	r := New()
	for _, rule := range allRules {
		if rule.ID != "" {
			r.Add(rule)
		}
	}

	b.Run("FirstRule", func(b *testing.B) {
		b.ReportAllocs()

		firstRule := allRules[0]
		method := firstRule.Method
		if method == "" {
			method = "GET"
		}
		req, _ := http.NewRequest(method, buildRuleURL(firstRule), nil)

		for b.Loop() {
			r.Match(req)
		}
	})

	b.Run("MiddleRule", func(b *testing.B) {
		b.ReportAllocs()

		middleRule := allRules[len(allRules)/2]
		method := middleRule.Method
		if method == "" {
			method = "GET"
		}
		req, _ := http.NewRequest(method, buildRuleURL(middleRule), nil)

		for b.Loop() {
			r.Match(req)
		}
	})

	b.Run("LastRule", func(b *testing.B) {
		b.ReportAllocs()

		lastRule := allRules[len(allRules)-1]
		method := lastRule.Method
		if method == "" {
			method = "GET"
		}
		req, _ := http.NewRequest(method, buildRuleURL(lastRule), nil)

		for b.Loop() {
			r.Match(req)
		}
	})

	b.Run("NoMatch", func(b *testing.B) {
		b.ReportAllocs()

		req, _ := http.NewRequest("GET", "https://unknown-host-notinrules.example.com/no/match/path", nil)

		for b.Loop() {
			r.Match(req)
		}
	})

	b.Run("MethodMismatch", func(b *testing.B) {
		b.ReportAllocs()

		// Find first rule with Method="GET" and request it with POST.
		var getRule Rule
		for _, rule := range allRules {
			if rule.Method == "GET" {
				getRule = rule
				break
			}
		}

		req, _ := http.NewRequest("POST", buildRuleURL(getRule), nil)

		for b.Loop() {
			r.Match(req)
		}
	})

	b.Run("WildcardMethod", func(b *testing.B) {
		b.ReportAllocs()

		// Find first rule with no method (wildcard).
		var wildcardRule Rule
		for _, rule := range allRules {
			if rule.Method == "" {
				wildcardRule = rule
				break
			}
		}

		req, _ := http.NewRequest("PUT", buildRuleURL(wildcardRule), nil)

		for b.Loop() {
			r.Match(req)
		}
	})
}

// BenchmarkMatchScaling benchmarks performance with different rule set sizes.
func BenchmarkMatchScaling(b *testing.B) {
	allRules := loadBenchRules(b)

	sizes := []struct {
		name  string
		count int
	}{
		{"100rules", 100},
		{"500rules", 500},
		{"1000rules", 1000},
	}

	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			b.ReportAllocs()

			r := New()
			for i := 0; i < size.count && i < len(allRules); i++ {
				if allRules[i].ID != "" {
					r.Add(allRules[i])
				}
			}

			// Match against middle rule.
			middleIdx := size.count / 2
			if middleIdx >= len(allRules) {
				middleIdx = len(allRules) - 1
			}

			middleRule := allRules[middleIdx]
			method := middleRule.Method
			if method == "" {
				method = "GET"
			}
			req, _ := http.NewRequest(method, buildRuleURL(middleRule), nil)

			for b.Loop() {
				r.Match(req)
			}
		})
	}
}

// BenchmarkMatchConcurrent benchmarks concurrent matching.
func BenchmarkMatchConcurrent(b *testing.B) {
	allRules := loadBenchRules(b)
	allRequests := loadBenchRequests(b)

	r := New()
	for _, rule := range allRules {
		if rule.ID != "" {
			r.Add(rule)
		}
	}

	// Parse all requests once.
	parsedRequests := make([]*http.Request, len(allRequests))
	for i, reqLine := range allRequests {
		parsedRequests[i] = parseRequest(b, reqLine)
	}

	sameReq := parsedRequests[0]

	concurrencyLevels := []int{1, 4, 16, 64}

	for _, numGoroutines := range concurrencyLevels {
		b.Run(fmt.Sprintf("%dgoroutines/SameRequest", numGoroutines), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					go func() {
						defer wg.Done()
						r.Match(sameReq)
					}()
				}

				wg.Wait()
			}
		})

		b.Run(fmt.Sprintf("%dgoroutines/RandomRequest", numGoroutines), func(b *testing.B) {
			b.ReportAllocs()

			for b.Loop() {
				var wg sync.WaitGroup
				wg.Add(numGoroutines)

				for i := 0; i < numGoroutines; i++ {
					go func(goroutineID int) {
						defer wg.Done()
						reqIdx := goroutineID % len(parsedRequests)
						r.Match(parsedRequests[reqIdx])
					}(i)
				}

				wg.Wait()
			}
		})
	}
}

// BenchmarkMatchRealistic simulates a real-world proxy workload.
func BenchmarkMatchRealistic(b *testing.B) {
	b.ReportAllocs()

	allRules := loadBenchRules(b)
	allRequests := loadBenchRequests(b)

	r := New()
	for _, rule := range allRules {
		if rule.ID != "" {
			r.Add(rule)
		}
	}

	// Parse all requests once (before timing).
	parsedRequests := make([]*http.Request, len(allRequests))
	for i, reqLine := range allRequests {
		parsedRequests[i] = parseRequest(b, reqLine)
	}

	// Use fixed seed for reproducibility.
	rng := rand.New(rand.NewSource(42))

	for b.Loop() {
		reqIdx := rng.Intn(len(parsedRequests))
		r.Match(parsedRequests[reqIdx])
	}
}
