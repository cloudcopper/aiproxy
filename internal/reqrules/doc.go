// Package reqrules provides thread-safe storage and matching of HTTP request rules.
//
// This package is designed for managing whitelist and blacklist rules in proxy
// applications, with support for glob pattern matching and deterministic rule ordering.
//
// # Rule Format
//
// Rules are represented as [Rule] structs with the following fields:
//
//   - ID (required): unique identifier; determines match priority (lexicographic order)
//   - Comment: human-readable description; ignored by matcher
//   - Method: HTTP method (e.g., "GET", "POST"); absent = any method
//   - Scheme: URL scheme ("http" or "https"); absent = any scheme
//   - Host: hostname glob pattern (e.g., "api.example.com", "*.example.com"); absent = any host
//   - Path: URL path glob pattern (e.g., "/v1/*", "/**"); absent = any path
//   - Port: exact port number; 0 = absent (any port)
//   - PortRange: *[2]int port range inclusive; nil = absent (any port)
//   - PortRanges: multiple [low, high] ranges; nil = absent (any port)
//   - RPM: per-rule rate limit in requests/min; field stored, enforcement is future work
//
// All present (non-zero) fields must match for a rule to fire (AND semantics).
// Absent fields are wildcards — they match any value.
//
// # Host Glob Semantics
//
// Host patterns use dot-as-separator semantics: "*" does not match "."; "**"
// matches across "." boundaries. This mirrors standard doublestar path semantics
// applied to hostname components:
//
//   - "api.openai.com"     — exact match
//   - "*.openai.com"       — one subdomain level (api.openai.com, not deep.api.openai.com)
//   - "**.openai.com"      — any depth (openai.com, api.openai.com, deep.api.openai.com)
//   - "*"                  — explicit any-host wildcard
//
// # Thread Safety
//
// ReqRules is safe for concurrent use by multiple goroutines. It uses sync.RWMutex
// internally, optimized for read-heavy workloads (many Match/Range operations,
// infrequent Add/Del operations).
//
// # Rule Ordering
//
// Rules are automatically sorted lexicographically by ID regardless of insertion
// order. The first matching rule (in sorted ID order) is returned by Match.
//
// Example IDs that produce predictable ordering:
//
//   - "a-openai-api", "b-github", "z-fallback" (letter prefix controls order)
//   - "0010", "0020", "0030" (zero-padded numeric, with gaps for future insertion)
//
// # Usage Example
//
//	package main
//
//	import (
//	    "fmt"
//	    "net/http"
//	    "github.com/cloudcopper/aiproxy/internal/reqrules"
//	)
//
//	func main() {
//	    rules := reqrules.New()
//
//	    rule := reqrules.Rule{
//	        ID:     "github-readonly",
//	        Method: "GET",
//	        Scheme: "https",
//	        Host:   "api.github.com",
//	        Path:   "/repos/**",
//	    }
//
//	    // Validate before adding
//	    if err := rule.Validate(); err != nil {
//	        panic(err)
//	    }
//
//	    // Add rules (panics if invalid)
//	    rules.Add(rule)
//	    rules.Add(reqrules.Rule{
//	        ID:     "openai-chat",
//	        Method: "POST",
//	        Scheme: "https",
//	        Host:   "api.openai.com",
//	        Path:   "/v1/chat/completions",
//	    })
//
//	    // Match against HTTP request
//	    req, _ := http.NewRequest("GET", "https://api.github.com/repos/foo/bar", nil)
//	    if matched, ok := rules.Match(req); ok {
//	        fmt.Printf("Matched rule: %s\n", matched.ID)
//	    }
//
//	    // Iterate over all rules (in sorted ID order)
//	    rules.Range(func(r reqrules.Rule) bool {
//	        fmt.Println(r.ID)
//	        return true // continue iteration
//	    })
//
//	    // Remove a rule by ID
//	    rules.Del("openai-chat")
//	}
package reqrules
