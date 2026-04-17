package reqrules

import (
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// slashHost is a hostname with every "." replaced by "/", making it compatible
// with doublestar glob matching. Doublestar treats "/" as a segment separator:
// "*" matches within a single segment (does not cross "/"), while "**" matches
// across segments. By converting "." to "/" we get the intended DNS-label
// semantics:
//   - "*.example.com"  → matches "api.example.com"  but not "a.b.example.com"
//   - "**.example.com" → matches "api.example.com"  and "a.b.example.com"
//
// This type is pre-computed once — at Add time for rules (stored in Rule.slashHost),
// and once per request in Match — to avoid repeated allocations in the hot loop.
type slashHost string

// getSlashHost converts a raw hostname into a slashHost suitable for doublestar
// matching by replacing all "." separators with "/".
func getSlashHost(host string) slashHost {
	return slashHost(strings.ReplaceAll(host, ".", "/"))
}

// matchesRule reports whether a rule matches the given request fields.
// All non-zero fields in the rule must match (AND semantics).
//
// host must be a pre-computed slashHost (see getSlashHost). rule.slashHost is
// expected to have been set at Add time. Together they eliminate all string
// allocations from host matching in the hot loop.
//
// Checks are ordered cheapest-first to maximise early exits:
//  1. Method  — exact string compare
//  2. Scheme  — exact string compare
//  3. Port    — integer compare (before glob fields)
//  4. Host    — doublestar glob (pre-computed slashHost, no allocation)
//  5. Path    — doublestar glob
func matchesRule(rule Rule, method, scheme string, host slashHost, path string, port int) bool {
	if rule.Method != "" && rule.Method != method {
		return false
	}

	if rule.Scheme != "" && rule.Scheme != scheme {
		return false
	}

	// Port is an integer compare — cheaper than the glob matches below.
	if rule.Port != 0 {
		if port != rule.Port {
			return false
		}
	} else if rule.PortRange != nil {
		if port < rule.PortRange[0] || port > rule.PortRange[1] {
			return false
		}
	} else if rule.PortRanges != nil {
		inRange := false
		for _, pr := range rule.PortRanges {
			if port >= pr[0] && port <= pr[1] {
				inRange = true
				break
			}
		}
		if !inRange {
			return false
		}
	}

	if rule.Host != "" && rule.Host != "*" {
		// Both sides are pre-computed slashHost values — no allocation here.
		if !doublestar.MatchUnvalidated(string(rule.slashHost), string(host)) {
			return false
		}
	}

	if rule.Path != "" && !doublestar.MatchUnvalidated(rule.Path, path) {
		return false
	}

	return true
}
