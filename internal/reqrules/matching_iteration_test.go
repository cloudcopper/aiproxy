package reqrules

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRange tests iteration over rules.
func TestRange(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()
	r.Add(Rule{ID: "c", Host: "c.example.com"})
	r.Add(Rule{ID: "a", Host: "a.example.com"})
	r.Add(Rule{ID: "b", Host: "b.example.com"})

	var ids []string
	r.Range(func(rule Rule) bool {
		ids = append(ids, rule.ID)
		return true
	})

	is.Equal([]string{"a", "b", "c"}, ids, "Expected rules sorted by ID")

	// Test early termination.
	count := 0
	r.Range(func(rule Rule) bool {
		count++
		return count < 2
	})
	is.Equal(2, count, "Expected Range to stop after 2 iterations")
}

// TestRuleOrderingByID tests that rules are sorted lexicographically by ID.
func TestRuleOrderingByID(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()

	// Add in non-sorted order.
	r.Add(Rule{ID: "z-last", Host: "z.example.com"})
	r.Add(Rule{ID: "a-first", Host: "a.example.com"})
	r.Add(Rule{ID: "m-middle", Host: "m.example.com"})
	r.Add(Rule{ID: "0010", Host: "num1.example.com"})
	r.Add(Rule{ID: "0020", Host: "num2.example.com"})

	var ids []string
	r.Range(func(rule Rule) bool {
		ids = append(ids, rule.ID)
		return true
	})

	is.Equal([]string{"0010", "0020", "a-first", "m-middle", "z-last"}, ids,
		"Rules should be sorted lexicographically by ID")
}

// TestMatchReturnsFirstMatchingRuleByID tests that Match returns the first rule
// in sorted order when multiple rules match and all have equal priority.
func TestMatchReturnsFirstMatchingRuleByID(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	r := New()

	// Both rules match GET https://api.example.com/v1/users, equal priority.
	// "aaa" sorts before "zzz" so "aaa" should match first.
	r.Add(Rule{ID: "zzz", Scheme: "https", Host: "api.example.com"})
	r.Add(Rule{ID: "aaa", Scheme: "https", Host: "api.example.com"})

	req, err := http.NewRequest("GET", "https://api.example.com/v1/users", nil)
	must.NoError(err)

	rule, matched := r.Match(req)
	is.True(matched, "Expected a match")
	is.Equal("aaa", rule.ID, "Expected first rule in sorted ID order when priorities equal")
}

// TestRuleOrderingByPriority verifies that lower priority numbers sort earlier
// (i.e. are checked first by Match).
func TestRuleOrderingByPriority(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()
	r.Add(Rule{ID: "low", Host: "low.example.com", Priority: 10})
	r.Add(Rule{ID: "high", Host: "high.example.com", Priority: 1})
	r.Add(Rule{ID: "zero", Host: "zero.example.com", Priority: 0})

	var ids []string
	r.Range(func(rule Rule) bool {
		ids = append(ids, rule.ID)
		return true
	})

	is.Equal([]string{"zero", "high", "low"}, ids,
		"Rules must be ordered by priority ascending (lower number = higher priority)")
}

// TestRuleOrderingByPriorityThenID verifies that equal-priority rules are
// broken by lexicographic ID order.
func TestRuleOrderingByPriorityThenID(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()
	r.Add(Rule{ID: "z-rule", Host: "z.example.com", Priority: 5})
	r.Add(Rule{ID: "a-rule", Host: "a.example.com", Priority: 5})
	r.Add(Rule{ID: "m-rule", Host: "m.example.com", Priority: 5})
	r.Add(Rule{ID: "early", Host: "e.example.com", Priority: 1})

	var ids []string
	r.Range(func(rule Rule) bool {
		ids = append(ids, rule.ID)
		return true
	})

	is.Equal([]string{"early", "a-rule", "m-rule", "z-rule"}, ids,
		"Priority=1 rule first, then priority=5 rules sorted by ID")
}

// TestAddReplacedRuleSortsOnPriorityChange verifies that replacing a rule with
// a different priority re-sorts the store. This is the regression test for the
// bug where the replace path in Add returned early before calling sort, causing
// the WebUI to display rules in the wrong order after an edit.
func TestAddReplacedRuleSortsOnPriorityChange(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()
	// Insert two rules both with priority 0 — sorted by ID: "a" then "z".
	r.Add(Rule{ID: "a", Host: "a.example.com", Priority: 0})
	r.Add(Rule{ID: "z", Host: "z.example.com", Priority: 0})

	var ids []string
	r.Range(func(rule Rule) bool { ids = append(ids, rule.ID); return true })
	is.Equal([]string{"a", "z"}, ids, "initial order should be a, z (same priority, ID sort)")

	// Give "z" a lower priority number — it should now sort before "a".
	r.Add(Rule{ID: "z", Host: "z.example.com", Priority: -0 + 0}) // same as 0, no change first
	r.Add(Rule{ID: "z", Host: "z.example.com", Priority: 0})      // still same

	// Now actually lower the priority number of "a" so "z" comes first.
	r.Add(Rule{ID: "a", Host: "a.example.com", Priority: 10}) // push "a" down

	ids = ids[:0]
	r.Range(func(rule Rule) bool { ids = append(ids, rule.ID); return true })
	is.Equal([]string{"z", "a"}, ids,
		"after raising priority number of 'a' to 10, 'z' (priority 0) must sort first")
}

// TestMatchReturnsFirstMatchingRuleByPriority verifies that among rules that
// all match the same request, the one with the lowest priority number wins.
func TestMatchReturnsFirstMatchingRuleByPriority(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	r := New()
	// "zzz" has lower priority number so it should be checked first despite ID being last.
	r.Add(Rule{ID: "aaa", Scheme: "https", Host: "api.example.com", Priority: 10})
	r.Add(Rule{ID: "zzz", Scheme: "https", Host: "api.example.com", Priority: 1})

	req, err := http.NewRequest("GET", "https://api.example.com/v1/users", nil)
	must.NoError(err)

	rule, matched := r.Match(req)
	must.True(matched)
	is.Equal("zzz", rule.ID,
		"Rule with lower priority number must win even if its ID sorts last")
}
