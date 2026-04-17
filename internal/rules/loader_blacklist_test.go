package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadBlacklist_ValidFile tests various valid blacklist configurations.
func TestLoadBlacklist_ValidFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		content   string
		wantCount int
	}{
		{
			name: "multiple rules",
			content: `[
				{"id": "block-spam",   "method": "GET",  "scheme": "https", "host": "spam.example.com"},
				{"id": "block-admin",  "method": "POST", "scheme": "https", "host": "malicious-api.com", "path": "/admin/*"},
				{"id": "block-domain", "scheme": "https", "host": "blocked-domain.com", "path": "/**"}
			]`,
			wantCount: 3,
		},
		{
			name:      "single rule",
			content:   `[{"id": "r1", "method": "GET", "scheme": "https", "host": "api.example.com", "path": "/v1/*"}]`,
			wantCount: 1,
		},
		{
			name:      "empty array",
			content:   `[]`,
			wantCount: 0,
		},
		{
			name:      "empty file",
			content:   ``,
			wantCount: 0,
		},
		{
			name:      "rule without method matches any",
			content:   `[{"id": "any-method", "scheme": "https", "host": "any-method.example.com", "path": "/**"}]`,
			wantCount: 1,
		},
		{
			name:      "rule with id only",
			content:   `[{"id": "minimal"}]`,
			wantCount: 1,
		},
		{
			name:      "rule with port",
			content:   `[{"id": "r1", "host": "internal.corp", "port": 8080}]`,
			wantCount: 1,
		},
		{
			name:      "rule with port_range",
			content:   `[{"id": "r1", "host": "internal.corp", "port_range": [8080, 9090]}]`,
			wantCount: 1,
		},
		{
			name:      "rule with port_ranges",
			content:   `[{"id": "r1", "host": "internal.corp", "port_ranges": [[80, 80], [443, 443]]}]`,
			wantCount: 1,
		},
		{
			name: "rule with all optional fields",
			content: `[{
				"id": "full-rule",
				"comment": "All fields set",
				"method": "POST",
				"scheme": "https",
				"host": "api.example.com",
				"path": "/v1/chat/**",
				"rpm": 20
			}]`,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			req := require.New(t)

			dir := t.TempDir()
			path := filepath.Join(dir, "blacklist.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0644))

			rules, err := Load(path)
			req.NoError(err, "valid file should not return an error")
			req.NotNil(rules)

			is.Equal(tt.wantCount, rules.Count(), "rule count mismatch")
		})
	}
}

func TestLoadBlacklist_MissingFile(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	// A missing file must NOT be an error — fresh deployments have no rule files.
	rules, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	is.NoError(err, "missing file must not be an error")
	is.NotNil(rules)

	is.Equal(0, rules.Count(), "missing file should yield zero rules")
}

func TestLoadBlacklist_InvalidFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "malformed JSON",
			content: `not valid json`,
		},
		{
			name:    "JSON string instead of array",
			content: `"just a string"`,
		},
		{
			name:    "JSON object instead of array",
			content: `{"id": "r1", "host": "example.com"}`,
		},
		{
			name:    "rule missing id",
			content: `[{"host": "example.com"}]`,
		},
		{
			name:    "rule with empty id",
			content: `[{"id": "", "host": "example.com"}]`,
		},
		{
			name:    "rule with invalid method",
			content: `[{"id": "r1", "method": "BREW", "host": "example.com"}]`,
		},
		{
			name:    "rule with invalid scheme",
			content: `[{"id": "r1", "scheme": "ftp", "host": "example.com"}]`,
		},
		{
			name:    "rule with port and port_range both set",
			content: `[{"id": "r1", "port": 80, "port_range": [80, 443]}]`,
		},
		{
			name:    "rule with empty port_ranges",
			content: `[{"id": "r1", "port_ranges": []}]`,
		},
		{
			name:    "rule with invalid port_range bounds",
			content: `[{"id": "r1", "port_range": [9090, 8080]}]`,
		},
		{
			name:    "rule with negative rpm",
			content: `[{"id": "r1", "rpm": -1}]`,
		},
		{
			name:    "duplicate ids",
			content: `[{"id": "same-id", "host": "a.example.com"}, {"id": "same-id", "host": "b.example.com"}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "blacklist.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0644))

			_, err := Load(path)
			assert.Error(t, err, "invalid content should return an error")
		})
	}
}

// TestLoadBlacklist_ErrorContainsIndex verifies the error message pinpoints
// the exact failing rule by index, making misconfiguration easy to diagnose.
func TestLoadBlacklist_ErrorContainsIndex(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.json")
	content := `[
		{"id": "r0", "host": "valid.com"},
		{"id": "r1", "host": "also-valid.com"},
		{"id": "r2", "method": "BADMETHOD", "host": "invalid.com"}
	]`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index 2", "error should identify the failing rule index")
}

// TestLoadBlacklist_DuplicateIDError verifies that duplicate IDs are a fatal
// load-time error (not silently deduplicated).
func TestLoadBlacklist_DuplicateIDError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.json")
	content := `[
		{"id": "same-id", "host": "first.example.com"},
		{"id": "same-id", "host": "second.example.com"}
	]`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	_, err := Load(path)
	require.Error(t, err, "duplicate IDs must be a fatal load error")
	assert.Contains(t, err.Error(), "same-id", "error should mention the duplicate ID")
}

// TestLoadBlacklist_RulesLoadedWithCorrectFields verifies that all rule fields
// are correctly parsed and stored.
func TestLoadBlacklist_RulesLoadedWithCorrectFields(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.json")
	require.NoError(t, os.WriteFile(path, []byte(`[{
		"id": "full-rule",
		"comment": "test comment",
		"method": "POST",
		"scheme": "https",
		"host": "api.example.com",
		"path": "/v1/**",
		"rpm": 10
	}]`), 0644))

	rules, err := Load(path)
	req.NoError(err)

	var loaded []reqrules.Rule
	rules.Range(func(r reqrules.Rule) bool {
		loaded = append(loaded, r)
		return true
	})

	req.Len(loaded, 1)
	r := loaded[0]
	is.Equal("full-rule", r.ID)
	is.Equal("test comment", r.Comment)
	is.Equal("POST", r.Method)
	is.Equal("https", r.Scheme)
	is.Equal("api.example.com", r.Host)
	is.Equal("/v1/**", r.Path)
	is.Equal(10, r.RPM)
}

// TestLoadBlacklist_NoOptions_RuntimeFalse verifies that rules loaded without
// WithRuntime() always have Runtime==false (the zero value / static default).
func TestLoadBlacklist_NoOptions_RuntimeFalse(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "blacklist.json")
	require.NoError(t, os.WriteFile(path, []byte(`[
		{"id": "rule-a", "host": "a.example.com"},
		{"id": "rule-b", "host": "b.example.com"}
	]`), 0644))

	store, err := Load(path)
	req.NoError(err)

	store.Range(func(r reqrules.Rule) bool {
		req.Falsef(r.Runtime, "rule %q loaded without WithRuntime() must have Runtime==false", r.ID)
		return true
	})
}
