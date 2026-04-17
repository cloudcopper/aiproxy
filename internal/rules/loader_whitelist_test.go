package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeFile is a test helper that writes content to a temp file and returns its path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}

// TestLoadWhitelist_ValidFile tests loading a valid whitelist file.
func TestLoadWhitelist_ValidFile(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	writeFile(t, path, `[
		{"id": "github-read", "method": "GET",  "scheme": "https", "host": "api.github.com", "path": "/**"},
		{"id": "openai-chat", "method": "POST", "scheme": "https", "host": "api.openai.com", "path": "/v1/chat"}
	]`)

	rules, err := Load(path)
	req.NoError(err)
	req.NotNil(rules)

	is.Equal(2, rules.Count())
}

func TestLoadWhitelist_MissingFile(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	rules, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	is.NoError(err)
	is.NotNil(rules)
}

// TestLoadWhitelist_NoOptions_RuntimeFalse verifies that rules loaded without
// WithRuntime() always have Runtime==false (the zero value / static default).
func TestLoadWhitelist_NoOptions_RuntimeFalse(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	writeFile(t, path, `[
		{"id": "rule-a", "host": "a.example.com"},
		{"id": "rule-b", "host": "b.example.com"}
	]`)

	store, err := Load(path)
	req.NoError(err)

	store.Range(func(r reqrules.Rule) bool {
		req.Falsef(r.Runtime, "rule %q loaded without WithRuntime() must have Runtime==false", r.ID)
		return true
	})
}
