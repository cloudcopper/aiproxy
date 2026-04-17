package rules

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validRulesJSON is a reusable two-rule JSON fixture.
const validRulesJSON = `[
	{"id": "rule-a", "host": "a.example.com"},
	{"id": "rule-b", "host": "b.example.com"}
]`

// TestLoad_WithRuntime_StampsFlag verifies that every rule loaded with
// WithRuntime() has Runtime==true.
func TestLoad_WithRuntime_StampsFlag(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	writeFile(t, path, validRulesJSON)

	store, err := Load(path, WithRuntime())
	req.NoError(err)
	req.Equal(2, store.Count())

	store.Range(func(r reqrules.Rule) bool {
		req.Truef(r.Runtime, "rule %q loaded with WithRuntime() must have Runtime==true", r.ID)
		return true
	})
}

// TestLoad_WithoutRuntime_FlagFalse verifies that every rule loaded without
// options has Runtime==false.
func TestLoad_WithoutRuntime_FlagFalse(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	writeFile(t, path, validRulesJSON)

	store, err := Load(path)
	req.NoError(err)
	req.Equal(2, store.Count())

	store.Range(func(r reqrules.Rule) bool {
		req.Falsef(r.Runtime, "rule %q loaded without options must have Runtime==false", r.ID)
		return true
	})
}

// TestSave_WritesRuntimeRulesOnly verifies that Save writes only Runtime==true
// rules and that the serialized JSON does not contain a "runtime" key (json:"-").
func TestSave_WritesRuntimeRulesOnly(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")

	store := reqrules.New()
	store.SetFilename(path)
	store.Add(reqrules.Rule{ID: "static-rule", Host: "static.example.com", Runtime: false})
	store.Add(reqrules.Rule{ID: "runtime-rule", Host: "runtime.example.com", Runtime: true})

	req.NoError(Save(store))

	data, err := os.ReadFile(path)
	req.NoError(err)

	// Only the runtime rule must be present.
	var loaded []map[string]interface{}
	req.NoError(json.Unmarshal(data, &loaded))
	is.Len(loaded, 1, "only runtime rule should be written")

	// The "runtime" key must never appear in the JSON output (json:"-").
	is.False(bytes.Contains(data, []byte(`"runtime"`)),
		"Runtime field must not be serialized (json:\"-\")")

	id, _ := loaded[0]["id"].(string)
	is.Equal("runtime-rule", id)
}

// TestSave_NoFilename_NoOp verifies that Save is a no-op when no filename is
// configured (stores created with reqrules.New() without SetFilename).
func TestSave_NoFilename_NoOp(t *testing.T) {
	t.Parallel()

	store := reqrules.New()
	store.Add(reqrules.Rule{ID: "runtime-rule", Host: "runtime.example.com", Runtime: true})

	// No filename set — Save must return nil without touching the filesystem.
	assert.NoError(t, Save(store))
}

// TestSave_Atomic_DirectoryMissing verifies that Save returns an error (and
// does not panic or create a partial file) when the target directory does not
// exist.
func TestSave_Atomic_DirectoryMissing(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nonexistent-subdir", "out.json")
	store := reqrules.New()
	store.SetFilename(path)
	store.Add(reqrules.Rule{ID: "r1", Host: "example.com", Runtime: true})

	err := Save(store)
	assert.Error(t, err, "Save must fail when the target directory does not exist")
}

// TestSave_RoundTrip verifies that Load2→Save→Load preserves rule count and
// field values, and that the Runtime flag is set by the load option (not
// persisted, since json:"-" means the field is never in the file).
func TestSave_RoundTrip(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "src.json")
	dstPath := filepath.Join(dir, "dst.json")

	writeFile(t, srcPath, `[
		{"id": "r1", "host": "one.example.com"},
		{"id": "r2", "host": "two.example.com"}
	]`)

	// Load as runtime rules via Load2 (no static file).
	first, err := Load2(filepath.Join(dir, "missing-static.json"), srcPath)
	req.NoError(err)
	req.Equal(2, first.Count())

	// Override filename so Save writes to dstPath.
	first.SetFilename(dstPath)
	req.NoError(Save(first))

	// Reload from the saved file as runtime rules.
	second, err := Load(dstPath, WithRuntime())
	req.NoError(err)
	req.Equal(2, second.Count(), "rule count must survive round-trip")

	// Verify Runtime is true (from option, not from file — json:"-").
	second.Range(func(r reqrules.Rule) bool {
		req.Truef(r.Runtime, "rule %q must have Runtime==true after load with WithRuntime()", r.ID)
		return true
	})

	// Verify field values survive the round-trip.
	var saved []reqrules.Rule
	second.Range(func(r reqrules.Rule) bool {
		saved = append(saved, r)
		return true
	})
	req.Len(saved, 2)
	// Rules in lex order: r1, r2.
	req.Equal("r1", saved[0].ID)
	req.Equal("one.example.com", saved[0].Host)
	req.Equal("r2", saved[1].ID)
	req.Equal("two.example.com", saved[1].Host)
}

// TestMerge_LexicographicOrderPreserved verifies that merging runtime rules
// into a static store preserves lexicographic order across both sources.
func TestMerge_LexicographicOrderPreserved(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	// Static store: "a-rule" and "c-rule".
	static := reqrules.New()
	static.Add(reqrules.Rule{ID: "a-rule", Host: "a.example.com"})
	static.Add(reqrules.Rule{ID: "c-rule", Host: "c.example.com"})

	// Runtime store (loaded via file): "b-rule".
	dir := t.TempDir()
	path := filepath.Join(dir, "rt.json")
	writeFile(t, path, `[{"id": "b-rule", "host": "b.example.com"}]`)

	rt, err := Load(path, WithRuntime())
	req.NoError(err)

	// Merge runtime into static.
	rt.Range(func(r reqrules.Rule) bool {
		static.Add(r)
		return true
	})

	// Collect merged rules and verify lex order.
	var ids []string
	static.Range(func(r reqrules.Rule) bool {
		ids = append(ids, r.ID)
		return true
	})

	req.Equal([]string{"a-rule", "b-rule", "c-rule"}, ids)
}

// TestMerge_RuntimeFlagPreservedAfterMerge verifies that after merging a
// runtime rule into a static store, the Runtime flag is preserved correctly:
// the merged runtime rule has Runtime==true, static rules have Runtime==false.
func TestMerge_RuntimeFlagPreservedAfterMerge(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	static := reqrules.New()
	static.Add(reqrules.Rule{ID: "static-rule", Host: "static.example.com", Runtime: false})

	rt := reqrules.New()
	rt.Add(reqrules.Rule{ID: "runtime-rule", Host: "runtime.example.com", Runtime: true})

	// Merge.
	rt.Range(func(r reqrules.Rule) bool {
		static.Add(r)
		return true
	})

	// Verify flags in merged store.
	static.Range(func(r reqrules.Rule) bool {
		switch r.ID {
		case "static-rule":
			req.Falsef(r.Runtime, "static-rule must have Runtime==false after merge")
		case "runtime-rule":
			req.Truef(r.Runtime, "runtime-rule must have Runtime==true after merge")
		}
		return true
	})
}

// TestMerge_CollisionStaticWins verifies the security guarantee at the
// *policy* level: when static rules are added after runtime rules (as Load2
// does), static rules win on ID collision.
func TestMerge_CollisionStaticWins(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	// Runtime rule added first.
	store := reqrules.New()
	store.Add(reqrules.Rule{ID: "shared", Host: "runtime.example.com", Runtime: true})

	// Static rule added second — it must overwrite the runtime rule.
	store.Add(reqrules.Rule{ID: "shared", Host: "static.example.com", Runtime: false})

	req.Equal(1, store.Count(), "collision must replace, not duplicate")

	var found reqrules.Rule
	store.Range(func(r reqrules.Rule) bool {
		found = r
		return false
	})

	is.Equal("static.example.com", found.Host, "static rule must win")
	is.False(found.Runtime, "winning rule must have Runtime==false")
}

// TestMerge_CollisionRuntimeWins documents the underlying last-writer-wins
// primitive: if runtime rules were (incorrectly) added last they would win.
// This test exists to make the mechanism explicit; Load2 avoids this by always
// adding static rules second (see TestMerge_CollisionStaticWins).
func TestMerge_CollisionRuntimeWins(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	// Static rule added first.
	store := reqrules.New()
	store.Add(reqrules.Rule{ID: "shared", Host: "static.example.com", Runtime: false})

	// Runtime rule added second — it overwrites (demonstrating last-writer-wins).
	store.Add(reqrules.Rule{ID: "shared", Host: "runtime.example.com", Runtime: true})

	req.Equal(1, store.Count())

	var found reqrules.Rule
	store.Range(func(r reqrules.Rule) bool {
		found = r
		return false
	})

	is.Equal("runtime.example.com", found.Host, "last-writer wins in raw Add")
	is.True(found.Runtime)
}

// --- Load2 tests ---

// TestLoad2_MergesStaticAndRuntime verifies the happy-path: static and runtime
// rules from separate files are combined into one store with correct counts and
// Runtime flags.
func TestLoad2_MergesStaticAndRuntime(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	rtPath := filepath.Join(dir, "rt.json")

	writeFile(t, staticPath, `[{"id": "s1", "host": "static.example.com"}]`)
	writeFile(t, rtPath, `[{"id": "r1", "host": "runtime.example.com"}]`)

	store, err := Load2(staticPath, rtPath)
	req.NoError(err)
	req.Equal(2, store.Count())

	var rules []reqrules.Rule
	store.Range(func(r reqrules.Rule) bool {
		rules = append(rules, r)
		return true
	})

	// Lex order: r1, s1.
	req.Len(rules, 2)
	is.Equal("r1", rules[0].ID)
	is.True(rules[0].Runtime, "runtime rule must have Runtime==true")
	is.Equal("s1", rules[1].ID)
	is.False(rules[1].Runtime, "static rule must have Runtime==false")
}

// TestLoad2_SetsFilename verifies that Load2 stores the runtime file path on
// the returned store so rules.Save can write without needing the path again.
func TestLoad2_SetsFilename(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	rtPath := filepath.Join(dir, "rt.json")
	writeFile(t, staticPath, `[]`)
	writeFile(t, rtPath, `[]`)

	store, err := Load2(staticPath, rtPath)
	req.NoError(err)
	req.Equal(rtPath, store.Filename(), "Load2 must set the runtime file path as the store's filename")
}

// TestLoad2_MissingStaticFile_OK verifies that a missing static file is not
// an error; only the runtime rules are returned.
func TestLoad2_MissingStaticFile_OK(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	rtPath := filepath.Join(dir, "rt.json")
	writeFile(t, rtPath, `[{"id": "r1", "host": "runtime.example.com"}]`)

	store, err := Load2(filepath.Join(dir, "missing.json"), rtPath)
	req.NoError(err)
	req.Equal(1, store.Count())

	store.Range(func(r reqrules.Rule) bool {
		req.True(r.Runtime)
		return true
	})
}

// TestLoad2_MissingRuntimeFile_OK verifies that a missing runtime file is not
// an error; only the static rules are returned.
func TestLoad2_MissingRuntimeFile_OK(t *testing.T) {
	t.Parallel()
	req := require.New(t)

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	writeFile(t, staticPath, `[{"id": "s1", "host": "static.example.com"}]`)

	store, err := Load2(staticPath, filepath.Join(dir, "missing.json"))
	req.NoError(err)
	req.Equal(1, store.Count())

	store.Range(func(r reqrules.Rule) bool {
		req.False(r.Runtime)
		return true
	})
}

// TestLoad2_InvalidStaticFile_Error verifies that an invalid static file
// causes Load2 to return an error.
func TestLoad2_InvalidStaticFile_Error(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	writeFile(t, staticPath, `not valid json`)

	_, err := Load2(staticPath, filepath.Join(dir, "missing.json"))
	assert.Error(t, err)
}

// TestLoad2_InvalidRuntimeFile_Error verifies that an invalid runtime file
// causes Load2 to return an error.
func TestLoad2_InvalidRuntimeFile_Error(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	rtPath := filepath.Join(dir, "rt.json")
	writeFile(t, staticPath, `[]`)
	writeFile(t, rtPath, `not valid json`)

	_, err := Load2(staticPath, rtPath)
	assert.Error(t, err)
}

// TestLoad2_CollisionStaticWins verifies the security guarantee: when Load2
// encounters an ID collision the static (RO) rule always wins, regardless of
// what the runtime file contains. This prevents a compromised runtime file
// from shadowing hardened static rules.
func TestLoad2_CollisionStaticWins(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	req := require.New(t)

	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	rtPath := filepath.Join(dir, "rt.json")
	writeFile(t, staticPath, `[{"id": "shared", "host": "static.example.com"}]`)
	writeFile(t, rtPath, `[{"id": "shared", "host": "runtime.example.com"}]`)

	store, err := Load2(staticPath, rtPath)
	req.NoError(err)
	req.Equal(1, store.Count(), "collision must replace, not duplicate")

	var found reqrules.Rule
	store.Range(func(r reqrules.Rule) bool {
		found = r
		return false
	})

	is.Equal("static.example.com", found.Host, "static rule must win over runtime rule")
	is.False(found.Runtime, "winning rule must have Runtime==false (is a static rule)")
}
