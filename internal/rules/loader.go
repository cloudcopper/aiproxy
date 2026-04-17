// Package rules provides loading and saving of access control rules from/to
// JSON files.
//
// # File Format
//
// Both blacklist and whitelist files use the same JSON array-of-objects format,
// where each object is a rule accepted by the reqrules package:
//
//	[
//	    {"id": "block-spam",   "method": "GET",  "scheme": "https", "host": "spam.example.com"},
//	    {"id": "block-admin",  "method": "POST", "scheme": "https", "host": "malicious-api.com", "path": "/admin/*"},
//	    {"id": "block-domain", "scheme": "https", "host": "blocked-domain.com", "path": "/**"}
//	]
//
// All fields except id are optional. Absent fields match any value.
// See [reqrules.Rule] for the full field reference.
//
// # Missing Files
//
// A missing file is not an error. The proxy starts with an empty rule set,
// which is the safe default (no extra blocking/allowing beyond other rules).
//
// # Error Handling
//
// If the file exists but contains invalid JSON, invalid rule fields, or
// duplicate rule IDs, an error is returned and the proxy should refuse to start.
// This catches misconfigured rule files at startup, not silently at runtime.
package rules

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
)

// LoadOption configures how rules are loaded from a JSON file.
type LoadOption func(*loadConfig)

type loadConfig struct {
	runtime bool
}

// WithRuntime returns a LoadOption that stamps Runtime=true on every loaded rule.
// Use when loading proxy-managed rule files (whitelist2.json, blacklist2.json).
func WithRuntime() LoadOption {
	return func(c *loadConfig) {
		c.runtime = true
	}
}

// Load loads rules from a JSON file into a new ReqRules store.
// Options are applied to every rule after parsing.
//
// Missing file is not an error — returns an empty store.
// Existing but invalid file returns an error (caller should treat as fatal).
func Load(filePath string, opts ...LoadOption) (*reqrules.ReqRules, error) {
	cfg := &loadConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	return loadRulesFromFile(filePath, cfg)
}

// Load2 loads static (read-only) rules from staticPath and runtime rules from
// rtPath, merges them into a single *reqrules.ReqRules store, and returns it.
//
// staticPath rules are stamped Runtime=false (user-managed, read-only in WebUI).
// rtPath rules are stamped Runtime=true (proxy-managed, editable in WebUI).
// Missing files are not errors — each missing file contributes zero rules.
// Invalid files return an error; the caller should treat this as fatal.
//
// Security guarantee: static rules always win.
// Runtime rules are loaded first; static rules are loaded second. Because
// ReqRules.Add replaces by ID, a static rule with the same ID as a runtime
// rule always overrides it. An INFO is logged for each override — this is the
// expected workflow when a runtime rule is promoted to the static file.
func Load2(staticPath, rtPath string) (*reqrules.ReqRules, error) {
	// 1. Seed the store with runtime rules.
	store, err := Load(rtPath, WithRuntime())
	if err != nil {
		return nil, fmt.Errorf("load runtime rules from %q: %w", rtPath, err)
	}

	// Record which IDs came from the runtime file (for collision detection).
	rtIDs := make(map[string]struct{}, store.Count())
	store.Range(func(r reqrules.Rule) bool {
		rtIDs[r.ID] = struct{}{}
		return true
	})

	// 2. Load static rules — they overwrite any runtime rule with the same ID.
	static, err := Load(staticPath)
	if err != nil {
		return nil, fmt.Errorf("load static rules from %q: %w", staticPath, err)
	}

	static.Range(func(r reqrules.Rule) bool {
		if _, exists := rtIDs[r.ID]; exists {
			// Normal workflow: admin promoted a runtime rule to the static file.
			// Log at INFO so they know the runtime copy can be cleaned up.
			slog.Info("static rule overrides runtime rule with same ID",
				"id", r.ID,
				"static_file", staticPath,
				"runtime_file", rtPath,
			)
		}
		store.Add(r)
		return true
	})

	store.SetFilename(rtPath)
	return store, nil
}

// Save writes runtime rules from store to the file configured via SetFilename.
// Only rules with Runtime==true are written; static rules are never persisted
// by this function (the static files are user-managed and never modified by
// the proxy).
//
// Returns nil without writing when no filename is configured (e.g., stores
// created with reqrules.New() in tests).
//
// The write is atomic: a temp file in the same directory is written and then
// renamed over the target. The target directory must already exist.
func Save(store *reqrules.ReqRules) error {
	path := store.Filename()
	if path == "" {
		return nil
	}

	var collected []reqrules.Rule
	store.Range(func(r reqrules.Rule) bool {
		if r.Runtime {
			collected = append(collected, r)
		}
		return true
	})
	if collected == nil {
		collected = []reqrules.Rule{}
	}

	data, err := json.MarshalIndent(collected, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rules: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".rules-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %q: %w", dir, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename temp file to %q: %w", path, err)
	}

	return nil
}

// loadRulesFromFile is the shared implementation for Load.
func loadRulesFromFile(filePath string, cfg *loadConfig) (*reqrules.ReqRules, error) {
	r := reqrules.New()

	// Missing file is explicitly allowed: proxy starts with empty rule set.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return r, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read rules file: %w", err)
	}

	// Empty file is treated the same as an empty JSON array.
	if len(data) == 0 {
		return r, nil
	}

	var ruleObjects []reqrules.Rule
	if err := json.Unmarshal(data, &ruleObjects); err != nil {
		return nil, fmt.Errorf("parse rules file %q (expected JSON array of rule objects): %w", filePath, err)
	}

	// Validate all rules before adding any — fail fast with an informative index.
	// Also detect duplicate IDs (fatal per spec).
	seen := make(map[string]int, len(ruleObjects)) // id → first seen index
	for i, rule := range ruleObjects {
		if err := rule.Validate(); err != nil {
			return nil, fmt.Errorf("invalid rule at index %d in %q: %w", i, filePath, err)
		}
		if prev, exists := seen[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule id %q at index %d in %q (first seen at index %d)",
				rule.ID, i, filePath, prev)
		}
		seen[rule.ID] = i
		rule.Runtime = cfg.runtime // stamp Runtime flag before storing
		r.Add(rule)
	}

	return r, nil
}
