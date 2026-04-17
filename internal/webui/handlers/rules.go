package handlers

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/cloudcopper/aiproxy/internal/rules"
	"github.com/cloudcopper/aiproxy/internal/webui/templates"
)

// RulesSource provides live access to the whitelist and blacklist rule stores.
// Defined on the consumer side (handlers) so the proxy package has no webui dependency.
// Mutations to the returned stores take effect immediately in proxy request matching.
type RulesSource interface {
	Whitelist() *reqrules.ReqRules
	Blacklist() *reqrules.ReqRules
}

// RulesConfig holds dependencies for all rules page handlers.
type RulesConfig struct {
	Source  RulesSource
	Pending PendingSource // used to call ReevaluatePending after rule changes
	Nav     templates.NavData
}

// rulesTableBodyData converts a ReqRules store into template display rows.
// Rules are returned in the store's natural order (lexicographic by ID).
func rulesTableBodyData(store *reqrules.ReqRules) []templates.RuleRowData {
	if store == nil {
		return nil
	}
	var rows []templates.RuleRowData
	store.Range(func(r reqrules.Rule) bool {
		rows = append(rows, templates.RuleRowData{
			ID:       r.ID,
			Priority: r.Priority,
			Comment:  r.Comment,
			Method:   r.Method,
			Scheme:   r.Scheme,
			Host:     r.Host,
			Path:     r.Path,
			Runtime:  r.Runtime,
		})
		return true
	})
	return rows
}

// storeForListType returns the correct store based on the list type string.
func storeForListType(cfg *RulesConfig, listType string) *reqrules.ReqRules {
	switch listType {
	case "whitelist":
		return cfg.Source.Whitelist()
	case "blacklist":
		return cfg.Source.Blacklist()
	}
	return nil
}

func sectionTitle(listType string) string {
	switch listType {
	case "whitelist":
		return "Whitelist Rules"
	case "blacklist":
		return "Blacklist Rules"
	}
	return listType
}

// buildSection constructs a RulesSectionData from a store, with optional form state.
func buildSection(listType string, store *reqrules.ReqRules, vals templates.RuleFormValues, errMsg string) templates.RulesSectionData {
	return templates.RulesSectionData{
		ListType: listType,
		Title:    sectionTitle(listType),
		Rules:    rulesTableBodyData(store),
		FormVals: vals,
		ErrMsg:   errMsg,
	}
}

// renderSectionBody renders RulesSectionBody into a buffer and writes it.
// On template error it writes a 500 response (only valid before any header flush).
// It detects HTMX requests via HX-Request header and sets Vary for caching.
func renderSectionBody(w http.ResponseWriter, r *http.Request, section templates.RulesSectionData, status int) {
	isHTMX := r.Header.Get("HX-Request") == "true"
	// These endpoints are HTMX-only.
	if !isHTMX {
		http.Error(w, "this endpoint requires HTMX", http.StatusMethodNotAllowed)
		return
	}

	var buf bytes.Buffer
	if err := templates.RulesSectionBody(section).Render(r.Context(), &buf); err != nil {
		http.Error(w, "template render error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "HX-Request")
	w.WriteHeader(status)
	w.Write(buf.Bytes()) //nolint:errcheck
}

// --- Rules page (GET /rules) ---

type rulesPageHandler struct{ cfg *RulesConfig }

// NewRulesPageHandler returns an http.Handler for GET /rules.
// Must be wrapped with AuthMiddleware.
func NewRulesPageHandler(cfg *RulesConfig) http.Handler { return &rulesPageHandler{cfg: cfg} }

func (h *rulesPageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract prefill query params if present.
	prefillType, prefillVals := extractPrefillParams(r)

	// Build empty form values for both sections.
	emptyVals := templates.RuleFormValues{}

	whitelistVals := emptyVals
	blacklistVals := emptyVals

	// Pre-populate the target section with prefill values.
	switch prefillType {
	case "whitelist":
		whitelistVals = prefillVals
	case "blacklist":
		blacklistVals = prefillVals
	}

	data := templates.RulesPageData{
		Nav:           h.cfg.Nav,
		Whitelist:     buildSection("whitelist", h.cfg.Source.Whitelist(), whitelistVals, ""),
		Blacklist:     buildSection("blacklist", h.cfg.Source.Blacklist(), blacklistVals, ""),
		PrefillTarget: prefillType,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := templates.RulesPage(data).Render(r.Context(), w); err != nil {
		http.Error(w, "template render error", http.StatusInternalServerError)
	}
}

// extractPrefillParams extracts prefill query parameters from the request.
// Returns the list type ("whitelist" or "blacklist") and pre-populated form values.
func extractPrefillParams(r *http.Request) (string, templates.RuleFormValues) {
	listType := r.URL.Query().Get("prefill")
	if listType != "whitelist" && listType != "blacklist" {
		return "", templates.RuleFormValues{}
	}

	// The host may be in form "hostname" or "hostname:port"
	// Ensure the a has two elements here
	a := append(strings.Split(r.URL.Query().Get("host"), ":"), "")
	host, port := a[0], a[1]
	_ = port
	vals := templates.RuleFormValues{
		Method:  r.URL.Query().Get("method"),
		Scheme:  r.URL.Query().Get("scheme"),
		Host:    host,
		Path:    r.URL.Query().Get("path"),
		Comment: "", // No prefill for comment
	}
	return listType, vals
}

// --- Add rule (POST /api/rules/{whitelist|blacklist}) ---

type rulesAddHandler struct {
	cfg      *RulesConfig
	listType string
}

// NewRulesAddHandler returns an http.Handler for POST /api/rules/{whitelist|blacklist}.
// Must be wrapped with AuthMiddleware.
func NewRulesAddHandler(cfg *RulesConfig, listType string) http.Handler {
	return &rulesAddHandler{cfg: cfg, listType: listType}
}

func (h *rulesAddHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isHTMX := r.Header.Get("HX-Request") == "true"
	// These endpoints are HTMX-only.
	if !isHTMX {
		http.Error(w, "this endpoint requires HTMX", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	priorityStr := r.FormValue("priority")
	priority := 0
	var errMsg string
	if priorityStr != "" {
		p, parseErr := strconv.Atoi(priorityStr)
		if parseErr != nil {
			errMsg = "priority must be a non-negative integer"
		} else {
			priority = p
		}
	}

	vals := templates.RuleFormValues{
		ID:       r.FormValue("id"),
		Priority: priorityStr,
		Method:   r.FormValue("method"),
		Scheme:   r.FormValue("scheme"),
		Host:     r.FormValue("host"),
		Path:     r.FormValue("path"),
		Comment:  r.FormValue("comment"),
	}

	store := storeForListType(h.cfg, h.listType)

	rule := reqrules.Rule{
		ID:       vals.ID,
		Priority: priority,
		Method:   vals.Method,
		Scheme:   vals.Scheme,
		Host:     vals.Host,
		Path:     vals.Path,
		Comment:  vals.Comment,
		Runtime:  true,
	}

	if errMsg == "" {
		if err := rule.Validate(); err != nil {
			errMsg = err.Error()
		} else {
			// Reject duplicate IDs — Add() would silently replace an existing rule.
			store.Range(func(existing reqrules.Rule) bool {
				if existing.ID == rule.ID {
					errMsg = fmt.Sprintf("rule ID %q already exists", rule.ID)
					return false
				}
				return true
			})
			if errMsg == "" {
				store.Add(rule)
				// Re-evaluate pending requests so any that now match the new rule
				// are resolved immediately (approved or denied) instead of waiting
				// for their timeout (IDEA.md D-REEVALUATE-8).
				h.cfg.Pending.ReevaluatePending()
				if err := rules.Save(store); err != nil {
					slog.Error("failed to persist runtime rules after add", "error", err)
				}
			}
		}
	}

	status := http.StatusOK
	section := buildSection(h.listType, store, templates.RuleFormValues{}, "")
	if errMsg != "" {
		status = http.StatusUnprocessableEntity
		section = buildSection(h.listType, store, vals, errMsg)
	}
	renderSectionBody(w, r, section, status)
}

// --- Delete rule (DELETE /api/rules/{whitelist|blacklist}/{id}) ---

type rulesDeleteHandler struct {
	cfg      *RulesConfig
	listType string
}

// NewRulesDeleteHandler returns an http.Handler for DELETE /api/rules/{whitelist|blacklist}/{id}.
// Must be wrapped with AuthMiddleware.
func NewRulesDeleteHandler(cfg *RulesConfig, listType string) http.Handler {
	return &rulesDeleteHandler{cfg: cfg, listType: listType}
}

// --- Edit rule (PUT /api/rules/{whitelist|blacklist}/{id}) ---

type rulesEditHandler struct {
	cfg      *RulesConfig
	listType string
}

// NewRulesEditHandler returns an http.Handler for PUT /api/rules/{whitelist|blacklist}/{id}.
// Must be wrapped with AuthMiddleware.
// 200: returns full <tbody> fragment (rule updated, correct sort order).
// 422: returns plain-text error message (JS injects inline into the edit row).
func NewRulesEditHandler(cfg *RulesConfig, listType string) http.Handler {
	return &rulesEditHandler{cfg: cfg, listType: listType}
}

func (h *rulesEditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isHTMX := r.Header.Get("HX-Request") == "true"
	// These endpoints are HTMX-only — reject direct browser access.
	if !isHTMX {
		http.Error(w, "this endpoint requires HTMX", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing rule id", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	store := storeForListType(h.cfg, h.listType)

	// Verify the rule exists and is runtime-editable.
	var found, isRuntime bool
	store.Range(func(rule reqrules.Rule) bool {
		if rule.ID == id {
			found = true
			isRuntime = rule.Runtime
			return false
		}
		return true
	})
	if !found {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if !isRuntime {
		http.Error(w, "cannot edit static rules via WebUI", http.StatusForbidden)
		return
	}

	// Parse priority — empty string means keep 0.
	priorityStr := r.FormValue("priority")
	priority := 0
	if priorityStr != "" {
		p, err := strconv.Atoi(priorityStr)
		if err != nil {
			http.Error(w, "priority must be a non-negative integer", http.StatusUnprocessableEntity)
			return
		}
		priority = p
	}

	updated := reqrules.Rule{
		ID:       id,
		Priority: priority,
		Method:   r.FormValue("method"),
		Scheme:   r.FormValue("scheme"),
		Host:     r.FormValue("host"),
		Path:     r.FormValue("path"),
		Comment:  r.FormValue("comment"),
		Runtime:  true,
	}

	if err := updated.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	store.Add(updated) // idempotent replace by ID
	// Re-evaluate pending requests: the edited rule may now match pending entries.
	h.cfg.Pending.ReevaluatePending()
	if err := rules.Save(store); err != nil {
		slog.Error("failed to persist runtime rules after edit", "error", err)
	}

	section := buildSection(h.listType, store, templates.RuleFormValues{}, "")
	renderSectionBody(w, r, section, http.StatusOK)
}

func (h *rulesDeleteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isHTMX := r.Header.Get("HX-Request") == "true"
	// These endpoints are HTMX-only.
	if !isHTMX {
		http.Error(w, "this endpoint requires HTMX", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing rule id", http.StatusBadRequest)
		return
	}

	store := storeForListType(h.cfg, h.listType)

	// Find the rule and verify it is runtime-editable.
	var found, isRuntime bool
	store.Range(func(rule reqrules.Rule) bool {
		if rule.ID == id {
			found = true
			isRuntime = rule.Runtime
			return false
		}
		return true
	})

	if !found {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if !isRuntime {
		http.Error(w, "cannot delete static rules via WebUI", http.StatusForbidden)
		return
	}

	store.Del(id)
	if err := rules.Save(store); err != nil {
		slog.Error("failed to persist runtime rules after delete", "error", err)
	}

	section := buildSection(h.listType, store, templates.RuleFormValues{}, "")
	renderSectionBody(w, r, section, http.StatusOK)
}
