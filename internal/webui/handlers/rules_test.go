package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cloudcopper/aiproxy/internal/reqrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRulesSource implements RulesSource with two pre-created stores.
type stubRulesSource struct {
	whitelist *reqrules.ReqRules
	blacklist *reqrules.ReqRules
}

func (s *stubRulesSource) Whitelist() *reqrules.ReqRules { return s.whitelist }
func (s *stubRulesSource) Blacklist() *reqrules.ReqRules { return s.blacklist }

var _ RulesSource = (*stubRulesSource)(nil)

// newStubRulesSource returns a source with empty stores ready for use.
func newStubRulesSource() *stubRulesSource {
	return &stubRulesSource{
		whitelist: reqrules.New(),
		blacklist: reqrules.New(),
	}
}

// addRule adds a rule to the store, marking it runtime or static.
func addRule(store *reqrules.ReqRules, id string, runtime bool) {
	store.Add(reqrules.Rule{
		ID:      id,
		Host:    "api.example.com",
		Runtime: runtime,
	})
}

func newTestRulesConfig(src RulesSource) (*RulesConfig, *stubPendingSource) {
	pendingStub := &stubPendingSource{}
	return &RulesConfig{
		Source:  src,
		Pending: pendingStub,
		Nav:     testNav, // reused from pending_test.go
	}, pendingStub
}

// postRulesForm sends a POST to /api/rules/{listType} with form values.
// Includes HX-Request header for HTMX endpoints.
func postRulesForm(t *testing.T, h http.Handler, target string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// deleteRule sends a DELETE to /api/rules/{listType}/{id}.
// Includes HX-Request header for HTMX endpoints.
func deleteRule(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, target, nil)
	req.Header.Set("HX-Request", "true")
	req.SetPathValue("id", target[strings.LastIndex(target, "/")+1:])
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- rulesTableBodyData ---

func TestRulesTableBodyData(t *testing.T) {
	t.Parallel()

	t.Run("nil store returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, rulesTableBodyData(nil))
	})

	t.Run("empty store returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, rulesTableBodyData(reqrules.New()))
	})

	t.Run("rules are returned in sorted order", func(t *testing.T) {
		t.Parallel()
		store := reqrules.New()
		store.Add(reqrules.Rule{ID: "z-rule", Host: "z.example.com", Runtime: true})
		store.Add(reqrules.Rule{ID: "a-rule", Host: "a.example.com", Runtime: false})

		rows := rulesTableBodyData(store)
		require.Len(t, rows, 2)
		assert.Equal(t, "a-rule", rows[0].ID)
		assert.Equal(t, "z-rule", rows[1].ID)
	})

	t.Run("runtime flag is preserved", func(t *testing.T) {
		t.Parallel()
		store := reqrules.New()
		store.Add(reqrules.Rule{ID: "rt", Host: "rt.example.com", Runtime: true})
		store.Add(reqrules.Rule{ID: "static", Host: "s.example.com", Runtime: false})

		rows := rulesTableBodyData(store)
		require.Len(t, rows, 2)
		// sorted: rt < static lexicographically (same priority 0)
		assert.Equal(t, "rt", rows[0].ID)
		assert.True(t, rows[0].Runtime)
		assert.Equal(t, "static", rows[1].ID)
		assert.False(t, rows[1].Runtime)
	})

	t.Run("priority is mapped correctly", func(t *testing.T) {
		t.Parallel()
		store := reqrules.New()
		store.Add(reqrules.Rule{ID: "low", Host: "low.example.com", Priority: 10, Runtime: true})
		store.Add(reqrules.Rule{ID: "high", Host: "high.example.com", Priority: 1, Runtime: true})

		rows := rulesTableBodyData(store)
		require.Len(t, rows, 2)
		// priority=1 sorts before priority=10
		assert.Equal(t, "high", rows[0].ID)
		assert.Equal(t, 1, rows[0].Priority)
		assert.Equal(t, "low", rows[1].ID)
		assert.Equal(t, 10, rows[1].Priority)
	})

	t.Run("all fields are mapped", func(t *testing.T) {
		t.Parallel()
		store := reqrules.New()
		store.Add(reqrules.Rule{
			ID:      "full",
			Comment: "my comment",
			Method:  "GET",
			Scheme:  "https",
			Host:    "api.example.com",
			Path:    "/v1/**",
			Runtime: true,
		})

		rows := rulesTableBodyData(store)
		require.Len(t, rows, 1)
		r := rows[0]
		assert.Equal(t, "full", r.ID)
		assert.Equal(t, "my comment", r.Comment)
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "https", r.Scheme)
		assert.Equal(t, "api.example.com", r.Host)
		assert.Equal(t, "/v1/**", r.Path)
		assert.True(t, r.Runtime)
	})
}

// --- Rules page handler ---

func TestRulesPageHandler(t *testing.T) {
	t.Parallel()

	src := newStubRulesSource()
	addRule(src.whitelist, "wl-static", false)
	addRule(src.whitelist, "wl-rt", true)
	addRule(src.blacklist, "bl-rt", true)

	cfg, _ := newTestRulesConfig(src)
	h := NewRulesPageHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/rules", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	is := assert.New(t)
	is.Equal(http.StatusOK, rec.Code)
	is.Contains(rec.Header().Get("Content-Type"), "text/html")
	body := rec.Body.String()
	is.Contains(body, "Whitelist Rules")
	is.Contains(body, "Blacklist Rules")
	is.Contains(body, "wl-static")
	is.Contains(body, "wl-rt")
	is.Contains(body, "bl-rt")
	// Static rule should show "static" badge, not a Delete button for that rule
	is.Contains(body, "static")
	// Runtime rules should have delete buttons
	is.Contains(body, "hx-delete")
	// Add-row inputs should be present for both lists
	is.Contains(body, "whitelist-add-row")
	is.Contains(body, "blacklist-add-row")
}

// --- Add rule handler ---

func TestRulesAddHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		listType        string
		form            url.Values
		preload         func(src *stubRulesSource) // optional: pre-populate store
		wantStatus      int
		wantContains    []string
		wantNotContains []string
		wantRuleAdded   bool
		wantReevaluate  bool // ReevaluatePending must be called on success
	}{
		{
			name:     "valid rule is added and tbody returned",
			listType: "whitelist",
			form: url.Values{
				"id":     {"new-rule"},
				"method": {"GET"},
				"scheme": {"https"},
				"host":   {"api.example.com"},
				"path":   {"/v1/**"},
			},
			wantStatus:    http.StatusOK,
			wantContains:  []string{"new-rule", "whitelist-rows"},
			wantRuleAdded: true,
			wantReevaluate: true,
		},
		{
			name:     "missing id returns 422 with error and form pre-populated",
			listType: "whitelist",
			form: url.Values{
				"id":   {""},
				"host": {"api.example.com"},
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"whitelist-rows", "rule id is required"},
		},
		{
			name:     "duplicate id returns 422 with error message",
			listType: "whitelist",
			form:     url.Values{"id": {"existing"}, "host": {"x.example.com"}},
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "existing", Host: "api.example.com", Runtime: true})
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"already exists"},
		},
		{
			name:     "invalid glob pattern returns 422 with validation error",
			listType: "blacklist",
			form: url.Values{
				"id":   {"bad-glob"},
				"host": {"[invalid"},
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"blacklist-rows"},
		},
		{
			name:     "valid rule with explicit priority is added",
			listType: "whitelist",
			form: url.Values{
				"id":       {"prio-rule"},
				"priority": {"5"},
				"host":     {"api.example.com"},
			},
			wantStatus:    http.StatusOK,
			wantContains:  []string{"prio-rule", "whitelist-rows"},
			wantRuleAdded: true,
			wantReevaluate: true,
		},
		{
			name:     "negative priority returns 422 with validation error",
			listType: "whitelist",
			form: url.Values{
				"id":       {"neg-prio"},
				"priority": {"-1"},
				"host":     {"api.example.com"},
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"priority"},
		},
		{
			name:     "non-integer priority returns 422 with error",
			listType: "whitelist",
			form: url.Values{
				"id":       {"bad-prio"},
				"priority": {"abc"},
				"host":     {"api.example.com"},
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"priority must be a non-negative integer"},
		},
		{
			name:          "valid rule added to blacklist",
			listType:      "blacklist",
			form:          url.Values{"id": {"bl-rule"}, "scheme": {"https"}, "host": {"evil.example.com"}},
			wantStatus:    http.StatusOK,
			wantContains:  []string{"bl-rule", "blacklist-rows"},
			wantRuleAdded: true,
			wantReevaluate: true,
		},
		{
			name:     "on error form values are preserved for user correction",
			listType: "whitelist",
			form: url.Values{
				"id":     {""},
				"method": {"POST"},
				"host":   {"typed-host.com"},
			},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"typed-host.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			src := newStubRulesSource()
			if tt.preload != nil {
				tt.preload(src)
			}
			var store *reqrules.ReqRules
			if tt.listType == "whitelist" {
				store = src.whitelist
			} else {
				store = src.blacklist
			}
			countBefore := store.Count()

			cfg, pendingStub := newTestRulesConfig(src)
			h := NewRulesAddHandler(cfg, tt.listType)
			rec := postRulesForm(t, h, "/api/rules/"+tt.listType, tt.form)

			is.Equal(tt.wantStatus, rec.Code)
			is.Contains(rec.Header().Get("Content-Type"), "text/html")
			body := rec.Body.String()
			for _, s := range tt.wantContains {
				is.Contains(body, s)
			}
			for _, s := range tt.wantNotContains {
				is.NotContains(body, s)
			}

			if tt.wantRuleAdded {
				is.Equal(countBefore+1, store.Count(), "store count should increase by 1")
			} else {
				is.Equal(countBefore, store.Count(), "store count should not change on error")
			}
			if tt.wantReevaluate {
				is.Equal(1, pendingStub.reevaluateCalled,
					"ReevaluatePending must be called exactly once after a successful rule add")
			} else {
				is.Equal(0, pendingStub.reevaluateCalled,
					"ReevaluatePending must NOT be called when the rule is rejected")
			}
		})
	}
}

// --- Delete rule handler ---

func TestRulesDeleteHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		listType     string
		targetID     string
		preload      func(src *stubRulesSource)
		wantStatus   int
		wantContains []string
		wantRuleGone bool
	}{
		{
			name:     "delete existing runtime rule returns updated tbody",
			listType: "whitelist",
			targetID: "rt-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "rt-rule", Host: "api.example.com", Runtime: true})
				src.whitelist.Add(reqrules.Rule{ID: "keeper", Host: "keep.example.com", Runtime: true})
			},
			wantStatus:   http.StatusOK,
			wantContains: []string{"whitelist-rows", "keeper"},
			wantRuleGone: true,
		},
		{
			name:     "delete static rule returns 403",
			listType: "whitelist",
			targetID: "static-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "static-rule", Host: "api.example.com", Runtime: false})
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "delete non-existent rule returns 404",
			listType:   "blacklist",
			targetID:   "ghost",
			preload:    func(_ *stubRulesSource) {},
			wantStatus: http.StatusNotFound,
		},
		{
			name:     "delete from blacklist works correctly",
			listType: "blacklist",
			targetID: "bl-rt",
			preload: func(src *stubRulesSource) {
				src.blacklist.Add(reqrules.Rule{ID: "bl-rt", Host: "evil.example.com", Runtime: true})
			},
			wantStatus:   http.StatusOK,
			wantContains: []string{"blacklist-rows"},
			wantRuleGone: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			src := newStubRulesSource()
			if tt.preload != nil {
				tt.preload(src)
			}
			var store *reqrules.ReqRules
			if tt.listType == "whitelist" {
				store = src.whitelist
			} else {
				store = src.blacklist
			}
			countBefore := store.Count()

			cfg, _ := newTestRulesConfig(src)
			h := NewRulesDeleteHandler(cfg, tt.listType)
			rec := deleteRule(t, h, "/api/rules/"+tt.listType+"/"+tt.targetID)

			is.Equal(tt.wantStatus, rec.Code)
			if tt.wantStatus == http.StatusOK {
				is.Contains(rec.Header().Get("Content-Type"), "text/html")
			}
			body := rec.Body.String()
			for _, s := range tt.wantContains {
				is.Contains(body, s)
			}
			if tt.wantRuleGone {
				is.Equal(countBefore-1, store.Count(), "store count should decrease by 1")
				is.NotContains(body, tt.targetID)
			}
		})
	}
}

// putRule sends a PUT to /api/rules/{listType}/{id} with form values.
// Includes HX-Request header for HTMX endpoints.
func putRule(t *testing.T, h http.Handler, target string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	// Extract id from target path for PathValue.
	req.SetPathValue("id", target[strings.LastIndex(target, "/")+1:])
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- Edit rule handler (PUT) ---

func TestRulesEditHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		listType       string
		targetID       string
		form           url.Values
		preload        func(src *stubRulesSource)
		wantStatus     int
		wantContains   []string
		wantBodyIsHTML bool                                     // true → 200 tbody; false → plain text error
		checkRule      func(t *testing.T, src *stubRulesSource) // optional post-condition
	}{
		{
			name:     "valid edit updates rule and returns tbody",
			listType: "whitelist",
			targetID: "rt-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "rt-rule", Host: "old.example.com", Priority: 0, Runtime: true})
			},
			form: url.Values{
				"priority": {"5"},
				"method":   {"GET"},
				"scheme":   {"https"},
				"host":     {"new.example.com"},
				"path":     {"/v2/**"},
				"comment":  {"updated"},
			},
			wantStatus:     http.StatusOK,
			wantContains:   []string{"whitelist-rows", "rt-rule", "new.example.com"},
			wantBodyIsHTML: true,
			checkRule: func(t *testing.T, src *stubRulesSource) {
				rows := rulesTableBodyData(src.whitelist)
				require.Len(t, rows, 1)
				assert.Equal(t, "new.example.com", rows[0].Host)
				assert.Equal(t, 5, rows[0].Priority)
				assert.Equal(t, "GET", rows[0].Method)
				assert.Equal(t, "updated", rows[0].Comment)
			},
		},
		{
			name:     "rule count unchanged after edit (no add or delete)",
			listType: "whitelist",
			targetID: "rt-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "rt-rule", Host: "a.example.com", Runtime: true})
				src.whitelist.Add(reqrules.Rule{ID: "other", Host: "b.example.com", Runtime: true})
			},
			form:           url.Values{"host": {"c.example.com"}},
			wantStatus:     http.StatusOK,
			wantBodyIsHTML: true,
			checkRule: func(t *testing.T, src *stubRulesSource) {
				assert.Equal(t, 2, src.whitelist.Count(), "edit must not change rule count")
			},
		},
		{
			name:       "non-existent rule returns 404",
			listType:   "whitelist",
			targetID:   "ghost",
			preload:    func(_ *stubRulesSource) {},
			form:       url.Values{"host": {"x.example.com"}},
			wantStatus: http.StatusNotFound,
		},
		{
			name:     "static rule returns 403",
			listType: "whitelist",
			targetID: "static-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "static-rule", Host: "s.example.com", Runtime: false})
			},
			form:       url.Values{"host": {"x.example.com"}},
			wantStatus: http.StatusForbidden,
		},
		{
			name:     "negative priority returns 422 plain text",
			listType: "blacklist",
			targetID: "bl-rule",
			preload: func(src *stubRulesSource) {
				src.blacklist.Add(reqrules.Rule{ID: "bl-rule", Host: "evil.example.com", Runtime: true})
			},
			form:         url.Values{"priority": {"-1"}, "host": {"evil.example.com"}},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"priority"},
		},
		{
			name:     "non-integer priority returns 422 plain text",
			listType: "whitelist",
			targetID: "rt-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "rt-rule", Host: "a.example.com", Runtime: true})
			},
			form:         url.Values{"priority": {"abc"}, "host": {"a.example.com"}},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"non-negative integer"},
		},
		{
			name:     "invalid glob host returns 422 plain text",
			listType: "whitelist",
			targetID: "rt-rule",
			preload: func(src *stubRulesSource) {
				src.whitelist.Add(reqrules.Rule{ID: "rt-rule", Host: "a.example.com", Runtime: true})
			},
			form:         url.Values{"host": {"[invalid"}},
			wantStatus:   http.StatusUnprocessableEntity,
			wantContains: []string{"host"},
		},
		{
			name:     "edit on blacklist works correctly",
			listType: "blacklist",
			targetID: "bl-rule",
			preload: func(src *stubRulesSource) {
				src.blacklist.Add(reqrules.Rule{ID: "bl-rule", Host: "evil.example.com", Runtime: true})
			},
			form:           url.Values{"host": {"evil2.example.com"}, "scheme": {"https"}},
			wantStatus:     http.StatusOK,
			wantContains:   []string{"blacklist-rows", "evil2.example.com"},
			wantBodyIsHTML: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			src := newStubRulesSource()
			if tt.preload != nil {
				tt.preload(src)
			}

			cfg, _ := newTestRulesConfig(src)
			h := NewRulesEditHandler(cfg, tt.listType)
			rec := putRule(t, h, "/api/rules/"+tt.listType+"/"+tt.targetID, tt.form)

			is.Equal(tt.wantStatus, rec.Code)
			body := rec.Body.String()
			for _, s := range tt.wantContains {
				is.Contains(body, s)
			}
			if tt.wantBodyIsHTML {
				is.Contains(rec.Header().Get("Content-Type"), "text/html")
			}
			if tt.checkRule != nil {
				tt.checkRule(t, src)
			}
		})
	}
}
