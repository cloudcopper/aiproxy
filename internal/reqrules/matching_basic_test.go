package reqrules

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAddAndDel tests adding and removing rules.
func TestAddAndDel(t *testing.T) {
	t.Parallel()
	is := assert.New(t)
	must := require.New(t)

	r := New()

	r.Add(Rule{ID: "get-example", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"})
	r.Add(Rule{ID: "post-openai", Method: "POST", Scheme: "https", Host: "api.openai.com", Path: "/**"})

	req, err := http.NewRequest("GET", "https://api.example.com/v1/users", nil)
	must.NoError(err)

	rule, matched := r.Match(req)
	is.True(matched, "Expected rule to match after Add")
	is.Equal("get-example", rule.ID)

	r.Del("get-example")

	_, matched = r.Match(req)
	is.False(matched, "Expected no match after Del")
}

// TestAddIdempotentByID tests that adding a rule with the same ID replaces it.
func TestAddIdempotentByID(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()

	r.Add(Rule{ID: "rule1", Scheme: "https", Host: "api.example.com"})
	r.Add(Rule{ID: "rule1", Scheme: "https", Host: "api.example.com"}) // same ID, same content

	is.Equal(1, r.Count(), "Expected 1 rule after adding duplicate IDs")
}

// TestMatch tests request matching logic.
func TestMatch(t *testing.T) {
	t.Parallel()

	r := New()
	r.Add(Rule{ID: "get-api", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"})
	r.Add(Rule{ID: "post-openai", Method: "POST", Scheme: "https", Host: "api.openai.com", Path: "/**"})
	r.Add(Rule{ID: "trusted-any", Scheme: "https", Host: "trusted.example.com", Path: "/**"})

	tests := []struct {
		name        string
		method      string
		url         string
		wantID      string
		wantMatched bool
	}{
		{
			name:        "match GET rule",
			method:      "GET",
			url:         "https://api.example.com/v1/users",
			wantID:      "get-api",
			wantMatched: true,
		},
		{
			name:        "match POST rule",
			method:      "POST",
			url:         "https://api.openai.com/v1/chat/completions",
			wantID:      "post-openai",
			wantMatched: true,
		},
		{
			name:        "match wildcard method rule with GET",
			method:      "GET",
			url:         "https://trusted.example.com/anything",
			wantID:      "trusted-any",
			wantMatched: true,
		},
		{
			name:        "match wildcard method rule with POST",
			method:      "POST",
			url:         "https://trusted.example.com/anything",
			wantID:      "trusted-any",
			wantMatched: true,
		},
		{
			name:        "no match - wrong method",
			method:      "PUT",
			url:         "https://api.example.com/v1/users",
			wantID:      "",
			wantMatched: false,
		},
		{
			name:        "no match - wrong host",
			method:      "GET",
			url:         "https://different.example.com/users",
			wantID:      "",
			wantMatched: false,
		},
		{
			name:        "no match - wrong scheme",
			method:      "GET",
			url:         "http://api.example.com/v1/users",
			wantID:      "",
			wantMatched: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			req, err := http.NewRequest(tt.method, tt.url, nil)
			must.NoError(err)

			rule, matched := r.Match(req)

			is.Equal(tt.wantMatched, matched)
			if tt.wantMatched {
				is.Equal(tt.wantID, rule.ID)
			}
		})
	}
}
