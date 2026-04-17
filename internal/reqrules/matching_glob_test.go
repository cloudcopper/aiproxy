package reqrules

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchHostGlobSemantics verifies dot-as-separator semantics for host matching.
func TestMatchHostGlobSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		hostPattern string
		reqURL      string
		wantMatched bool
	}{
		{
			name:        "exact host match",
			hostPattern: "api.openai.com",
			reqURL:      "https://api.openai.com/v1",
			wantMatched: true,
		},
		{
			name:        "exact host no match",
			hostPattern: "api.openai.com",
			reqURL:      "https://other.openai.com/v1",
			wantMatched: false,
		},
		{
			name:        "single wildcard matches one label",
			hostPattern: "*.openai.com",
			reqURL:      "https://api.openai.com/v1",
			wantMatched: true,
		},
		{
			name:        "single wildcard does not match two labels",
			hostPattern: "*.openai.com",
			reqURL:      "https://deep.api.openai.com/v1",
			wantMatched: false,
		},
		{
			name:        "double wildcard matches any depth",
			hostPattern: "**.openai.com",
			reqURL:      "https://api.openai.com/v1",
			wantMatched: true,
		},
		{
			name:        "double wildcard matches deep subdomain",
			hostPattern: "**.openai.com",
			reqURL:      "https://deep.api.openai.com/v1",
			wantMatched: true,
		},
		{
			name:        "explicit any host wildcard",
			hostPattern: "*",
			reqURL:      "https://api.openai.com/v1",
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			r := New()
			r.Add(Rule{ID: "test-rule", Host: tt.hostPattern})

			req, err := http.NewRequest("GET", tt.reqURL, nil)
			must.NoError(err)

			_, matched := r.Match(req)
			is.Equal(tt.wantMatched, matched, "hostPattern=%q reqURL=%q", tt.hostPattern, tt.reqURL)
		})
	}
}
