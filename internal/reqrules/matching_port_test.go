package reqrules

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMatchPortConstraints tests port-based rule matching.
func TestMatchPortConstraints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rule        Rule
		reqURL      string
		wantMatched bool
	}{
		{
			name:        "exact port match",
			rule:        Rule{ID: "r", Port: 8080},
			reqURL:      "http://example.com:8080/path",
			wantMatched: true,
		},
		{
			name:        "exact port no match",
			rule:        Rule{ID: "r", Port: 8080},
			reqURL:      "http://example.com:9090/path",
			wantMatched: false,
		},
		{
			name:        "port range match",
			rule:        Rule{ID: "r", PortRange: &[2]int{8000, 9000}},
			reqURL:      "http://example.com:8080/path",
			wantMatched: true,
		},
		{
			name:        "port range low bound",
			rule:        Rule{ID: "r", PortRange: &[2]int{8080, 9090}},
			reqURL:      "http://example.com:8080/path",
			wantMatched: true,
		},
		{
			name:        "port range high bound",
			rule:        Rule{ID: "r", PortRange: &[2]int{8080, 9090}},
			reqURL:      "http://example.com:9090/path",
			wantMatched: true,
		},
		{
			name:        "port range below range",
			rule:        Rule{ID: "r", PortRange: &[2]int{8080, 9090}},
			reqURL:      "http://example.com:8079/path",
			wantMatched: false,
		},
		{
			name:        "port ranges match first range",
			rule:        Rule{ID: "r", PortRanges: [][2]int{{80, 80}, {443, 443}, {8080, 9090}}},
			reqURL:      "http://example.com:80/path",
			wantMatched: true,
		},
		{
			name:        "port ranges match last range",
			rule:        Rule{ID: "r", PortRanges: [][2]int{{80, 80}, {443, 443}, {8080, 9090}}},
			reqURL:      "http://example.com:8500/path",
			wantMatched: true,
		},
		{
			name:        "port ranges no match",
			rule:        Rule{ID: "r", PortRanges: [][2]int{{80, 80}, {443, 443}}},
			reqURL:      "http://example.com:8080/path",
			wantMatched: false,
		},
		{
			name:        "no port constraint matches any port",
			rule:        Rule{ID: "r", Host: "example.com"},
			reqURL:      "http://example.com:12345/path",
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			r := New()
			r.Add(tt.rule)

			req, err := http.NewRequest("GET", tt.reqURL, nil)
			must.NoError(err)

			_, matched := r.Match(req)
			is.Equal(tt.wantMatched, matched)
		})
	}
}

// TestMatchPortDefaultInference tests that http URLs without an explicit port
// are treated as port 80, and https URLs as port 443.
func TestMatchPortDefaultInference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		rule        Rule
		reqURL      string
		wantMatched bool
	}{
		{
			name:        "http URL without port matches Port:80 rule",
			rule:        Rule{ID: "r", Port: 80},
			reqURL:      "http://example.com/path",
			wantMatched: true,
		},
		{
			name:        "http URL with explicit :80 matches Port:80 rule",
			rule:        Rule{ID: "r", Port: 80},
			reqURL:      "http://example.com:80/path",
			wantMatched: true,
		},
		{
			name:        "https URL without port matches Port:443 rule",
			rule:        Rule{ID: "r", Port: 443},
			reqURL:      "https://example.com/path",
			wantMatched: true,
		},
		{
			name:        "https URL with explicit :443 matches Port:443 rule",
			rule:        Rule{ID: "r", Port: 443},
			reqURL:      "https://example.com:443/path",
			wantMatched: true,
		},
		{
			name:        "http URL without port does not match Port:443 rule",
			rule:        Rule{ID: "r", Port: 443},
			reqURL:      "http://example.com/path",
			wantMatched: false,
		},
		{
			name:        "https URL without port does not match Port:80 rule",
			rule:        Rule{ID: "r", Port: 80},
			reqURL:      "https://example.com/path",
			wantMatched: false,
		},
		{
			name:        "http URL without port matches PortRange containing 80",
			rule:        Rule{ID: "r", PortRange: &[2]int{80, 90}},
			reqURL:      "http://example.com/path",
			wantMatched: true,
		},
		{
			name:        "https URL without port matches PortRanges containing 443",
			rule:        Rule{ID: "r", PortRanges: [][2]int{{80, 80}, {443, 443}}},
			reqURL:      "https://example.com/path",
			wantMatched: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)
			must := require.New(t)

			r := New()
			r.Add(tt.rule)

			req, err := http.NewRequest("GET", tt.reqURL, nil)
			must.NoError(err)

			_, matched := r.Match(req)
			is.Equal(tt.wantMatched, matched)
		})
	}
}
