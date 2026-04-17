package reqrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidate tests rule validation logic.
func TestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
	}{
		// Valid rules
		{
			name:    "minimal valid rule (id only)",
			rule:    Rule{ID: "r1"},
			wantErr: false,
		},
		{
			name:    "valid GET rule",
			rule:    Rule{ID: "r1", Method: "GET", Scheme: "https", Host: "api.example.com", Path: "/v1/*"},
			wantErr: false,
		},
		{
			name:    "valid POST rule",
			rule:    Rule{ID: "r2", Method: "POST", Scheme: "https", Host: "api.openai.com", Path: "/**"},
			wantErr: false,
		},
		{
			name:    "valid wildcard method (omitted)",
			rule:    Rule{ID: "r3", Scheme: "https", Host: "example.com", Path: "/**"},
			wantErr: false,
		},
		{
			name:    "valid CONNECT rule",
			rule:    Rule{ID: "r4", Method: "CONNECT", Host: "proxy.example.com"},
			wantErr: false,
		},
		{
			name:    "valid with port",
			rule:    Rule{ID: "r5", Port: 8080},
			wantErr: false,
		},
		{
			name:    "valid with port_range",
			rule:    Rule{ID: "r6", PortRange: &[2]int{8080, 9090}},
			wantErr: false,
		},
		{
			name:    "valid with port_ranges",
			rule:    Rule{ID: "r7", PortRanges: [][2]int{{80, 80}, {443, 443}}},
			wantErr: false,
		},
		{
			name:    "valid with rpm",
			rule:    Rule{ID: "r8", RPM: 100},
			wantErr: false,
		},
		{
			name:    "valid with host glob pattern",
			rule:    Rule{ID: "r9", Host: "*.example.com"},
			wantErr: false,
		},
		{
			name:    "valid with double-star host glob",
			rule:    Rule{ID: "r10", Host: "**.example.com"},
			wantErr: false,
		},
		{
			name:    "valid with path glob",
			rule:    Rule{ID: "r11", Path: "/v1/**"},
			wantErr: false,
		},
		{
			name:    "valid positive priority",
			rule:    Rule{ID: "r1", Priority: 10},
			wantErr: false,
		},
		{
			name:    "valid rpm zero (absent)",
			rule:    Rule{ID: "r12", RPM: 0},
			wantErr: false,
		},
		{
			name:    "valid http scheme",
			rule:    Rule{ID: "r13", Scheme: "http"},
			wantErr: false,
		},

		// Invalid rules
		{
			name:    "missing id",
			rule:    Rule{},
			wantErr: true,
		},
		{
			name:    "empty id",
			rule:    Rule{ID: ""},
			wantErr: true,
		},
		{
			name:    "invalid method",
			rule:    Rule{ID: "r1", Method: "INVALID"},
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			rule:    Rule{ID: "r1", Scheme: "ftp"},
			wantErr: true,
		},
		{
			name:    "port and port_range both set",
			rule:    Rule{ID: "r1", Port: 80, PortRange: &[2]int{80, 443}},
			wantErr: true,
		},
		{
			name:    "port and port_ranges both set",
			rule:    Rule{ID: "r1", Port: 80, PortRanges: [][2]int{{80, 80}}},
			wantErr: true,
		},
		{
			name:    "port_range and port_ranges both set",
			rule:    Rule{ID: "r1", PortRange: &[2]int{80, 443}, PortRanges: [][2]int{{80, 80}}},
			wantErr: true,
		},
		{
			name:    "port_range low bound zero",
			rule:    Rule{ID: "r1", PortRange: &[2]int{0, 443}},
			wantErr: true,
		},
		{
			name:    "port_range low > high",
			rule:    Rule{ID: "r1", PortRange: &[2]int{9090, 8080}},
			wantErr: true,
		},
		{
			name:    "port_ranges empty slice",
			rule:    Rule{ID: "r1", PortRanges: [][2]int{}},
			wantErr: true,
		},
		{
			name:    "port_ranges entry invalid",
			rule:    Rule{ID: "r1", PortRanges: [][2]int{{0, 80}}},
			wantErr: true,
		},
		{
			name:    "negative priority",
			rule:    Rule{ID: "r1", Priority: -1},
			wantErr: true,
		},
		{
			name:    "negative rpm",
			rule:    Rule{ID: "r1", RPM: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			err := tt.rule.Validate()
			if tt.wantErr {
				is.Error(err, "Validate(%v) should return error", tt.rule)
				return
			}
			is.NoError(err, "Validate(%v) should not return error", tt.rule)
		})
	}
}

// TestAddInvalidPanics tests that Add panics on invalid rules.
func TestAddInvalidPanics(t *testing.T) {
	t.Parallel()
	is := assert.New(t)

	r := New()

	is.Panics(func() {
		r.Add(Rule{}) // missing ID
	}, "Expected Add to panic on rule with missing ID")

	is.Panics(func() {
		r.Add(Rule{ID: "r1", Method: "INVALID"}) // bad method
	}, "Expected Add to panic on rule with invalid method")
}
