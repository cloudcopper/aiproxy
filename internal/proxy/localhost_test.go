package proxy

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLocalhostTarget(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"Hostname localhost", "http://localhost:8080/path", true},
		{"IPv4 127.0.0.1", "http://127.0.0.1:8080/path", true},
		{"IPv4 127.0.0.2", "http://127.0.0.2/path", true},
		{"IPv6 ::1", "http://[::1]:8080/path", true},
		{"Hostname example.com", "http://example.com/path", false},
		{"IPv4 public 8.8.8.8", "http://8.8.8.8/path", false},
		{"Empty hostname", "http:///path", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.url, nil)
			require.NoError(t, err)
			result := isLocalhostTarget(req)
			assert.Equal(t, tt.expected, result, "URL: %s", tt.url)
		})
	}
}
