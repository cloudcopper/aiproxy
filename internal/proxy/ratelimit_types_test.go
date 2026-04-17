package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- RequestID tests ---

func TestRequestID_String(t *testing.T) {
	tests := []struct {
		id   RequestID
		want string
	}{
		{1, "req_1"},
		{42, "req_42"},
		{100, "req_100"},
		{101, "req_101"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.id.String())
		})
	}
}

// --- DelayedRequestStatus tests ---

func TestDelayedRequestStatus_String(t *testing.T) {
	tests := []struct {
		status DelayedRequestStatus
		want   string
	}{
		{StatusPending, "pending"},
		{StatusSent, "sent"},
		{StatusCancelled, "cancelled"},
		{DelayedRequestStatus(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.status.String())
		})
	}
}
