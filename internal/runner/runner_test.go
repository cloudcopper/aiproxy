package runner

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/cloudcopper/aiproxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEnvironment(t *testing.T) {
	proxyAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	certPath := "/path/to/ca-cert.pem"

	env := buildEnvironment(proxyAddr, certPath)

	// Convert to map for easier testing
	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Verify proxy URL format
	expectedProxyURL := "http://127.0.0.1:12345"
	assert.Equal(t, expectedProxyURL, envMap["http_proxy"])
	assert.Equal(t, expectedProxyURL, envMap["https_proxy"])
	assert.Equal(t, expectedProxyURL, envMap["HTTP_PROXY"])
	assert.Equal(t, expectedProxyURL, envMap["HTTPS_PROXY"])

	// Verify CA cert paths
	assert.Equal(t, certPath, envMap["SSL_CERT_FILE"])
	assert.Equal(t, certPath, envMap["CURL_CA_BUNDLE"])
	assert.Equal(t, certPath, envMap["REQUESTS_CA_BUNDLE"])
	assert.Equal(t, certPath, envMap["NODE_EXTRA_CA_CERTS"])
}

func TestBuildEnvironment_InheritsParentEnv(t *testing.T) {
	// Set a unique env var in parent
	testKey := "TEST_RUNNER_UNIQUE_VAR"
	testValue := "test_value_12345"
	os.Setenv(testKey, testValue)
	defer os.Unsetenv(testKey)

	env := buildEnvironment(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "/cert.pem")

	// Verify parent env var is inherited
	found := false
	for _, e := range env {
		if strings.HasPrefix(e, testKey+"=") {
			assert.Equal(t, testKey+"="+testValue, e)
			found = true
			break
		}
	}
	assert.True(t, found, "Parent environment variable should be inherited")
}

func TestRun_SuccessfulCommand(t *testing.T) {
	cmdExec := &config.CommandExecution{
		Command: "echo",
		Args:    []string{"hello"},
	}

	ctx := context.Background()
	exitCode := Run(ctx, cmdExec, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "/tmp/cert.pem")

	assert.Equal(t, 0, exitCode, "echo command should exit with code 0")
}

func TestRun_FailedCommand(t *testing.T) {
	// Use 'sh -c "exit 42"' to exit with specific code
	cmdExec := &config.CommandExecution{
		Command: "sh",
		Args:    []string{"-c", "exit 42"},
	}

	ctx := context.Background()
	exitCode := Run(ctx, cmdExec, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "/tmp/cert.pem")

	assert.Equal(t, 42, exitCode, "Command should exit with code 42")
}

func TestRun_CommandNotFound(t *testing.T) {
	cmdExec := &config.CommandExecution{
		Command: "nonexistent-command-xyz-12345",
		Args:    []string{},
	}

	ctx := context.Background()
	exitCode := Run(ctx, cmdExec, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "/tmp/cert.pem")

	// Command not found should return exit code 1
	assert.Equal(t, 1, exitCode, "Non-existent command should exit with code 1")
}

func TestRun_ContextCancellation(t *testing.T) {
	cmdExec := &config.CommandExecution{
		Command: "sleep",
		Args:    []string{"10"},
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	exitCode := Run(ctx, cmdExec, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}, "/tmp/cert.pem")

	// Cancelled command should exit with non-zero
	assert.NotEqual(t, 0, exitCode, "Cancelled command should exit with non-zero code")
}

func TestRun_SetsEnvironmentVariables(t *testing.T) {
	// Use a shell script to verify environment variables are set
	cmdExec := &config.CommandExecution{
		Command: "sh",
		Args: []string{"-c", `
			test "$HTTP_PROXY" = "http://127.0.0.1:9999"  || exit 1
			test "$HTTPS_PROXY" = "http://127.0.0.1:9999" || exit 2
			test "$SSL_CERT_FILE" = "/test/cert.pem"      || exit 3
			test "$CURL_CA_BUNDLE" = "/test/cert.pem"     || exit 4
			exit 0
		`},
	}

	ctx := context.Background()
	exitCode := Run(ctx, cmdExec, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}, "/test/cert.pem")

	require.Equal(t, 0, exitCode, "Environment variables should be set correctly")
}
