package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"

	"github.com/cloudcopper/aiproxy/internal/config"
)

// Run executes a wrapped command with proxy environment variables.
// Returns the command's exit code.
//
// This function:
//   - Sets up environment variables (proxy URLs, CA cert paths)
//   - Forwards stdin/stdout/stderr to the command
//   - Logs command start and completion with exit code
//   - Returns command's exit code (or 1 on execution failure)
//
// The command runs with context cancellation support - if ctx is cancelled,
// the command process is terminated.
func Run(ctx context.Context, cmdExec *config.CommandExecution, proxyAddr net.Addr, certPath string) int {
	cmd := exec.CommandContext(ctx, cmdExec.Command, cmdExec.Args...)
	cmd.Env = buildEnvironment(proxyAddr, certPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	slog.Info("starting wrapped command",
		"command", cmdExec.Command,
		"args", cmdExec.Args,
	)

	err := cmd.Run()

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode := exitErr.ExitCode()
			slog.Info("command exited",
				"command", cmdExec.Command,
				"exit_code", exitCode,
			)
			return exitCode
		}
		slog.Error("failed to execute command",
			"command", cmdExec.Command,
			"error", err,
		)
		return 1
	}

	slog.Info("command completed successfully",
		"command", cmdExec.Command,
		"exit_code", 0,
	)
	return 0
}

// buildEnvironment creates environment variables for the wrapped command.
// Includes standard proxy vars (http_proxy, https_proxy, etc.) and
// CA certificate paths for various tools (curl, Python, Node.js, etc.).
//
// All parent process environment variables are inherited, with proxy-specific
// variables added/overridden.
func buildEnvironment(proxyAddr net.Addr, certPath string) []string {
	env := os.Environ()

	proxyURL := fmt.Sprintf("http://%s", proxyAddr)

	proxyVars := map[string]string{
		// Standard proxy environment variables (lowercase - most common)
		"http_proxy":  proxyURL,
		"https_proxy": proxyURL,

		// Standard proxy environment variables (uppercase - some tools)
		"HTTP_PROXY":  proxyURL,
		"HTTPS_PROXY": proxyURL,

		// CA certificate paths for various tools
		"SSL_CERT_FILE":       certPath, // OpenSSL, curl, Ruby
		"CURL_CA_BUNDLE":      certPath, // curl
		"REQUESTS_CA_BUNDLE":  certPath, // Python requests library
		"NODE_EXTRA_CA_CERTS": certPath, // Node.js

		// No proxy for localhost addresses to prevent proxy loops (optional, but common)
		"NO_PROXY": "localhost,127.0.0.1,::1",
	}

	for key, value := range proxyVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}
