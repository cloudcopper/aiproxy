package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseArgs_DaemonMode(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "no delimiter",
			args: []string{"aiproxy", "--listen", ":8080"},
		},
		{
			name: "only program name",
			args: []string{"aiproxy"},
		},
		{
			name: "multiple flags",
			args: []string{"aiproxy", "--listen", ":8080", "--admin-secret", "test123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			configArgs, cmdExec := parseArgs(tt.args)

			is.Equal(tt.args, configArgs)
			is.Nil(cmdExec)
		})
	}
}

func TestParseArgs_WrapperMode(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		expectedConfig  []string
		expectedCommand string
		expectedArgs    []string
	}{
		{
			name:            "simple command",
			args:            []string{"aiproxy", "--", "curl", "https://github.com"},
			expectedConfig:  []string{"aiproxy"},
			expectedCommand: "curl",
			expectedArgs:    []string{"https://github.com"},
		},
		{
			name:            "command with multiple args",
			args:            []string{"aiproxy", "--", "git", "clone", "https://github.com/golang/go", "/tmp/go"},
			expectedConfig:  []string{"aiproxy"},
			expectedCommand: "git",
			expectedArgs:    []string{"clone", "https://github.com/golang/go", "/tmp/go"},
		},
		{
			name:            "with proxy flags before delimiter",
			args:            []string{"aiproxy", "--listen", ":8080", "--admin-secret", "test123", "--", "curl", "https://github.com"},
			expectedConfig:  []string{"aiproxy", "--listen", ":8080", "--admin-secret", "test123"},
			expectedCommand: "curl",
			expectedArgs:    []string{"https://github.com"},
		},
		{
			name:            "command without args",
			args:            []string{"aiproxy", "--", "uptime"},
			expectedConfig:  []string{"aiproxy"},
			expectedCommand: "uptime",
			expectedArgs:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			configArgs, cmdExec := parseArgs(tt.args)

			is.Equal(tt.expectedConfig, configArgs)
			is.NotNil(cmdExec)
			is.Equal(tt.expectedCommand, cmdExec.Command)
			is.Equal(tt.expectedArgs, cmdExec.Args)
		})
	}
}

func TestParseArgs_EmptyCommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "delimiter at end",
			args: []string{"aiproxy", "--"},
		},
		{
			name: "delimiter with flags before",
			args: []string{"aiproxy", "--listen", ":8080", "--"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			configArgs, cmdExec := parseArgs(tt.args)

			expectedConfig := []string{"aiproxy"}
			if len(tt.args) > 2 {
				expectedConfig = tt.args[:len(tt.args)-1]
			}
			is.Equal(expectedConfig, configArgs)
			is.NotNil(cmdExec)
			is.Equal("", cmdExec.Command)
			is.Nil(cmdExec.Args)
		})
	}
}

func TestParseArgs_CommandWithDelimiterInArgs(t *testing.T) {
	is := assert.New(t)

	// Command arguments can contain "--" - only first one is the delimiter
	args := []string{"aiproxy", "--", "git", "log", "--since", "yesterday", "--", "file.txt"}

	configArgs, cmdExec := parseArgs(args)

	is.Equal([]string{"aiproxy"}, configArgs)
	is.NotNil(cmdExec)
	is.Equal("git", cmdExec.Command)
	is.Equal([]string{"log", "--since", "yesterday", "--", "file.txt"}, cmdExec.Args)
}

func TestResolvePaths(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name         string
		inputCert    string
		inputKey     string
		expectedCert string
		expectedKey  string
	}{
		{
			name:         "relative with dot-slash prefix",
			inputCert:    "./certs/ca-cert.pem",
			inputKey:     "./certs/ca-key.pem",
			expectedCert: filepath.Join(cwd, "certs/ca-cert.pem"),
			expectedKey:  filepath.Join(cwd, "certs/ca-key.pem"),
		},
		{
			name:         "relative without prefix",
			inputCert:    "certs/ca-cert.pem",
			inputKey:     "certs/ca-key.pem",
			expectedCert: filepath.Join(cwd, "certs/ca-cert.pem"),
			expectedKey:  filepath.Join(cwd, "certs/ca-key.pem"),
		},
		{
			name:         "already absolute",
			inputCert:    "/etc/ssl/ca-cert.pem",
			inputKey:     "/etc/ssl/ca-key.pem",
			expectedCert: "/etc/ssl/ca-cert.pem",
			expectedKey:  "/etc/ssl/ca-key.pem",
		},
		{
			name:         "cert and key in different relative dirs",
			inputCert:    "mydir/cert.pem",
			inputKey:     "otherdir/key.pem",
			expectedCert: filepath.Join(cwd, "mydir/cert.pem"),
			expectedKey:  filepath.Join(cwd, "otherdir/key.pem"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			is := assert.New(t)

			cfg := &Config{TLSCert: tt.inputCert, TLSKey: tt.inputKey}
			require.NoError(t, resolvePaths(cfg))

			is.Equal(tt.expectedCert, cfg.TLSCert)
			is.Equal(tt.expectedKey, cfg.TLSKey)
			is.True(filepath.IsAbs(cfg.TLSCert), "TLSCert must be absolute")
			is.True(filepath.IsAbs(cfg.TLSKey), "TLSKey must be absolute")
		})
	}
}
