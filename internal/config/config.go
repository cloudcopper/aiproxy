package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jessevdk/go-flags"
)

// Config holds all configuration for AIProxy.
// Flags take precedence over environment variables.
type Config struct {
	// Proxy settings
	Listen      string `long:"listen" env:"AIPROXY_LISTEN" default:"localhost:0" description:"Proxy listen address"`
	WebUIListen string `long:"webui-listen" env:"AIPROXY_WEBUI_LISTEN" default:"" description:"WebUI listen address (empty = disabled)"`

	// Rule file paths (static, user-managed)
	BlacklistRules string `long:"blacklist-rules" env:"AIPROXY_BLACKLIST_RULES" default:"rules/blacklist.json" description:"Blacklist rules file (JSON array of rule strings)"`
	WhitelistRules string `long:"whitelist-rules" env:"AIPROXY_WHITELIST_RULES" default:"rules/whitelist.json" description:"Whitelist rules file (JSON array of rule strings)"`

	// Runtime rule file paths (proxy-managed via WebUI, Phase 6 features)
	RTBlacklistRules string `long:"rt-blacklist-rules" env:"AIPROXY_RT_BLACKLIST_RULES" default:"data/blacklist2.json" description:"Runtime blacklist rules file, WebUI-managed"`
	RTWhitelistRules string `long:"rt-whitelist-rules" env:"AIPROXY_RT_WHITELIST_RULES" default:"data/whitelist2.json" description:"Runtime whitelist rules file, WebUI-managed"`

	// TLS certificate file paths
	TLSCert string `long:"tls-cert" env:"AIPROXY_TLS_CERT" default:"./certs/ca-cert.pem" description:"TLS certificate file path (auto-generate if missing)"`
	TLSKey  string `long:"tls-key" env:"AIPROXY_TLS_KEY" default:"./certs/ca-key.pem" description:"TLS private key file path (auto-generate if missing)"`

	// Authentication
	AdminSecret string `long:"admin-secret" env:"AIPROXY_ADMIN_SECRET" description:"Admin authentication secret (optional; WebUI login disabled if empty)"`

	// Security
	InsecureCerts bool `long:"insecure-certs" env:"AIPROXY_INSECURE_CERTS" description:"Allow insecure certificates (validation errors become warnings)"`

	// Behavior settings
	PendingTimeout  time.Duration `long:"pending-timeout" env:"AIPROXY_PENDING_TIMEOUT" default:"120s" description:"Pending request timeout"`
	GlobalRateLimit int           `long:"global-rate-limit" env:"AIPROXY_GLOBAL_RATE_LIMIT" default:"0" description:"Global rate limit in req/min (0 = unlimited)"`

	// Logging
	LogLevel      string `long:"log-level" env:"AIPROXY_LOG_LEVEL" default:"info" choice:"debug" choice:"info" choice:"warn" choice:"error" description:"Log level"`
	LogFile       string `long:"log-file" env:"AIPROXY_LOG_FILE" default:"" description:"Log file path (empty = stdout)"`
	LogMaxSize    int    `long:"log-max-size" env:"AIPROXY_LOG_MAX_SIZE" default:"10" description:"Max log file size in MB before rotation"`
	LogMaxAge     int    `long:"log-max-age" env:"AIPROXY_LOG_MAX_AGE" default:"0" description:"Max days to retain old log files (0 = no limit)"`
	LogMaxBackups int    `long:"log-max-backups" env:"AIPROXY_LOG_MAX_BACKUPS" default:"3" description:"Max number of old log files to retain"`

	// Timeout settings
	ConnectionTimeout time.Duration `long:"connection-timeout" env:"AIPROXY_CONNECTION_TIMEOUT" default:"30s" description:"Connection timeout"`
	RequestTimeout    time.Duration `long:"request-timeout" env:"AIPROXY_REQUEST_TIMEOUT" default:"300s" description:"Request timeout"`

	// Informational (handled by init() in version.go before go-flags runs)
	Version bool `long:"version" description:"Print version and exit"`
}

// CommandExecution represents a command to execute after proxy starts.
// Used for wrapper mode: ./aiproxy [flags] -- <command> [args...]
type CommandExecution struct {
	Command string   // Command name (e.g., "curl")
	Args    []string // Command arguments (e.g., ["https://github.com"])
}

// parseArgs splits args into config args and optional command execution args.
// Returns config args (everything before "--") and optional command execution info (everything after "--").
//
// Examples:
//   - ["aiproxy", "--listen", ":8080"] -> configArgs: all, command: nil (daemon mode)
//   - ["aiproxy", "--listen", ":8080", "--", "curl", "https://github.com"] -> configArgs: before "--", command: {Command: "curl", Args: ["https://github.com"]}
//   - ["aiproxy", "--"] -> configArgs: ["aiproxy"], command: {Command: "", Args: nil} (empty command - validation error)
func parseArgs(args []string) (configArgs []string, command *CommandExecution) {
	// Find "--" delimiter
	delimiterIndex := -1
	for i, arg := range args {
		if arg == "--" {
			delimiterIndex = i
			break
		}
	}

	// No delimiter found - daemon mode
	if delimiterIndex == -1 {
		return args, nil
	}

	// Split args at delimiter
	configArgs = args[:delimiterIndex]

	// Everything after "--" is the command
	commandArgs := args[delimiterIndex+1:]
	if len(commandArgs) == 0 {
		// Empty command after "--" - return empty CommandExecution for validation error
		return configArgs, &CommandExecution{Command: "", Args: nil}
	}

	return configArgs, &CommandExecution{
		Command: commandArgs[0],
		Args:    commandArgs[1:],
	}
}

// Load parses configuration from CLI flags and environment variables.
// Flags take precedence over environment variables.
// Returns parsed config, optional command execution info, or error if parsing fails.
//
// The function supports two modes:
//   - Daemon mode (no "--"): Returns config with nil command execution
//   - Wrapper mode (with "--"): Returns config with command execution info
//
// Callers should pass os.Args:
//
//	cfg, cmd, err := config.Load(os.Args)
func Load(args []string) (*Config, *CommandExecution, error) {
	// Parse args to split config from command execution
	configArgs, cmdExec := parseArgs(args)

	// Parse config from split args
	var cfg Config
	parser := flags.NewParser(&cfg, flags.Default)

	// Set custom usage to document daemon and wrapper modes
	parser.Usage = `[OPTIONS]

Modes:
  aiproxy [OPTIONS]                Run in daemon mode (proxy server)
  aiproxy [OPTIONS] -- COMMAND...  Run in wrapper mode (execute COMMAND with proxy)

Examples:
  aiproxy                          Start proxy in daemon mode
  aiproxy -- curl https://github.com
  aiproxy --global-rate-limit 10 -- python3 script.py`

	if _, err := parser.ParseArgs(configArgs[1:]); err != nil {
		// go-flags handles --help; other errors are returned
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			// Help was printed, exit cleanly
			os.Exit(0)
		}
		return nil, nil, fmt.Errorf("failed to parse configuration: %w", err)
	}

	if err := resolvePaths(&cfg); err != nil {
		return nil, nil, err
	}

	return &cfg, cmdExec, nil
}

// resolvePaths resolves relative TLS cert/key paths to absolute paths.
// This ensures paths remain valid regardless of working directory changes
// in wrapped subprocesses.
func resolvePaths(cfg *Config) error {
	var err error
	cfg.TLSCert, err = filepath.Abs(cfg.TLSCert)
	if err != nil {
		return fmt.Errorf("failed to resolve TLS cert path: %w", err)
	}
	cfg.TLSKey, err = filepath.Abs(cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("failed to resolve TLS key path: %w", err)
	}
	return nil
}
