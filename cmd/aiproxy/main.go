package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cloudcopper/aiproxy/internal/certs"
	"github.com/cloudcopper/aiproxy/internal/config"
	"github.com/cloudcopper/aiproxy/internal/proxy"
	"github.com/cloudcopper/aiproxy/internal/rules"
	"github.com/cloudcopper/aiproxy/internal/runner"
	"github.com/cloudcopper/aiproxy/internal/webui"
	"github.com/cloudcopper/aiproxy/internal/webui/handlers"
)

// Compile-time check: proxy.Proxy must satisfy handlers.ProxyMetrics.
var _ handlers.ProxyMetrics = (*proxy.Proxy)(nil)

func main() {
	// Load configuration (supports both daemon and wrapper modes)
	cfg, cmd, err := config.Load(os.Args)
	if err != nil {
		// Configuration errors use exit code 2
		slog.Error("configuration error", "error", err)
		os.Exit(2)
	}

	// Validate empty command after "--"
	if cmd != nil && cmd.Command == "" {
		slog.Error("empty command after '--' delimiter")
		os.Exit(2)
	}

	// Setup logger based on configuration
	level := parseLogLevel(cfg.LogLevel)
	initLogWriter(os.Stdout, level)
	if cfg.LogFile != "" {
		f := initLogFile(cfg.LogFile, cfg.LogMaxSize, cfg.LogMaxAge, cfg.LogMaxBackups, level)
		defer f.Close()
		slog.Info("logging to file",
			"file", cfg.LogFile,
			"max_size_mb", cfg.LogMaxSize,
			"max_backups", cfg.LogMaxBackups,
		)
	}

	// Initialize certificate manager
	certMgr := certs.NewManager(cfg.TLSCert, cfg.TLSKey, cfg.InsecureCerts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := certMgr.Initialize(ctx); err != nil {
		slog.Error("certificate initialization failed", "error", err)
		os.Exit(1)
	}

	cert := certMgr.Certificate()
	slog.Info("certificate manager initialized",
		"cert", cfg.TLSCert,
		"key", cfg.TLSKey,
		"subject", cert.Subject.CommonName,
		"expires", cert.NotAfter,
		"serial", cert.SerialNumber,
	)

	// Load blacklist rules (static + runtime merged).
	// Missing files are not errors. Invalid files are fatal (exit 1).
	blacklist, err := rules.Load2(cfg.BlacklistRules, cfg.RTBlacklistRules)
	if err != nil {
		slog.Error("failed to load blacklist rules", "error", err)
		os.Exit(1)
	}
	if blacklist.Count() == 0 {
		slog.Warn("blacklist empty")
	} else {
		slog.Info("blacklist loaded", "rule_count", blacklist.Count())
	}

	// Load whitelist rules (static + runtime merged).
	// Missing files are not errors. Invalid files are fatal (exit 1).
	whitelist, err := rules.Load2(cfg.WhitelistRules, cfg.RTWhitelistRules)
	if err != nil {
		slog.Error("failed to load whitelist rules", "error", err)
		os.Exit(1)
	}
	if whitelist.Count() == 0 {
		slog.Warn("whitelist empty")
	} else {
		slog.Info("whitelist loaded", "rule_count", whitelist.Count())
	}

	// Initialize proxy server with TLS bumping
	proxyConfig := &proxy.Config{
		Listen:                 cfg.Listen,
		ConnectionTimeout:      cfg.ConnectionTimeout,
		RequestTimeout:         cfg.RequestTimeout,
		GlobalRateLimit:        cfg.GlobalRateLimit,
		PendingTimeout:         cfg.PendingTimeout,
		DisableConnectBlocking: false,
	}
	proxyServer := proxy.NewProxy(proxyConfig, certMgr.Certificate(), certMgr.PrivateKey(), blacklist, whitelist)

	// Start proxy in background
	errChan := make(chan error, 1)
	wg := &sync.WaitGroup{}
	wg.Go(func() {
		if err := proxyServer.Start(ctx); err != nil {
			errChan <- err
		}
	})

	// Wait for proxy to be ready OR for Start() to fail
	// We must check both channels to avoid deadlock if Start() fails before opening the listener
	var proxyAddr net.Addr
	var addrErr error
	proxyReady := make(chan struct{})
	go func() {
		proxyAddr, addrErr = proxyServer.Addr(ctx)
		close(proxyReady)
	}()

	select {
	case <-proxyReady:
		if addrErr != nil {
			slog.Error("failed to get proxy address", "error", addrErr)
			os.Exit(1)
		}
	case err := <-errChan:
		slog.Error("proxy server failed to start", "error", err)
		os.Exit(1)
	}
	slog.Info("proxy server ready", "addr", proxyAddr)

	// Start WebUI if configured (works in both daemon and wrapper modes)
	if cfg.WebUIListen != "" {
		// Warn if admin secret is empty
		if cfg.AdminSecret == "" {
			slog.Warn("the admin secret is empty - webui login will be disabled")
		}

		webuiCfg := &webui.ServerConfig{
			Listen:          cfg.WebUIListen,
			StartTime:       time.Now(),
			GlobalRateLimit: cfg.GlobalRateLimit,
			Cert:            cert,
			Metrics:         proxyServer,
			AdminSecret:     cfg.AdminSecret,
			Pending:         proxyServer,
			Rules:           proxyServer,
		}
		webuiServer := webui.NewServer(webuiCfg)
		webuiErrChan := make(chan error, 1)
		wg.Go(func() {
			if err := webuiServer.Start(ctx); err != nil {
				webuiErrChan <- err
			}
		})

		// Wait for WebUI to be ready OR for Start() to fail
		var webuiAddr net.Addr
		var webuiAddrErr error
		webuiReady := make(chan struct{})
		go func() {
			webuiAddr, webuiAddrErr = webuiServer.Addr(ctx)
			close(webuiReady)
		}()

		select {
		case <-webuiReady:
			if webuiAddrErr != nil {
				slog.Error("failed to get webui address", "error", webuiAddrErr)
				os.Exit(1)
			}
		case err := <-webuiErrChan:
			slog.Error("webui server failed to start", "error", err)
			os.Exit(1)
		}
		slog.Info("webui server ready", "addr", webuiAddr)
	}

	// Dual mode decision
	if cmd != nil {
		// Wrapper mode: execute command, then shutdown
		exitCode := runner.Run(ctx, cmd, proxyAddr, cfg.TLSCert)

		// Shutdown proxy (and WebUI if running)
		cancel()
		wg.Wait()
		os.Exit(exitCode)
	}

	// Daemon mode: block until proxy exits
	// TODO Add signal handling to allow graceful shutdown in daemon mode (e.g. on SIGINT/SIGTERM)
	slog.Info("daemon mode - blocking until proxy exits")
	if err := <-errChan; err != nil {
		slog.Error("proxy server failed", "error", err)
		os.Exit(1)
	}
}

// parseLogLevel converts string log level to slog.Level.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info":
		return slog.LevelInfo
	default:
		panic(fmt.Sprintf("Invalid log level: %s", level))
	}
}
