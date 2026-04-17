package main

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const timeFormat string = "2006-01-02 15:04:05.000 -0700" // may be time.DateTime

// logWriter wraps an io.Writer to add timestamps.
type logWriter struct {
	w io.Writer
}

func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprintf(writer.w, "[%s] %s", time.Now().Local().Format(timeFormat), string(bytes))
}

// initLogWriter sets up the default slog logger writing to the given writer.
func initLogWriter(w io.Writer, level slog.Leveler) {
	log.SetFlags(0)
	log.SetOutput(&logWriter{w: w})
	handler := slog.NewTextHandler(&logWriter{w: w}, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove slog's built-in timestamp since logWriter adds one
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(handler))
}

// initLogFile configures the global logger based on configuration.
// Returns a io.Closer with a Close function to call on shutdown.
// Logs go to the file with lumberjack rotation.
func initLogFile(logFile string, logMaxSize, logMaxAge, logMaxBackups int, level slog.Leveler) io.Closer {
	// File mode with lumberjack rotation
	lw := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    logMaxSize,    // megabytes
		MaxAge:     logMaxAge,     // days
		MaxBackups: logMaxBackups, // count
		LocalTime:  true,          // use local time for rotated file names
		Compress:   false,         // gzip rotated files
	}

	// Test that we can actually write to the file
	if _, err := lw.Write([]byte{}); err != nil {
		// No fallback - we must be able to write log file
		panic(fmt.Sprintf("Cannot write to log file %s: %v", logFile, err))
	}

	initLogWriter(lw, level)
	return lw
}

// init keeps stdout-only logger for early startup errors (before config is loaded).
func init() {
	initLogWriter(os.Stdout, slog.LevelInfo)
}
