package main

import (
	"log/slog"
	"os"
	"strings"
)

// setupLogging installs the process-wide default slog logger from the
// configured format ("json" or "text") and level ("debug"/"info"/"warn"/
// "error"). Every subsystem uses the default logger via slog.Info /
// slog.Warn / slog.Error — production wants JSON for a log aggregator to
// index, development wants text for human reading. The log package's
// standard bridge also flows through slog so any leftover log.Printf
// calls land in the same structured stream.
func setupLogging(format, level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: lvl,
		// Add source only at debug — the file/line lookup isn't free
		// and is noise at info/warn/error under production load.
		AddSource: lvl == slog.LevelDebug,
	}

	var h slog.Handler
	if strings.ToLower(format) == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
