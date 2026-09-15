package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// withSetupLogging installs the logger under test and puts the previous
// process-wide default back afterwards. setupLogging mutates global
// state that the whole package logs through, so a test that forgets to
// restore it would silently change the log level of every test that
// runs after it.
func withSetupLogging(t *testing.T, format, level string) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	setupLogging(format, level)
}

// captureLogging points os.Stderr at a pipe for the duration of one
// emit, so a test can read back the bytes a handler actually produced.
// Only the handler's own file descriptor is redirected; the default
// logger and os.Stderr are restored before the captured output is read.
func captureLogging(t *testing.T, format, level string, emit func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevStderr, prevLogger := os.Stderr, slog.Default()
	os.Stderr = w
	setupLogging(format, level)
	emit()
	slog.SetDefault(prevLogger)
	os.Stderr = prevStderr

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	_ = r.Close()
	return string(out)
}

// lineContaining picks the record a test emitted out of the captured
// stream. Background goroutines belonging to other pools and watchers
// keep logging through the default logger while the pipe is installed,
// so the capture is not guaranteed to hold exactly one line.
func lineContaining(t *testing.T, out, needle string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	t.Fatalf("no captured line contains %q; got %q", needle, out)
	return ""
}

// TestSetupLoggingLevelThresholds: log_level is the only control an
// operator has over log volume, and a proxy logs on the per-connection
// path. Mapping "warn" to debug would bury a production host in disk
// writes; mapping it the other way would drop the records an incident
// is reconstructed from.
func TestSetupLoggingLevelThresholds(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		// Anything unrecognised — including a level the config layer
		// never filled in — has to behave like the documented default
		// rather than turning logging off.
		"":            slog.LevelInfo,
		"not-a-level": slog.LevelInfo,
		// Config files are hand-written, so case is not something to
		// reject over.
		"WARN": slog.LevelWarn,
	}
	for level, want := range cases {
		t.Run(level, func(t *testing.T) {
			withSetupLogging(t, "json", level)

			all := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
			for _, l := range all {
				enabled := slog.Default().Enabled(t.Context(), l)
				if enabled != (l >= want) {
					t.Errorf("level %q: %v enabled = %v, want %v", level, l, enabled, l >= want)
				}
			}
		})
	}
}

// TestSetupLoggingFormatSelectsHandler: "json" is what makes the log
// stream indexable by an aggregator, and it is the fallback precisely
// because a mistyped log_format must not degrade production logs into
// text nobody is parsing.
func TestSetupLoggingFormatSelectsHandler(t *testing.T) {
	cases := map[string]bool{
		"text": true,
		"TEXT": true,
		"json": false,
		"":     false,
		"yaml": false,
	}
	for format, wantText := range cases {
		t.Run(format, func(t *testing.T) {
			withSetupLogging(t, format, "info")

			got := slog.Default().Handler()
			if _, isText := got.(*slog.TextHandler); isText != wantText {
				t.Errorf("format %q installed %T, wantText = %v", format, got, wantText)
			}
			if _, isJSON := got.(*slog.JSONHandler); isJSON == wantText {
				t.Errorf("format %q installed %T, wantText = %v", format, got, wantText)
			}
		})
	}
}

// TestSetupLoggingAddsSourceOnlyAtDebug guards a cost decision. The
// file/line lookup runs on every record, and this proxy emits records
// from the per-query path — paying for it at info level would show up
// as throughput loss on a busy pool, while at debug the caller location
// is most of the value of turning debug on at all.
func TestSetupLoggingAddsSourceOnlyAtDebug(t *testing.T) {
	out := captureLogging(t, "json", "debug", func() {
		slog.Debug("source-probe-debug")
	})
	line := lineContaining(t, out, "source-probe-debug")
	if !strings.Contains(line, `"source"`) {
		t.Errorf("debug record carries no source attribute: %s", line)
	}

	out = captureLogging(t, "json", "info", func() {
		slog.Info("source-probe-info")
	})
	line = lineContaining(t, out, "source-probe-info")
	if strings.Contains(line, `"source"`) {
		t.Errorf("info record pays for a source lookup: %s", line)
	}
}

// TestSetupLoggingWritesToStderr: stdout belongs to the admin CLI's
// query output, and a container runtime that mixes the two streams
// makes both unparseable. Logs go to stderr, always.
func TestSetupLoggingWritesToStderr(t *testing.T) {
	out := captureLogging(t, "text", "info", func() {
		slog.Info("stderr-probe")
	})
	line := lineContaining(t, out, "stderr-probe")
	// The text handler's own shape doubles as the proof that the "text"
	// format is not quietly the JSON one.
	if !strings.Contains(line, "msg=stderr-probe") {
		t.Errorf("text handler produced %q, want key=value output", line)
	}
}
