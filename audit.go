// Package main — structured audit log stream.
//
// Security events (auth failure, HBA reject, admin PAUSE/RESUME/
// RECONNECT, LISTEN in pooling mode, conn-limit rejects) are worth a
// separate log sink from the general operational firehose. Operators
// wire this into SIEM / Splunk / Loki with a different retention and
// alerting policy than "info" traffic.
//
// Implementation is deliberately minimal:
//
//   - JSON-only handler on a caller-provided io.Writer, defaulting
//     to stderr so audit is never silently swallowed.
//   - Package-level slog.Logger initialised once at startup.
//   - Every audit event is emitted at INFO level with a common
//     event=<name> key operators can pivot on.
//
// Callers just do auditLog("auth_fail", "user", u, "err", e) —
// no interface, no dependency injection, matches the ergonomic bar
// of stdlib slog.
package main

import (
	"io"
	"log/slog"
	"os"
	"sync/atomic"
)

// auditLogger is the process-wide audit sink. Initialised once by
// setupAuditLog; safe to read concurrently thereafter (atomic.Value
// avoids racing the setup goroutine).
var auditLogger atomic.Pointer[slog.Logger]

// setupAuditLog installs the audit sink. Called once from main after
// config is parsed. path == "" writes to stderr (via the same stream
// as operational logs but tagged event=<name> so filtering is easy).
// path == "-" is a synonym for stderr; anything else is a file path
// opened in append+create mode.
func setupAuditLog(path string) error {
	var w io.Writer = os.Stderr
	if path != "" && path != "-" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		w = f
	}
	// JSON-only: audit records go into log aggregators that want
	// structured fields, not human-friendly text.
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(h).With("component", "audit")
	auditLogger.Store(logger)
	return nil
}

// auditLog emits one audit event. Never returns an error — a broken
// audit sink is a config-time problem (see setupAuditLog); at runtime
// we prefer to keep serving over silently corrupting business traffic.
// Extra kv pairs are appended after the common event=<name>.
//
// Safe to call before setupAuditLog: a nil logger becomes a no-op so
// early startup code paths don't panic.
func auditLog(event string, kv ...any) {
	l := auditLogger.Load()
	if l == nil {
		return
	}
	l.Info(event, append([]any{"event", event}, kv...)...)
}
