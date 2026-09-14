package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withAuditLogger swaps the process-wide audit sink for the duration of
// one test and restores it afterwards, so audit tests don't leak into
// the rest of the suite.
func withAuditLogger(t *testing.T, path string) {
	t.Helper()
	prev := auditLogger.Load()
	t.Cleanup(func() { auditLogger.Store(prev) })
	if err := setupAuditLog(path); err != nil {
		t.Fatalf("setupAuditLog(%q): %v", path, err)
	}
}

// TestAuditLogWritesStructuredJSON: the audit stream exists to be
// consumed by a SIEM, so the format is the contract. Every record must
// be one parseable JSON object carrying event= and the caller's fields.
func TestAuditLogWritesStructuredJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	withAuditLogger(t, path)

	auditLog("auth_fail", "user", "alice", "remote", "10.0.0.7")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %q", len(lines), data)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("audit record is not valid JSON: %v (%q)", err, lines[0])
	}
	// event is duplicated into a field on purpose: slog's "msg" is not
	// a stable pivot key across sinks, "event" is what operators filter
	// and alert on.
	if rec["event"] != "auth_fail" {
		t.Errorf("event = %v, want auth_fail", rec["event"])
	}
	if rec["user"] != "alice" {
		t.Errorf("user = %v, want alice", rec["user"])
	}
	if rec["remote"] != "10.0.0.7" {
		t.Errorf("remote = %v, want 10.0.0.7", rec["remote"])
	}
	// component tags the stream so a shared stderr sink stays filterable.
	if rec["component"] != "audit" {
		t.Errorf("component = %v, want audit", rec["component"])
	}
}

func TestAuditLogAppendsAcrossCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	withAuditLogger(t, path)

	auditLog("admin_cmd", "cmd", "PAUSE")
	auditLog("admin_cmd", "cmd", "RESUME")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if n := len(strings.Split(strings.TrimSpace(string(data)), "\n")); n != 2 {
		t.Errorf("got %d records, want 2 — the file must be opened in append mode", n)
	}
}

// TestAuditLogBeforeSetupIsNoOp guards the ordering contract. Config
// parsing emits warnings before setupAuditLog runs, and a panic there
// would take down startup for the sake of a log line.
func TestAuditLogBeforeSetupIsNoOp(t *testing.T) {
	prev := auditLogger.Load()
	t.Cleanup(func() { auditLogger.Store(prev) })

	auditLogger.Store(nil)
	auditLog("early_event", "key", "value") // must not panic
}

func TestSetupAuditLogRejectsUnwritablePath(t *testing.T) {
	prev := auditLogger.Load()
	t.Cleanup(func() { auditLogger.Store(prev) })

	// A path whose parent directory does not exist. Failing loudly at
	// startup is right: silently downgrading to "no audit" is how an
	// install ends up with no security trail at all.
	err := setupAuditLog(filepath.Join(t.TempDir(), "nope", "audit.log"))
	if err == nil {
		t.Fatal("expected setupAuditLog to fail on an unwritable path")
	}
}

func TestSetupAuditLogDashMeansStderr(t *testing.T) {
	prev := auditLogger.Load()
	t.Cleanup(func() { auditLogger.Store(prev) })

	for _, path := range []string{"", "-"} {
		if err := setupAuditLog(path); err != nil {
			t.Errorf("setupAuditLog(%q) = %v, want nil (stderr fallback)", path, err)
		}
		if auditLogger.Load() == nil {
			t.Errorf("setupAuditLog(%q) left the sink nil", path)
		}
	}
}
