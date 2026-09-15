package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// listenSession builds the minimal session checkListenWarn reads: a
// pool mode plus the identity that goes into the warning, which is the
// only thing that makes the warning actionable.
func listenSession(mode string) *session {
	return &session{poolMode: mode, user: "alice", database: "shop"}
}

// TestCheckListenWarnFiresOnListenInTransactionPooling is the whole
// reason this detector exists. In transaction pooling the backend that
// ran LISTEN goes back to the pool at commit, so every later NOTIFY is
// delivered to whichever client is holding that backend at the time.
// Nothing errors, nothing retries — the client simply never hears from
// the channel again, which is close to undiagnosable from the
// application side. The warning is the only signal an operator gets.
func TestCheckListenWarnFiresOnListenInTransactionPooling(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	withAuditLogger(t, path)

	sess := listenSession("transaction")
	checkListenWarn(sess, "LISTEN job_done")

	if !sess.listenWarned {
		t.Fatal("LISTEN in transaction pooling produced no warning")
	}

	// The audit stream is where this lands for anyone reviewing an
	// installation after the fact, long after the startup logs rotated.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	if !strings.Contains(string(data), "listen_in_pool_mode") {
		t.Errorf("no listen_in_pool_mode audit record was written: %q", data)
	}
	for _, field := range []string{"alice", "shop", "transaction"} {
		if !strings.Contains(string(data), field) {
			t.Errorf("audit record omits %q, so nobody can tell which client to fix: %q", field, data)
		}
	}
}

// TestCheckListenWarnRecognisesRealClientSpellings: the detector reads
// raw SQL as the client wrote it, and clients write it in lower case,
// behind indentation, and — for drivers that wrap statements — behind a
// parenthesis. Missing any of those spellings means the footgun ships
// unannounced, which is indistinguishable from having no detector.
func TestCheckListenWarnRecognisesRealClientSpellings(t *testing.T) {
	cases := map[string]string{
		"upper case":       "LISTEN job_done",
		"lower case":       "listen job_done",
		"mixed case":       "Listen job_done",
		"leading spaces":   "   LISTEN job_done",
		"leading newline":  "\n\tLISTEN job_done",
		"leading paren":    "(LISTEN job_done)",
		"unlisten":         "UNLISTEN job_done",
		"unlisten star":    "unlisten *",
		"no trailing args": "LISTEN",
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			sess := listenSession("transaction")
			checkListenWarn(sess, sql)
			if !sess.listenWarned {
				t.Errorf("%q went undetected", sql)
			}
		})
	}
}

// TestCheckListenWarnStaysQuietInSessionPooling: session pooling pins
// one backend for the client's whole lifetime, so LISTEN/NOTIFY works
// exactly as Postgres documents it. Warning there would tell operators
// their correct configuration is broken, and the pool mode it tells
// them to switch to is the one they already run.
func TestCheckListenWarnStaysQuietInSessionPooling(t *testing.T) {
	sess := listenSession("session")
	checkListenWarn(sess, "LISTEN job_done")

	if sess.listenWarned {
		t.Error("LISTEN warned in session pooling, where it is the supported configuration")
	}
}

// TestCheckListenWarnIgnoresOtherStatements matters because this runs
// on every statement of every session. A prefix match loose enough to
// hit ordinary queries would flood the log from the hot path — and the
// flag is one-shot, so the first false positive also disables the
// warning for the real LISTEN that follows.
func TestCheckListenWarnIgnoresOtherStatements(t *testing.T) {
	cases := map[string]string{
		"select":           "SELECT 1",
		"shorter than six": "LIST",
		"empty":            "",
		"whitespace only":  "   ",
		"listen mid query": "SELECT 'LISTEN'",
		"similar prefix":   "LISTAGG(x)",
	}
	for name, sql := range cases {
		t.Run(name, func(t *testing.T) {
			sess := listenSession("transaction")
			checkListenWarn(sess, sql)
			if sess.listenWarned {
				t.Errorf("%q was mistaken for LISTEN", sql)
			}
		})
	}
}

// TestCheckListenWarnAlsoCoversStatementPooling: statement pooling
// releases the backend on every single round trip, so it loses NOTIFY
// deliveries even faster than transaction pooling does.
func TestCheckListenWarnAlsoCoversStatementPooling(t *testing.T) {
	sess := listenSession("statement")
	checkListenWarn(sess, "LISTEN job_done")

	if !sess.listenWarned {
		t.Error("LISTEN in statement pooling produced no warning")
	}
}
