// Package main — LISTEN/NOTIFY footgun detector.
//
// In transaction and statement pooling, the backend that received
// LISTEN gets released back to the pool once the current tx completes.
// Any NOTIFY the client's target channel receives afterwards is
// delivered to whichever session happens to be holding THAT backend
// at that moment — not to the LISTEN-ing client. Result: silent
// message loss that's brutal to diagnose.
//
// We can't fix this without pinning the backend (i.e. moving to
// session mode). What we CAN do is emit a clear one-shot warning
// the moment we see LISTEN so ops sees it early.
package main

import (
	"log/slog"
	"strings"
)

// checkListenWarn takes SQL text that processClientMsg has already
// extracted, so this does not repeat that type switch. Caller must have
// already checked sess.listenWarned to short-circuit.
func checkListenWarn(sess *session, sql string) {
	// Session pooling holds one backend for the whole client lifetime,
	// so LISTEN works fine there. Transaction & statement pooling
	// don't.
	if sess.poolMode == "session" {
		return
	}
	// Cheap prefix check — LISTEN is a leading keyword with no CTEs
	// or comments allowed before it. Uppercase compare after trimming
	// leading whitespace covers 99% of clients.
	trimmed := strings.TrimLeft(sql, " \t\r\n(")
	if len(trimmed) < 6 {
		return
	}
	head := strings.ToUpper(trimmed[:6])
	if head != "LISTEN" && head != "UNLIST" {
		return
	}
	sess.listenWarned = true
	slog.Warn("LISTEN in non-session pooling mode: NOTIFY delivery will be silently dropped once the backend rotates — use pool_mode: session for LISTEN/NOTIFY workloads",
		"pool_mode", sess.poolMode,
		"user", sess.user,
		"database", sess.database)
	auditLog("listen_in_pool_mode",
		"user", sess.user,
		"database", sess.database,
		"pool_mode", sess.poolMode)
}
