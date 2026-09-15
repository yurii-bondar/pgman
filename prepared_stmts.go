// Package main — prepared statement support in transaction pooling.
//
// The problem: pgx / Java / other extended-protocol clients aggressively
// Parse-then-Bind — the "prepared statement cache" is a client-side
// optimization that assumes the same backend across many requests. In
// transaction pooling that assumption breaks: after RFQ 'I' we release
// the backend and the next transaction may land elsewhere. The client
// tries Bind("stmtcache_0001", …) on a fresh backend that has never
// seen that Parse → "prepared statement does not exist".
//
// The fix (matches PgBouncer 1.21+):
//
//  1. Track per-client every Parse we relay: (client_name → sql + OIDs).
//  2. Track per-backend which of those statements it has actually
//     received a Parse for (backend.preparedStmts set).
//  3. Before forwarding a Bind/Describe/Close for statement S:
//     - If the current backend already has S: forward unchanged.
//     - Otherwise: prepend a Parse for S using the saved sql+OIDs,
//     mark the backend as knowing S, then forward the client's msg.
//  4. Swallow the ParseComplete produced by any prepended Parse so the
//     client's response stream contains exactly what the client asked
//     for — no phantom ParseCompletes it never issued a Parse for.
//  5. On client Close(S): drop from the session cache. Don't bother
//     forwarding a Close to the backend — the backend still holds S,
//     and DISCARD ALL between-txn Release cleans it up anyway.
//
// The whole surface only kicks in for NAMED prepared statements
// (Parse.Name != ""). Unnamed (Name = "") are single-Bind ephemerals —
// no risk of them being reused across backends.
package main

import (
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// defaultMaxPreparedStatements caps how many named statements one
// session may have tracked at a time. Matches PgBouncer's
// max_prepared_statements default.
//
// A cap is not optional. Every entry holds the statement's full SQL
// text, the client chooses both the name and how many to create, and
// max_client_conn defaults to 10000 — so without one, a single client
// looping over fresh statement names is an out-of-memory primitive that
// needs no privileges beyond connecting.
const defaultMaxPreparedStatements = 200

// prepStmtInfo is what the proxy needs to replay a Parse on any
// backend that hasn't seen a given prepared statement yet.
type prepStmtInfo struct {
	SQL           string
	ParameterOIDs []uint32

	// lastUsed orders eviction. Stamped from session.psClock on Parse
	// and on every Bind/Describe that finds this entry, so the cap
	// sheds the statements a client has stopped using rather than the
	// ones it is using right now.
	lastUsed uint64
}

// psCache is the per-session prepared statement registry — keyed by
// client-chosen name (e.g. "stmtcache_0001"). Grows on Parse, shrinks
// on Close.
type psCache map[string]*prepStmtInfo

// backendPSCache tracks which statement names the current backend has
// actually seen a Parse for. Attached to backendConn so that when the
// backend is released and later re-Acquired by a different session,
// the cache is preserved (safe: DISCARD ALL between transactions
// closes prepared statements, so we also need to clear this on Release
// — see clearBackendPSCache).
type backendPSCache map[string]struct{}

// processClientMsg is the fused fast-path called before forwarding
// each client message. It runs three independent checks in ONE type
// switch (formerly three separate calls with three type switches):
//
//  1. Prepared-statement lazy replay (Parse/Bind/Describe/Close)
//  2. LISTEN/NOTIFY footgun warn (Query/Parse carrying LISTEN)
//  3. DDL cache invalidation (Query/Parse carrying DDL)
//
// Fast bail-out: if the message isn't one of the interesting types
// (Sync, Execute, Flush, CopyData, …) it returns immediately with
// zero work — the hottest steady-state message flow is Bind → Execute
// → Sync repeated forever, and only Bind carries real work here.
//
// Return values: (msg unchanged so caller can forward it as-is,
// swallowParseComplete count as in the old interceptClientMsg).
func processClientMsg(
	fe *pgproto3.Frontend,
	backend *backendConn,
	sess *session,
	msg pgproto3.FrontendMessage,
) (pgproto3.FrontendMessage, int) {
	// Single type switch covers everything.
	switch m := msg.(type) {
	case *pgproto3.Parse:
		// PS tracking (unconditional — this is the only path that
		// populates sess.psCache) + DDL/LISTEN checks on the query text.
		if m.Name != "" {
			trackClientParse(backend, sess, m)
		}
		checkSQLSideEffects(backend, sess, m.Query)
		return msg, 0
	case *pgproto3.Bind:
		return ensureBackendHasStmt(fe, backend, sess, m.PreparedStatement, msg)
	case *pgproto3.Describe:
		if m.ObjectType == 'S' {
			return ensureBackendHasStmt(fe, backend, sess, m.Name, msg)
		}
		return msg, 0
	case *pgproto3.Close:
		if m.ObjectType == 'S' && m.Name != "" {
			if sess.psCache != nil {
				delete(sess.psCache, m.Name)
			}
			if backend != nil && backend.preparedStmts != nil {
				delete(backend.preparedStmts, m.Name)
			}
		}
		return msg, 0
	case *pgproto3.Query:
		// Simple protocol carries SQL directly. Only path where
		// LISTEN warn / DDL flush can trigger.
		checkSQLSideEffects(backend, sess, m.String)
		return msg, 0
	}
	// Sync, Execute, Flush, CopyData, CopyDone, CopyFail, Terminate:
	// nothing to inspect. This is the branch the hot Bind/Execute/Sync
	// loop hits 2 out of 3 messages — kept as a tight tail return.
	return msg, 0
}

// trackClientParse populates the session/backend caches when a client
// issues a named Parse. Split from processClientMsg so the *pgproto3.Parse
// branch there stays tight.
func trackClientParse(backend *backendConn, sess *session, m *pgproto3.Parse) {
	if sess.psCache == nil {
		sess.psCache = make(psCache)
	}
	if _, replacing := sess.psCache[m.Name]; !replacing {
		evictPreparedStmts(backend, sess)
	}
	sess.psClock++
	sess.psCache[m.Name] = &prepStmtInfo{
		SQL:           m.Query,
		ParameterOIDs: append([]uint32(nil), m.ParameterOIDs...),
		lastUsed:      sess.psClock,
	}
	if backend != nil {
		if backend.preparedStmts == nil {
			backend.preparedStmts = make(backendPSCache)
		}
		backend.preparedStmts[m.Name] = struct{}{}
	}
}

// evictPreparedStmts makes room for one more entry, dropping the least
// recently used statements until the cache is under sess.psLimit.
//
// Dropping an entry is safe, not a broken session: the next Bind for
// that name simply forwards unchanged. If the current backend still
// holds the statement it runs normally, and if it doesn't, Postgres
// answers 26000 "prepared statement does not exist" — which is exactly
// what every driver with its own statement cache (pgx, JDBC) already
// handles by re-issuing the Parse. Refusing the Parse instead would
// break the statement the client just asked for, i.e. the hottest one.
//
// The scan is O(len(cache)) but runs only when the cache is full, at a
// default cap of 200. A list-plus-map LRU would turn a 12-line function
// into a data structure for no measurable gain at that size.
func evictPreparedStmts(backend *backendConn, sess *session) {
	limit := sess.psLimit
	if limit <= 0 {
		return // negative or unset ⇒ no cap (see max_prepared_statements)
	}
	for len(sess.psCache) >= limit {
		var oldestName string
		var oldestUse uint64
		for name, info := range sess.psCache {
			if oldestName == "" || info.lastUsed < oldestUse {
				oldestName, oldestUse = name, info.lastUsed
			}
		}
		if oldestName == "" {
			return
		}
		delete(sess.psCache, oldestName)
		// Forget it on the backend too. The backend really does still
		// hold the statement, but we can no longer replay it anywhere
		// else, so the entry is dead weight — and in session pooling,
		// where the backend is never released, dead weight that never
		// gets collected.
		if backend != nil && backend.preparedStmts != nil {
			delete(backend.preparedStmts, oldestName)
		}
		if !sess.psEvicted {
			sess.psEvicted = true
			slog.Warn("prepared-statement cache full, evicting least recently used",
				"limit", limit,
				"user", sess.user,
				"database", sess.database,
				"hint", "raise max_prepared_statements, or lower the client driver's own statement-cache size")
		}
	}
}

// checkSQLSideEffects runs the two SQL-text-driven side-effect checks
// (LISTEN warn, DDL cache flush) in a single pass. Extracted so both
// the Query and Parse cases in processClientMsg share the same code.
// Empty sql short-circuits with no work.
func checkSQLSideEffects(backend *backendConn, sess *session, sql string) {
	if sql == "" {
		return
	}
	if !sess.listenWarned {
		checkListenWarn(sess, sql)
	}
	if isDDL(sql) {
		invalidatePSCachesOnDDL(backend, sess)
	}
}

// ensureBackendHasStmt is the core of the transaction-pool prepared-
// statement trick: if the backend hasn't been shown this statement
// yet, prepend a Parse before forwarding the client's message.
func ensureBackendHasStmt(
	fe *pgproto3.Frontend,
	backend *backendConn,
	sess *session,
	stmtName string,
	msg pgproto3.FrontendMessage,
) (pgproto3.FrontendMessage, int) {
	if stmtName == "" {
		return msg, 0 // unnamed / referring to a portal — nothing to prep
	}
	if sess.psCache == nil {
		return msg, 0
	}
	info, ok := sess.psCache[stmtName]
	if !ok {
		return msg, 0 // we've never seen a Parse for this name — client bug, evicted, or backend-side stmt
	}
	// Touch it: this statement is in active use and must outrank the
	// ones that are only sitting in the cache when the cap bites.
	sess.psClock++
	info.lastUsed = sess.psClock
	if backend == nil {
		return msg, 0
	}
	if backend.preparedStmts == nil {
		backend.preparedStmts = make(backendPSCache)
	}
	if _, has := backend.preparedStmts[stmtName]; has {
		return msg, 0 // backend already has it — no prepend needed
	}
	// Prepend the Parse — same name as client-chosen so the client's
	// Bind/Describe/Close forwarded right after references the same
	// name on the backend side too.
	fe.Send(&pgproto3.Parse{
		Name:          stmtName,
		Query:         info.SQL,
		ParameterOIDs: info.ParameterOIDs,
	})
	backend.preparedStmts[stmtName] = struct{}{}
	return msg, 1
}

// isDDL returns true when the SQL text looks like a schema-mutating
// statement (CREATE / ALTER / DROP / TRUNCATE / GRANT / REVOKE /
// COMMENT / REINDEX / VACUUM FULL etc). Cheap prefix match on the
// first keyword — false positives here just cause an extra
// prepared-statement cache flush (harmless), and false negatives cost
// nothing worse than what already happens today.
//
// Callers use this to invalidate cached prepared statements whose
// plans may reference the affected relation. Postgres will otherwise
// raise "cached plan must not change result type" on the next Execute.
func isDDL(sql string) bool {
	// Skip leading whitespace / opening paren / comments starting with
	// -- (block comments /* */ are handled by a client bug — we don't
	// unwrap them; the DDL keyword is still in the tail so misdetection
	// is only-way-forward = false negative, safe).
	s := strings.TrimLeft(sql, " \t\r\n")
	for strings.HasPrefix(s, "--") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = strings.TrimLeft(s[i+1:], " \t\r\n")
		} else {
			return false
		}
	}
	if len(s) < 5 {
		return false
	}
	// Only look at the first keyword. Uppercase compare.
	end := 0
	for end < len(s) {
		c := s[end]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			break
		}
		end++
	}
	head := strings.ToUpper(s[:end])
	switch head {
	case "CREATE", "ALTER", "DROP", "TRUNCATE",
		"GRANT", "REVOKE", "COMMENT", "REINDEX",
		"REFRESH", "CLUSTER", "SECURITY":
		return true
	case "VACUUM":
		// VACUUM (FULL) rewrites tables and invalidates cached plans.
		// Plain VACUUM is safer but flushing anyway is cheap — do it.
		return true
	}
	return false
}

// invalidatePSCachesOnDDL is called right after we forward a DDL to
// the backend. Clears the session-side cache so any subsequent Bind
// (which would have referenced the OLD prepared statement name) is
// treated as a fresh reference — client re-issues Parse, backend plans
// against post-DDL schema. Also clears the current backend's cache so
// the very next Bind IN THIS SAME TX gets a fresh Parse prepended.
//
// Backends not currently held by this session aren't touched — they
// still hold stale prepared statements. That's fine: Postgres itself
// raises "cached plan must not change result type" on the next
// Execute against them, and pgx/libpq handles that by re-preparing.
func invalidatePSCachesOnDDL(backend *backendConn, sess *session) {
	if sess != nil {
		sess.psCache = nil
	}
	clearBackendPSCache(backend)
}

// clearBackendPSCache is called right after a serverResetQuery runs
// ("DISCARD ALL" wipes all prepared statements on the backend), so the
// cache no longer reflects reality. Skipping this would leave stale
// entries saying "backend knows S" when it doesn't, causing the very
// "does not exist" errors this whole machinery exists to avoid.
func clearBackendPSCache(b *backendConn) {
	if b == nil {
		return
	}
	b.preparedStmts = nil
}
