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
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// defaultMaxPreparedStatements caps how many named statements one
// backend connection keeps prepared. Matches PgBouncer's
// max_prepared_statements default, and means the same thing it does
// there: the size of a per-server-connection LRU cache, not a limit on
// what a client may prepare.
//
// The distinction is the whole design. The proxy has two caches, and
// capping the wrong one is what produced the bug this replaced: with a
// cap on the session's map, an evicted entry took the statement's SQL
// with it, so the next Bind for that name could reach a backend that
// had never seen the Parse and come back 26000 "prepared statement does
// not exist" — a failure that appeared only under the load that moves
// connections between clients.
const defaultMaxPreparedStatements = 200

// sessionPSCeilingFactor derives the session map's hard ceiling from
// max_prepared_statements. The session map must not be capped at the
// same number as the backend cache — losing an entry there is what
// breaks replay — but it cannot be unbounded either: every entry holds
// the statement's full SQL text, the client picks both the names and
// how many, and max_client_conn defaults to 10000.
//
// 4× clears the statement-cache sizes real drivers ship with (pgx 512,
// pgJDBC 256) by a wide margin, so a client using a bounded cache never
// approaches it. A session that does reach 800 simultaneously live
// named statements is not using a driver cache at all — it is leaking
// names — and gets told so, with the knob to raise in the message.
const sessionPSCeilingFactor = 4

// prepStmtInfo is what the proxy needs to replay a Parse on any
// backend that hasn't seen a given prepared statement yet.
type prepStmtInfo struct {
	SQL           string
	ParameterOIDs []uint32
}

// psCache is the per-session prepared statement registry — keyed by
// client-chosen name (e.g. "stmtcache_0001"). Grows on Parse, shrinks
// on Close, and — unlike the backend cache below — never drops an entry
// on its own, because it is the only copy of the SQL a replay needs.
type psCache map[string]*prepStmtInfo

// backendPSCache tracks which statement names the current backend has
// seen a Parse for, mapped to the clock tick it was last used at so the
// cap can shed the least recently used one. Attached to backendConn so
// that when the backend is released and later re-Acquired by a
// different session, the cache is preserved (safe: DISCARD ALL between
// transactions closes prepared statements, so we also need to clear
// this on Release — see clearBackendPSCache).
type backendPSCache map[string]uint64

// psSwallow counts the backend replies produced by messages the proxy
// injected on its own initiative, which must be dropped before the
// response stream reaches the client: it never sent the Parse or the
// Close they acknowledge, and a driver that receives an unasked-for ack
// is entitled to treat the stream as corrupt.
type psSwallow struct {
	parseComplete int
	closeComplete int
}

func (s *psSwallow) add(other psSwallow) {
	s.parseComplete += other.parseComplete
	s.closeComplete += other.closeComplete
}

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
// Return values: the message to forward (unchanged — the proxy rewrites
// nothing), the injected replies the caller must swallow, and an error
// only when the session has to end. The error path exists for one
// condition: a client past the session ceiling, which cannot be served
// correctly and must not be served silently.
func processClientMsg(
	fe *pgproto3.Frontend,
	backend *backendConn,
	sess *session,
	msg pgproto3.FrontendMessage,
) (pgproto3.FrontendMessage, psSwallow, error) {
	// Single type switch covers everything.
	switch m := msg.(type) {
	case *pgproto3.Parse:
		// PS tracking (unconditional — this is the only path that
		// populates sess.psCache) + DDL/LISTEN checks on the query text.
		var swallow psSwallow
		if m.Name != "" {
			var err error
			if swallow, err = trackClientParse(fe, backend, sess, m); err != nil {
				return msg, swallow, err
			}
		}
		checkSQLSideEffects(backend, sess, m.Query)
		return msg, swallow, nil
	case *pgproto3.Bind:
		swallow := ensureBackendHasStmt(fe, backend, sess, m.PreparedStatement)
		return msg, swallow, nil
	case *pgproto3.Describe:
		if m.ObjectType == 'S' {
			return msg, ensureBackendHasStmt(fe, backend, sess, m.Name), nil
		}
		return msg, psSwallow{}, nil
	case *pgproto3.Close:
		if m.ObjectType == 'S' && m.Name != "" {
			if sess.psCache != nil {
				delete(sess.psCache, m.Name)
			}
			if backend != nil && backend.preparedStmts != nil {
				delete(backend.preparedStmts, m.Name)
			}
		}
		return msg, psSwallow{}, nil
	case *pgproto3.Query:
		// Simple protocol carries SQL directly. Only path where
		// LISTEN warn / DDL flush can trigger.
		checkSQLSideEffects(backend, sess, m.String)
		return msg, psSwallow{}, nil
	}
	// Sync, Execute, Flush, CopyData, CopyDone, CopyFail, Terminate:
	// nothing to inspect. This is the branch the hot Bind/Execute/Sync
	// loop hits 2 out of 3 messages — kept as a tight tail return.
	return msg, psSwallow{}, nil
}

// trackClientParse records a named Parse in the session map and marks
// the current backend as holding it, since the client's Parse is about
// to be forwarded there.
//
// Returns an error when the session map is at its ceiling. Nothing is
// recorded in that case, so the caller must end the session rather than
// forward the Parse: a statement the proxy has not recorded is one it
// cannot replay onto the next backend, which is precisely the silent
// failure this design exists to remove.
func trackClientParse(fe *pgproto3.Frontend, backend *backendConn, sess *session, m *pgproto3.Parse) (psSwallow, error) {
	if sess.psCache == nil {
		sess.psCache = make(psCache)
	}
	if _, replacing := sess.psCache[m.Name]; !replacing {
		if ceiling := sessionPSCeiling(sess.psLimit); ceiling > 0 && len(sess.psCache) >= ceiling {
			return psSwallow{}, fmt.Errorf(
				"session has %d named prepared statements open, the ceiling for max_prepared_statements=%d; "+
					"raise max_prepared_statements, or have the client close statements it no longer uses",
				len(sess.psCache), sess.psLimit)
		}
	}
	sess.psCache[m.Name] = &prepStmtInfo{
		SQL:           m.Query,
		ParameterOIDs: append([]uint32(nil), m.ParameterOIDs...),
	}
	return markBackendHasStmt(fe, backend, sess, m.Name), nil
}

// sessionPSCeiling is how many named statements one session may hold at
// once. Zero means uncapped, which is what a non-positive
// max_prepared_statements asks for.
func sessionPSCeiling(limit int) int {
	if limit <= 0 {
		return 0
	}
	return limit * sessionPSCeilingFactor
}

// markBackendHasStmt records that this backend now holds stmtName,
// evicting least-recently-used statements first if the backend is at
// max_prepared_statements.
//
// Eviction here is safe in the way eviction from the session map was
// not: the SQL is still in sess.psCache, so a later Bind for an evicted
// name is replayed onto whatever backend is current, exactly as if that
// backend had never seen the statement.
//
// The victim is closed on the backend rather than merely forgotten.
// Forgetting it leaves the statement — and its cached plan — resident
// in the Postgres backend for the life of the connection, which in
// session pooling is the life of the client. PgBouncer has been
// criticised for exactly this (pgbouncer#1472); one extra protocol
// message per eviction is a cheap way not to inherit it.
func markBackendHasStmt(fe *pgproto3.Frontend, backend *backendConn, sess *session, stmtName string) psSwallow {
	if backend == nil {
		return psSwallow{}
	}
	if backend.preparedStmts == nil {
		backend.preparedStmts = make(backendPSCache)
	}

	var swallow psSwallow
	limit := sess.psLimit
	if limit > 0 {
		if _, known := backend.preparedStmts[stmtName]; !known {
			// A loop, not a single eviction: the cap can be lowered by
			// a reload while a connection is already over it.
			for len(backend.preparedStmts) >= limit {
				victim, ok := lruStmt(backend.preparedStmts)
				if !ok {
					break
				}
				delete(backend.preparedStmts, victim)
				if fe != nil {
					fe.Send(&pgproto3.Close{ObjectType: 'S', Name: victim})
					swallow.closeComplete++
				}
				if !sess.psEvicted {
					sess.psEvicted = true
					slog.Info("prepared-statement cache full on a backend, closing least recently used",
						"limit", limit,
						"user", sess.user,
						"database", sess.database,
						"hint", "raise max_prepared_statements to keep more statements prepared per backend")
				}
			}
		}
	}

	sess.psClock++
	backend.preparedStmts[stmtName] = sess.psClock
	return swallow
}

// lruStmt picks the least recently used entry. The scan is
// O(len(cache)) but runs only when the cache is full, at a default cap
// of 200 — a list-plus-map LRU would turn eight lines into a data
// structure for no measurable gain at that size.
func lruStmt(cache backendPSCache) (string, bool) {
	var oldest string
	var oldestUse uint64
	for name, used := range cache {
		if oldest == "" || used < oldestUse {
			oldest, oldestUse = name, used
		}
	}
	return oldest, oldest != ""
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
) psSwallow {
	if stmtName == "" {
		return psSwallow{} // unnamed / referring to a portal — nothing to prep
	}
	if sess.psCache == nil || backend == nil {
		return psSwallow{}
	}
	info, ok := sess.psCache[stmtName]
	if !ok {
		// No Parse for this name was ever seen on this session: a
		// client bug, or a statement prepared server-side with SQL
		// PREPARE. Forward it and let Postgres have the last word.
		return psSwallow{}
	}
	if backend.preparedStmts != nil {
		if _, has := backend.preparedStmts[stmtName]; has {
			// Already there — just touch it so an active statement
			// outranks idle ones when the cap bites.
			sess.psClock++
			backend.preparedStmts[stmtName] = sess.psClock
			return psSwallow{}
		}
	}
	// Prepend the Parse — same name as client-chosen so the client's
	// Bind/Describe/Close forwarded right after references the same
	// name on the backend side too.
	swallow := markBackendHasStmt(fe, backend, sess, stmtName)
	fe.Send(&pgproto3.Parse{
		Name:          stmtName,
		Query:         info.SQL,
		ParameterOIDs: info.ParameterOIDs,
	})
	swallow.parseComplete++
	return swallow
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

// clearBackendPSCache drops a backend's record of which statements it
// has been shown. Called on every release of a backend out of a session
// (see relayImpl's release), and on DDL.
//
// Two distinct reasons, both load-bearing:
//
//   - "DISCARD ALL" wipes every prepared statement on the backend, so
//     keeping entries that say "backend knows S" produces exactly the
//     "does not exist" errors this machinery exists to avoid.
//   - Statement names are chosen per client. Without the reset query
//     the statements survive, and a stale entry lets the NEXT session's
//     Bind for a colliding name run the previous client's statement
//     instead of its own.
func clearBackendPSCache(b *backendConn) {
	if b == nil {
		return
	}
	b.preparedStmts = nil
}
