package main

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// parseNamed drives one named Parse through the same entry point the
// relay loop uses, so these tests exercise the real interception path
// rather than trackClientParse in isolation.
func parseNamed(f *psFixture, name, sql string) psSwallow {
	f.t.Helper()
	_, swallow := f.process(&pgproto3.Parse{Name: name, Query: sql})
	return swallow
}

func bindNamed(f *psFixture, name string) psSwallow {
	f.t.Helper()
	_, swallow := f.process(&pgproto3.Bind{PreparedStatement: name})
	return swallow
}

// TestBackendCacheStaysWithinLimit: max_prepared_statements bounds how
// many statements one backend connection keeps prepared, which is what
// the setting means in PgBouncer and what actually costs memory — in
// the Postgres backend's plan cache as much as here.
func TestBackendCacheStaysWithinLimit(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 10

	// Below the session ceiling (limit × sessionPSCeilingFactor), so
	// the only cap under test here is the backend cache's.
	for i := 0; i < 30; i++ {
		parseNamed(f, fmt.Sprintf("stmt_%d", i), "SELECT 1")
	}

	if got := len(f.backend.preparedStmts); got != 10 {
		t.Fatalf("backend.preparedStmts holds %d entries, want the limit of 10", got)
	}
}

// TestSessionCacheKeepsEveryStatementForReplay is the regression this
// design exists for. The session map is the only copy of a statement's
// SQL; dropping an entry there means a later Bind cannot be replayed
// and can reach a backend that never saw the Parse, which Postgres
// answers with 26000 — a failure that only shows up under the load
// that moves connections between clients.
func TestSessionCacheKeepsEveryStatementForReplay(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 10

	for i := 0; i < 30; i++ {
		parseNamed(f, fmt.Sprintf("stmt_%d", i), "SELECT 1")
	}

	if got := len(f.sess.psCache); got != 30 {
		t.Fatalf("psCache holds %d statements, want all 30: the cap belongs on the backend cache", got)
	}

	// The very first statement was evicted from the backend long ago.
	// Binding it must produce a replay, not a bare forward.
	swallow := bindNamed(f, "stmt_0")
	if swallow.parseComplete != 1 {
		t.Errorf("Bind for a statement evicted from the backend prepended %d Parses, want 1",
			swallow.parseComplete)
	}
}

// TestBackendEvictionClosesStatementOnBackend: forgetting the entry
// without closing it leaves the statement, and its cached plan,
// resident in the Postgres backend for the life of the connection —
// which in session pooling is the life of the client.
func TestBackendEvictionClosesStatementOnBackend(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 1

	parseNamed(f, "first", "SELECT 'first'")
	swallow := parseNamed(f, "second", "SELECT 'second'")

	if swallow.closeComplete != 1 {
		t.Fatalf("eviction produced %d Closes, want 1 — the statement was forgotten, not closed",
			swallow.closeComplete)
	}
	if err := f.fe.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// The client's own Parse messages are forwarded by the relay loop,
	// not by processClientMsg, so the only thing buffered here is what
	// the proxy injected: the Close for the evicted statement.
	msg := <-f.msgs
	c, ok := msg.(*pgproto3.Close)
	if !ok {
		t.Fatalf("backend received %T, want the Close for the evicted statement", msg)
	}
	if c.ObjectType != 'S' || c.Name != "first" {
		t.Errorf("Close = %+v, want statement 'first'", c)
	}
}

// TestBackendCacheEvictsLeastRecentlyUsed pins the eviction order.
// Closing the statement a client is actively binding would make the cap
// re-Parse the hot statement on every single Bind.
func TestBackendCacheEvictsLeastRecentlyUsed(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 3

	parseNamed(f, "a", "SELECT 'a'")
	parseNamed(f, "b", "SELECT 'b'")
	parseNamed(f, "c", "SELECT 'c'")

	// "a" is the oldest by Parse order, but using it here must promote
	// it past "b", which nothing has touched since.
	bindNamed(f, "a")

	parseNamed(f, "d", "SELECT 'd'")

	if _, ok := f.backend.preparedStmts["b"]; ok {
		t.Error(`"b" was the least recently used entry and should have been evicted`)
	}
	for _, name := range []string{"a", "c", "d"} {
		if _, ok := f.backend.preparedStmts[name]; !ok {
			t.Errorf("%q was evicted from the backend, but it is more recently used than %q", name, "b")
		}
	}
}

// TestSessionCeilingEndsSessionRatherThanLosingStatements: the session
// map cannot grow forever — every entry holds the statement's full SQL
// and the client picks both the names and how many. Past the ceiling
// the session is ended with a diagnosable error, because the
// alternatives are an out-of-memory kill or silently dropping a
// statement the proxy has promised it can replay.
func TestSessionCeilingEndsSessionRatherThanLosingStatements(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 2 // ceiling = 2 × sessionPSCeilingFactor

	ceiling := sessionPSCeiling(f.sess.psLimit)
	for i := 0; i < ceiling; i++ {
		if _, _, err := processClientMsg(f.fe, f.backend, f.sess,
			&pgproto3.Parse{Name: fmt.Sprintf("stmt_%d", i), Query: "SELECT 1"}); err != nil {
			t.Fatalf("statement %d of %d was refused below the ceiling: %v", i, ceiling, err)
		}
	}

	_, _, err := processClientMsg(f.fe, f.backend, f.sess,
		&pgproto3.Parse{Name: "one_too_many", Query: "SELECT 1"})
	if err == nil {
		t.Fatal("the statement past the ceiling was accepted")
	}
	if _, recorded := f.sess.psCache["one_too_many"]; recorded {
		t.Error("the refused statement was recorded anyway, which would make the error a lie")
	}

	// Re-preparing a name already held is not growth, so it stays legal
	// even at the ceiling — this is what a driver does when it re-Parses
	// a statement whose plan was invalidated.
	if _, _, err := processClientMsg(f.fe, f.backend, f.sess,
		&pgproto3.Parse{Name: "stmt_0", Query: "SELECT 2"}); err != nil {
		t.Errorf("re-Parse of an existing name was refused at the ceiling: %v", err)
	}
}

// TestPreparedStmtCacheUncappedWhenLimitNonPositive keeps the documented
// escape hatch working — and keeps every pre-existing test in this
// package, which builds sessions with a zero psLimit, on the uncapped
// path.
func TestPreparedStmtCacheUncappedWhenLimitNonPositive(t *testing.T) {
	for _, limit := range []int{0, -1} {
		f := newPSFixture(t)
		f.sess.psLimit = limit
		for i := 0; i < 50; i++ {
			parseNamed(f, fmt.Sprintf("stmt_%d", i), "SELECT 1")
		}
		if got := len(f.sess.psCache); got != 50 {
			t.Errorf("psLimit=%d: psCache holds %d, want all 50 (uncapped)", limit, got)
		}
		if got := len(f.backend.preparedStmts); got != 50 {
			t.Errorf("psLimit=%d: backend cache holds %d, want all 50 (uncapped)", limit, got)
		}
	}
}

func TestMaxPreparedStatementsDefault(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()
	if cfg.MaxPreparedStatements != defaultMaxPreparedStatements {
		t.Errorf("default = %d, want %d", cfg.MaxPreparedStatements, defaultMaxPreparedStatements)
	}
	// Negative must survive applyDefaults — it is the "no cap" opt-out,
	// not an unset value to be filled in.
	cfg = Config{MaxPreparedStatements: -1}
	cfg.applyDefaults()
	if cfg.MaxPreparedStatements != -1 {
		t.Errorf("explicit -1 became %d — the uncapped opt-out was overwritten", cfg.MaxPreparedStatements)
	}
}
