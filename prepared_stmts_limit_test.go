package main

import (
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// parseNamed drives one named Parse through the same entry point the
// relay loop uses, so these tests exercise the real interception path
// rather than trackClientParse in isolation.
func parseNamed(f *psFixture, name, sql string) {
	f.t.Helper()
	processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Parse{Name: name, Query: sql})
}

func bindNamed(f *psFixture, name string) {
	f.t.Helper()
	processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Bind{PreparedStatement: name})
}

// TestPreparedStmtCacheStaysWithinLimit is the memory-safety regression:
// the cache holds every statement's full SQL text and the client picks
// both the names and how many there are, so an uncapped cache is an
// out-of-memory primitive available to any connecting client.
func TestPreparedStmtCacheStaysWithinLimit(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 10

	for i := 0; i < 1000; i++ {
		parseNamed(f, fmt.Sprintf("stmt_%d", i), "SELECT 1")
	}

	if got := len(f.sess.psCache); got != 10 {
		t.Fatalf("psCache holds %d statements, want at most the limit of 10", got)
	}
	// The backend-side set must be trimmed alongside it: in session
	// pooling that backend is never released, so anything left there is
	// never collected either.
	if got := len(f.backend.preparedStmts); got > 10 {
		t.Errorf("backend.preparedStmts holds %d entries, want at most 10", got)
	}
}

// TestPreparedStmtCacheEvictsLeastRecentlyUsed pins the eviction order.
// Dropping the entry a client is actively binding would make the cap
// break the hot path it is supposed to protect.
func TestPreparedStmtCacheEvictsLeastRecentlyUsed(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 3

	parseNamed(f, "a", "SELECT 'a'")
	parseNamed(f, "b", "SELECT 'b'")
	parseNamed(f, "c", "SELECT 'c'")

	// "a" is the oldest by Parse order, but using it here must promote
	// it past "b", which nothing has touched since.
	bindNamed(f, "a")

	parseNamed(f, "d", "SELECT 'd'")

	if _, ok := f.sess.psCache["b"]; ok {
		t.Error(`"b" was the least recently used entry and should have been evicted`)
	}
	for _, name := range []string{"a", "c", "d"} {
		if _, ok := f.sess.psCache[name]; !ok {
			t.Errorf("%q was evicted, but it is more recently used than %q", name, "b")
		}
	}
}

// TestPreparedStmtEvictionDegradesToPlainForward documents what an
// evicted statement costs the client: the Bind is forwarded untouched,
// with no Parse prepended and no phantom ParseComplete to swallow. On a
// backend that still holds the statement it just works; on a fresh one
// Postgres answers 26000, which every driver with its own statement
// cache re-Parses through.
func TestPreparedStmtEvictionDegradesToPlainForward(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 1

	parseNamed(f, "old", "SELECT 'old'")
	parseNamed(f, "new", "SELECT 'new'") // evicts "old"

	msg, swallow := processClientMsg(f.fe, f.backend, f.sess,
		&pgproto3.Bind{PreparedStatement: "old"})

	if swallow != 0 {
		t.Errorf("swallowParseComplete = %d, want 0 — nothing was prepended for an evicted statement", swallow)
	}
	if bind, ok := msg.(*pgproto3.Bind); !ok || bind.PreparedStatement != "old" {
		t.Errorf("the client's Bind must be forwarded unchanged, got %#v", msg)
	}
}

// TestPreparedStmtCacheUncappedWhenLimitNonPositive keeps the documented
// escape hatch working — and keeps every pre-existing test in this
// package, which builds sessions with a zero psLimit, on the old path.
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
