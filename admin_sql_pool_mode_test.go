package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// poolModeRegistry has one pool of each shape: an explicitly
// session-pooled one, one left at the default, and one written in the
// case a YAML file might carry it in.
func poolModeRegistry() *PoolRegistry {
	held := dummyPoolConfig(2)
	held.PoolMode = "session"
	shouty := dummyPoolConfig(2)
	shouty.PoolMode = "SESSION"

	return NewPoolRegistry(map[string]PoolConfig{
		"held":    held,
		"shouty":  shouty,
		"default": dummyPoolConfig(2),
	}, NewEventLog(10))
}

// rowsByName indexes DataRows by the value in their first column, which
// every admin SHOW puts the pool name in.
func rowsByName(msgs []pgproto3.BackendMessage) map[string][][]byte {
	out := make(map[string][][]byte)
	for _, m := range msgs {
		if row, ok := m.(*pgproto3.DataRow); ok && len(row.Values) > 0 {
			out[string(row.Values[0])] = row.Values
		}
	}
	return out
}

// TestShowPoolsReportsRealPoolMode: this column used to be hardcoded to
// "transaction". An operator reading it during an incident is deciding
// whether a backend is pinned to a session or recycled per transaction,
// and a constant answers that question wrongly for every pool
// configured otherwise.
func TestShowPoolsReportsRealPoolMode(t *testing.T) {
	const poolModeColumn = 6 // database, cl_active, cl_waiting, sv_active, sv_idle, maxwait, pool_mode, paused

	msgs := adminExchange(t, poolModeRegistry(), "SHOW POOLS")
	rows := rowsByName(msgs)

	for name, want := range map[string]string{
		"held":    "session",
		"shouty":  "session", // case-insensitive, like the router's own reading
		"default": "transaction",
	} {
		row, ok := rows[name]
		if !ok {
			t.Fatalf("SHOW POOLS has no row for %q", name)
		}
		if got := string(row[poolModeColumn]); got != want {
			t.Errorf("pool %q reports pool_mode %q, want %q", name, got, want)
		}
	}
}

func TestShowDatabasesReportsRealPoolMode(t *testing.T) {
	const poolModeColumn = 5 // name, host, port, database, pool_size, pool_mode

	msgs := adminExchange(t, poolModeRegistry(), "SHOW DATABASES")
	rows := rowsByName(msgs)

	if got := string(rows["held"][poolModeColumn]); got != "session" {
		t.Errorf("pool_mode = %q, want session", got)
	}
	if got := string(rows["default"][poolModeColumn]); got != "transaction" {
		t.Errorf("pool_mode = %q, want transaction", got)
	}
}

// TestEffectivePoolModeMatchesTheRouter keeps the two readings of the
// setting from drifting: the relay decides when to release a backend
// from one, and every admin surface reports the other.
func TestEffectivePoolModeMatchesTheRouter(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{
		{"", "transaction"},
		{"transaction", "transaction"},
		{"session", "session"},
		{"Session", "session"},
		{"statement", "statement"},
	} {
		if got := effectivePoolMode(tc.configured); got != tc.want {
			t.Errorf("effectivePoolMode(%q) = %q, want %q", tc.configured, got, tc.want)
		}
	}
}
