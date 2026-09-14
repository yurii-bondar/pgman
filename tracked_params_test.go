package main

import (
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestExtractTrackedParamsFiltersToWhitelist(t *testing.T) {
	startup := map[string]string{
		"user":             "alice",
		"database":         "app",
		"application_name": "billing-worker",
		"TimeZone":         "Europe/Kyiv",
		"search_path":      "public,billing",
	}
	got := extractTrackedParams(startup, []string{"application_name", "TimeZone"})

	if len(got) != 2 {
		t.Fatalf("got %d params, want 2: %+v", len(got), got)
	}
	// user/database must never be replayed as GUCs — they are routing
	// inputs, and SET user would be a privilege change.
	for _, p := range got {
		if p.Name == "user" || p.Name == "database" {
			t.Errorf("%q must not be treated as a tracked parameter", p.Name)
		}
	}
}

// TestExtractTrackedParamsPreservesWhitelistOrder is not cosmetic.
// Some GUCs depend on others already being set (IntervalStyle before
// DateStyle is the classic pair), so replay order is part of the
// contract — and map iteration order in Go is deliberately random.
func TestExtractTrackedParamsPreservesWhitelistOrder(t *testing.T) {
	startup := map[string]string{
		"DateStyle":        "ISO, DMY",
		"IntervalStyle":    "postgres",
		"application_name": "app",
	}
	whitelist := []string{"IntervalStyle", "DateStyle", "application_name"}

	// Repeat: a single pass could pass by luck if the implementation
	// ranged over the map.
	for i := 0; i < 20; i++ {
		got := extractTrackedParams(startup, whitelist)
		if len(got) != 3 {
			t.Fatalf("got %d params, want 3", len(got))
		}
		for j, want := range whitelist {
			if got[j].Name != want {
				t.Fatalf("position %d = %q, want %q (replay order must follow the whitelist)",
					j, got[j].Name, want)
			}
		}
	}
}

func TestExtractTrackedParamsIsCaseInsensitiveOnStartupKeys(t *testing.T) {
	// pgx sends lowercase keys for the standard GUCs, but the operator
	// writes them in the canonical mixed case in config.
	startup := map[string]string{"timezone": "UTC"}
	got := extractTrackedParams(startup, []string{"TimeZone"})

	if len(got) != 1 {
		t.Fatalf("got %d params, want 1", len(got))
	}
	if got[0].Value != "UTC" {
		t.Errorf("value = %q, want UTC", got[0].Value)
	}
	// The name keeps the operator's casing so the emitted SET and any
	// log line match what was configured.
	if got[0].Name != "TimeZone" {
		t.Errorf("name = %q, want TimeZone", got[0].Name)
	}
}

func TestExtractTrackedParamsSkipsEmptyAndDisabled(t *testing.T) {
	startup := map[string]string{"application_name": "", "TimeZone": "UTC"}
	// "-" is PgBouncer's way of spelling "disabled" in a list.
	got := extractTrackedParams(startup, []string{"", "-", "application_name", "TimeZone"})

	if len(got) != 1 || got[0].Name != "TimeZone" {
		t.Fatalf("got %+v, want only TimeZone (empty values and \"-\" are skipped)", got)
	}
}

func TestExtractTrackedParamsEmptyInputs(t *testing.T) {
	if got := extractTrackedParams(nil, []string{"TimeZone"}); got != nil {
		t.Errorf("nil startup should yield nil, got %+v", got)
	}
	if got := extractTrackedParams(map[string]string{"TimeZone": "UTC"}, nil); got != nil {
		t.Errorf("empty whitelist should yield nil, got %+v", got)
	}
}

func TestQuoteIdentAndLiteralEscape(t *testing.T) {
	// A GUC name or value arrives straight from the client's
	// StartupMessage, so it is attacker-controlled text being spliced
	// into SQL. Doubling is the SQL-standard escape and works
	// regardless of standard_conforming_strings.
	if got := quoteIdent(`foo"; DROP TABLE t; --`); got != `"foo""; DROP TABLE t; --"` {
		t.Errorf("quoteIdent = %s", got)
	}
	if got := quoteLiteral(`it's'; DROP TABLE t; --`); got != `'it''s''; DROP TABLE t; --'` {
		t.Errorf("quoteLiteral = %s", got)
	}
}

// startupParamsFrontend wires a Frontend to a scripted fake backend and
// returns the SQL the frontend sent.
func startupParamsFrontend(t *testing.T, reply func(*pgproto3.Backend)) (*pgproto3.Frontend, <-chan string) {
	t.Helper()
	proxySide, serverSide := net.Pipe()
	t.Cleanup(func() { proxySide.Close(); serverSide.Close() })

	sqlCh := make(chan string, 1)
	go func() {
		be := pgproto3.NewBackend(serverSide, serverSide)
		msg, err := be.Receive()
		if err != nil {
			close(sqlCh)
			return
		}
		q, ok := msg.(*pgproto3.Query)
		if !ok {
			close(sqlCh)
			return
		}
		sqlCh <- q.String
		reply(be)
	}()
	return pgproto3.NewFrontend(proxySide, proxySide), sqlCh
}

// TestApplyTrackedParamsSendsOneBatchedQuery pins the round-trip cost.
// This runs on every backend acquire in transaction mode, so one SET
// per parameter would add a round trip per GUC to every transaction.
func TestApplyTrackedParamsSendsOneBatchedQuery(t *testing.T) {
	fe, sqlCh := startupParamsFrontend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SET")})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	})

	params := []trackedParam{
		{Name: "application_name", Value: "billing"},
		{Name: "TimeZone", Value: "Europe/Kyiv"},
	}
	if err := applyTrackedParams(fe, params); err != nil {
		t.Fatalf("applyTrackedParams: %v", err)
	}

	sql, ok := <-sqlCh
	if !ok {
		t.Fatal("backend never received a Query")
	}
	if n := strings.Count(sql, ";"); n != 1 {
		t.Errorf("SQL %q contains %d separators; the two SETs must ride in one Query", sql, n)
	}
	if !strings.Contains(sql, `SET "application_name" = 'billing'`) {
		t.Errorf("SQL %q is missing the quoted application_name assignment", sql)
	}
	if !strings.Contains(sql, `SET "TimeZone" = 'Europe/Kyiv'`) {
		t.Errorf("SQL %q is missing the quoted TimeZone assignment", sql)
	}
}

// TestApplyTrackedParamsSurfacesBackendError: a rejected SET means the
// backend does not carry the session state the client asked for, so the
// caller must be able to discard it rather than hand it over silently.
func TestApplyTrackedParamsSurfacesBackendError(t *testing.T) {
	fe, _ := startupParamsFrontend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "42704",
			Message:  `unrecognized configuration parameter "nope"`,
		})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	})

	err := applyTrackedParams(fe, []trackedParam{{Name: "nope", Value: "x"}})
	if err == nil {
		t.Fatal("expected an error when the backend rejects the SET")
	}
	if !strings.Contains(err.Error(), "42704") {
		t.Errorf("error %q should carry the SQLSTATE so the operator can diagnose it", err)
	}
}

func TestApplyTrackedParamsNoParamsIsNoOp(t *testing.T) {
	// nil Frontend proves no I/O is attempted — the function must
	// return before touching it.
	if err := applyTrackedParams(nil, nil); err != nil {
		t.Errorf("empty params should be a no-op, got %v", err)
	}
}
