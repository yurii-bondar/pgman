package main

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// adminExchange runs one admin SQL string through handleAdminQuery and
// returns everything the proxy wrote back, decoded.
//
// net.Pipe is unbuffered, so the reader has to run concurrently with the
// handler or both sides deadlock on the first write.
func adminExchange(t *testing.T, registry *PoolRegistry, sql string) []pgproto3.BackendMessage {
	t.Helper()
	proxySide, clientSide := net.Pipe()
	t.Cleanup(func() { proxySide.Close(); clientSide.Close() })

	type result struct {
		msgs []pgproto3.BackendMessage
		err  error
	}
	done := make(chan result, 1)
	go func() {
		fe := pgproto3.NewFrontend(clientSide, clientSide)
		var msgs []pgproto3.BackendMessage
		for {
			msg, err := fe.Receive()
			if err != nil {
				done <- result{msgs, err}
				return
			}
			// pgproto3 reuses message structs across Receive calls, so
			// anything kept past the next call must be copied.
			msgs = append(msgs, cloneBackendMessage(msg))
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				done <- result{msgs, nil}
				return
			}
		}
	}()

	handleAdminQuery(pgproto3.NewBackend(proxySide, proxySide), registry, sql)

	r := <-done
	if r.err != nil {
		t.Fatalf("reading admin reply for %q: %v", sql, r.err)
	}
	return r.msgs
}

func cloneBackendMessage(msg pgproto3.BackendMessage) pgproto3.BackendMessage {
	switch m := msg.(type) {
	case *pgproto3.RowDescription:
		c := *m
		c.Fields = append([]pgproto3.FieldDescription(nil), m.Fields...)
		return &c
	case *pgproto3.DataRow:
		c := *m
		c.Values = make([][]byte, len(m.Values))
		for i, v := range m.Values {
			c.Values[i] = append([]byte(nil), v...)
		}
		return &c
	case *pgproto3.CommandComplete:
		c := *m
		c.CommandTag = append([]byte(nil), m.CommandTag...)
		return &c
	case *pgproto3.ErrorResponse:
		c := *m
		return &c
	case *pgproto3.ReadyForQuery:
		c := *m
		return &c
	}
	return msg
}

func findMessage[T pgproto3.BackendMessage](msgs []pgproto3.BackendMessage) (T, bool) {
	for _, m := range msgs {
		if typed, ok := m.(T); ok {
			return typed, true
		}
	}
	var zero T
	return zero, false
}

func countDataRows(msgs []pgproto3.BackendMessage) int {
	n := 0
	for _, m := range msgs {
		if _, ok := m.(*pgproto3.DataRow); ok {
			n++
		}
	}
	return n
}

func adminTestRegistry(t *testing.T) *PoolRegistry {
	t.Helper()
	return NewPoolRegistry(map[string]PoolConfig{
		"backoffice": dummyPoolConfig(4),
		"game_rgs":   dummyPoolConfig(7),
	}, NewEventLog(10))
}

// TestAdminQueryAlwaysEndsWithReadyForQuery is the protocol invariant
// that keeps an admin session usable. A client blocks until it sees
// ReadyForQuery, so a command path that forgets to send one hangs the
// psql session rather than reporting an error.
func TestAdminQueryAlwaysEndsWithReadyForQuery(t *testing.T) {
	commands := []string{
		"SHOW POOLS", "SHOW STATS", "SHOW CLIENTS", "SHOW SERVERS",
		"SHOW DATABASES", "SHOW LISTS", "SHOW VERSION",
		"PAUSE", "RESUME", "RECONNECT",
		"PAUSE backoffice", "RESUME backoffice",
		"DROP TABLE users", // unsupported — still must terminate cleanly
		"",
	}
	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			msgs := adminExchange(t, adminTestRegistry(t), cmd)
			last := msgs[len(msgs)-1]
			if _, ok := last.(*pgproto3.ReadyForQuery); !ok {
				t.Fatalf("last message is %T, want ReadyForQuery", last)
			}
		})
	}
}

// TestAdminQueryRejectsArbitrarySQL: the virtual admin database is a
// fixed command surface, not a SQL engine. Anything unrecognised must
// come back as a syntax error rather than reaching a backend.
func TestAdminQueryRejectsArbitrarySQL(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM pg_shadow",
		"DROP DATABASE app",
		"SHOW POOLS; DROP TABLE users",
		"SET password_encryption = 'md5'",
	} {
		t.Run(sql, func(t *testing.T) {
			msgs := adminExchange(t, adminTestRegistry(t), sql)
			errResp, ok := findMessage[*pgproto3.ErrorResponse](msgs)
			if !ok {
				t.Fatalf("%q was not rejected", sql)
			}
			if errResp.Code != "42601" {
				t.Errorf("SQLSTATE = %s, want 42601 (syntax_error)", errResp.Code)
			}
			if countDataRows(msgs) != 0 {
				t.Error("a rejected command must not return rows")
			}
		})
	}
}

// TestAdminQueryIsCaseAndSemicolonInsensitive: psql appends a semicolon
// and people type in whatever case they like.
func TestAdminQueryAcceptsCasingAndTrailingSemicolon(t *testing.T) {
	for _, sql := range []string{"SHOW POOLS", "show pools", "  Show Pools ;  "} {
		t.Run(sql, func(t *testing.T) {
			msgs := adminExchange(t, adminTestRegistry(t), sql)
			if _, ok := findMessage[*pgproto3.ErrorResponse](msgs); ok {
				t.Fatalf("%q was rejected", sql)
			}
			if countDataRows(msgs) != 2 {
				t.Errorf("got %d rows, want one per pool", countDataRows(msgs))
			}
		})
	}
}

func TestShowPoolsReturnsRowPerPool(t *testing.T) {
	msgs := adminExchange(t, adminTestRegistry(t), "SHOW POOLS")

	desc, ok := findMessage[*pgproto3.RowDescription](msgs)
	if !ok {
		t.Fatal("no RowDescription — clients cannot decode the result")
	}
	if len(desc.Fields) == 0 {
		t.Fatal("RowDescription has no columns")
	}
	if got := countDataRows(msgs); got != 2 {
		t.Errorf("got %d rows, want 2", got)
	}
	cc, ok := findMessage[*pgproto3.CommandComplete](msgs)
	if !ok {
		t.Fatal("no CommandComplete")
	}
	if string(cc.CommandTag) != "SHOW" {
		t.Errorf("CommandTag = %q, want SHOW", cc.CommandTag)
	}
}

// TestPauseResumeAffectTheNamedPoolOnly: PAUSE with an argument is how
// an operator drains one database before a failover. Pausing everything
// instead would be an outage.
func TestPauseResumeAffectTheNamedPoolOnly(t *testing.T) {
	registry := adminTestRegistry(t)
	target, _ := registry.Get("backoffice")
	other, _ := registry.Get("game_rgs")

	adminExchange(t, registry, "PAUSE backoffice")
	if !target.IsPaused() {
		t.Error("the named pool was not paused")
	}
	if other.IsPaused() {
		t.Error("PAUSE with an argument must not touch other pools")
	}

	adminExchange(t, registry, "RESUME backoffice")
	if target.IsPaused() {
		t.Error("RESUME did not un-pause the named pool")
	}
}

func TestBarePauseResumeAffectEveryPool(t *testing.T) {
	registry := adminTestRegistry(t)

	adminExchange(t, registry, "PAUSE")
	for name, p := range registry.Pools() {
		if !p.IsPaused() {
			t.Errorf("pool %q was not paused by a bare PAUSE", name)
		}
	}

	adminExchange(t, registry, "RESUME")
	for name, p := range registry.Pools() {
		if p.IsPaused() {
			t.Errorf("pool %q was not resumed by a bare RESUME", name)
		}
	}
}

// TestPauseUnknownPoolReportsNotFound: silently succeeding on a typo
// would leave the operator believing a pool is drained when it is
// serving traffic.
func TestPauseUnknownPoolReportsNotFound(t *testing.T) {
	registry := adminTestRegistry(t)

	msgs := adminExchange(t, registry, "PAUSE nosuchpool")
	errResp, ok := findMessage[*pgproto3.ErrorResponse](msgs)
	if !ok {
		t.Fatal("PAUSE of an unknown pool reported success")
	}
	if errResp.Code != "3D000" {
		t.Errorf("SQLSTATE = %s, want 3D000 (invalid_catalog_name)", errResp.Code)
	}
	for name, p := range registry.Pools() {
		if p.IsPaused() {
			t.Errorf("pool %q was paused by a failed command", name)
		}
	}
}

func TestShowVersionReportsPgman(t *testing.T) {
	msgs := adminExchange(t, adminTestRegistry(t), "SHOW VERSION")

	row, ok := findMessage[*pgproto3.DataRow](msgs)
	if !ok {
		t.Fatal("SHOW VERSION returned no row")
	}
	if !strings.Contains(string(row.Values[0]), "pgman") {
		t.Errorf("version = %q, want it to identify pgman", row.Values[0])
	}
}

// TestHandleAdminExtendedMsgAcksEveryMessage: drivers like pgx use the
// extended protocol by default. Without these acks a client issuing
// SHOW POOLS through a prepared statement waits forever.
func TestHandleAdminExtendedMsgAcksEveryMessage(t *testing.T) {
	cases := []struct {
		in   pgproto3.FrontendMessage
		want pgproto3.BackendMessage
	}{
		{&pgproto3.Parse{}, &pgproto3.ParseComplete{}},
		{&pgproto3.Bind{}, &pgproto3.BindComplete{}},
		{&pgproto3.Describe{}, &pgproto3.NoData{}},
		{&pgproto3.Execute{}, &pgproto3.CommandComplete{}},
		{&pgproto3.Close{}, &pgproto3.CloseComplete{}},
	}
	for _, tc := range cases {
		t.Run(strings.TrimPrefix(typeName(tc.in), "*pgproto3."), func(t *testing.T) {
			proxySide, clientSide := net.Pipe()
			t.Cleanup(func() { proxySide.Close(); clientSide.Close() })

			got := make(chan pgproto3.BackendMessage, 1)
			go func() {
				fe := pgproto3.NewFrontend(clientSide, clientSide)
				msg, err := fe.Receive()
				if err != nil {
					close(got)
					return
				}
				got <- cloneBackendMessage(msg)
			}()

			handleAdminExtendedMsg(pgproto3.NewBackend(proxySide, proxySide), tc.in)

			reply, ok := <-got
			if !ok {
				t.Fatalf("%T was never acknowledged", tc.in)
			}
			if typeName(reply) != typeName(tc.want) {
				t.Errorf("got %s, want %s", typeName(reply), typeName(tc.want))
			}
		})
	}
}

func typeName(v any) string {
	return fmt.Sprintf("%T", v)
}
