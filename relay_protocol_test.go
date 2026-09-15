package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// The extended query protocol through a live proxy. Every driver worth
// naming — pgx, JDBC, Npgsql — uses it by default, so the batch handling
// and the prepared-statement replay are the paths most production
// traffic actually takes, while a simple `SELECT 1` exercises neither.

// extendedQuery sends one Parse/Bind/Execute/Sync batch and reads to
// ReadyForQuery.
func (c *pgClient) extendedQuery(name, sql string) ([]pgproto3.BackendMessage, error) {
	c.t.Helper()
	c.fe.Send(&pgproto3.Parse{Name: name, Query: sql})
	c.fe.Send(&pgproto3.Bind{PreparedStatement: name})
	c.fe.Send(&pgproto3.Execute{})
	c.fe.Send(&pgproto3.Sync{})
	if err := c.fe.Flush(); err != nil {
		return nil, fmt.Errorf("send extended batch: %w", err)
	}
	return c.awaitReady()
}

// TestRunRelaysAnExtendedProtocolBatch: the relay must buffer the whole
// batch and only then wait for the backend, because Postgres answers
// nothing until Sync. Forwarding one message at a time and waiting would
// deadlock every extended-protocol client — which is to say all of them.
func TestRunRelaysAnExtendedProtocolBatch(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	msgs, err := client.extendedQuery("stmt1", "SELECT $1::text")
	if err != nil {
		t.Fatalf("extended batch: %v", err)
	}
	// The client asked for exactly one Parse, so it must see exactly one
	// ParseComplete: the proxy prepends Parses of its own and has to
	// swallow their acks, and an extra one is a corrupt stream to a
	// driver counting responses.
	var parseCompletes int
	for _, m := range msgs {
		if _, ok := m.(*pgproto3.ParseComplete); ok {
			parseCompletes++
		}
	}
	if parseCompletes != 1 {
		t.Errorf("client saw %d ParseCompletes for one Parse, want 1", parseCompletes)
	}
}

// TestRunReplaysPreparedStatementsOntoAFreshBackend is the whole reason
// the prepared-statement machinery exists: in transaction pooling the
// next transaction can land on a backend that never saw the client's
// Parse, and Postgres would answer 26000. The proxy has to replay it
// from its own record, invisibly.
func TestRunReplaysPreparedStatementsOntoAFreshBackend(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	// Two clients over a pool of one force the second transaction onto a
	// connection whose prepared-statement state belongs to somebody else.
	pc := cfg.Pools["db1"]
	pc.Limit = 1
	cfg.Pools["db1"] = pc
	proxy := startProxy(t, cfg, "")

	first := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := first.awaitReady(); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if _, err := first.extendedQuery("shared_name", "SELECT 'first client'"); err != nil {
		t.Fatalf("first client batch: %v", err)
	}

	second := dialProxy(t, proxy.addrs.Listen, "bob", "db1")
	if _, err := second.awaitReady(); err != nil {
		t.Fatalf("second handshake: %v", err)
	}
	// The same statement name, a different statement. Without a replay
	// keyed to this session, bob would execute alice's SQL.
	if _, err := second.extendedQuery("shared_name", "SELECT 'second client'"); err != nil {
		t.Fatalf("second client batch: %v", err)
	}

	var sawFirst, sawSecond bool
	for _, q := range backend.seenQueries() {
		if strings.Contains(q, "first client") {
			sawFirst = true
		}
		if strings.Contains(q, "second client") {
			sawSecond = true
		}
	}
	if !sawFirst || !sawSecond {
		t.Errorf("backend saw first=%v second=%v — each session's own statement must reach it",
			sawFirst, sawSecond)
	}
}

// TestRunEndsSessionAtThePreparedStatementCeiling: past the ceiling the
// proxy can no longer promise it can replay what the client prepared, so
// it says so with 54000 instead of silently dropping a statement the
// client will bind later.
func TestRunEndsSessionAtThePreparedStatementCeiling(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.MaxPreparedStatements = 1 // ceiling is a small multiple of this
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	ceiling := sessionPSCeiling(cfg.MaxPreparedStatements)
	var lastErr error
	for i := 0; i < ceiling+2; i++ {
		if _, lastErr = client.extendedQuery(fmt.Sprintf("stmt_%d", i), "SELECT 1"); lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatalf("the session survived more than %d named statements", ceiling)
	}
	if !strings.Contains(lastErr.Error(), "54000") {
		t.Errorf("error = %v, want SQLSTATE 54000 (program_limit_exceeded)", lastErr)
	}
	if !strings.Contains(lastErr.Error(), "max_prepared_statements") {
		t.Errorf("error = %v, want it to name the setting to raise", lastErr)
	}
}

// TestRunReleasesTheBackendWhenAClientVanishesMidBatch: a client that
// disappears part-way through Parse/Bind/Execute leaves the backend in
// an unknown state, and handing that connection to the next client would
// pass along whatever it was in the middle of.
func TestRunReleasesTheBackendWhenAClientVanishesMidBatch(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	pc := cfg.Pools["db1"]
	pc.Limit = 1
	cfg.Pools["db1"] = pc
	proxy := startProxy(t, cfg, "")

	victim := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := victim.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// An unfinished batch: no Sync, so the relay is still reading.
	victim.fe.Send(&pgproto3.Parse{Name: "half", Query: "SELECT 1"})
	victim.fe.Send(&pgproto3.Bind{PreparedStatement: "half"})
	if err := victim.fe.Flush(); err != nil {
		t.Fatalf("send partial batch: %v", err)
	}
	_ = victim.conn.Close()

	// The pool has one connection. If the abandoned session did not give
	// it back, this client cannot get one and the query times out.
	next := dialProxy(t, proxy.addrs.Listen, "bob", "db1")
	if _, err := next.awaitReady(); err != nil {
		t.Fatalf("second client handshake: %v", err)
	}
	if _, err := next.query("SELECT 1"); err != nil {
		t.Fatalf("the pool never recovered the abandoned connection: %v", err)
	}
}

// TestRunAnswersAClientThatTerminatesImmediately: a health checker that
// opens a connection and closes it without a query is common enough
// (and a port scanner is too) that the path must not leave anything
// behind.
func TestRunAnswersAClientThatTerminatesImmediately(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	client.fe.Send(&pgproto3.Terminate{})
	if err := client.fe.Flush(); err != nil {
		t.Fatalf("send terminate: %v", err)
	}

	// The proxy must still be serving afterwards.
	other := dialProxy(t, proxy.addrs.Listen, "bob", "db1")
	if _, err := other.awaitReady(); err != nil {
		t.Fatalf("a later client could not connect: %v", err)
	}
}
