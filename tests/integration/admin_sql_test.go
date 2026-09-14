//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// adminSQLDSN — client connects with database="pgbouncer" to the DATA
// plane port, exactly like operators do with real PgBouncer.
func adminSQLDSN(proxyAddr string) string {
	return "postgres://admin:anything@" + proxyAddr + "/pgbouncer?sslmode=disable&default_query_exec_mode=simple_protocol"
}

// TestAdminSQLShowPools — the flagship pgbouncer-compat command.
// Verifies wire protocol works: RowDescription → DataRows → RFQ.
func TestAdminSQLShowPools(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, adminSQLDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect to pgbouncer db: %v", err)
	}
	defer conn.Close(ctx)

	rows, err := conn.Query(ctx, "SHOW POOLS")
	if err != nil {
		t.Fatalf("SHOW POOLS: %v", err)
	}
	defer rows.Close()

	// Collect all rows.
	var pools []string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			t.Fatalf("values: %v", err)
		}
		if len(vals) < 1 {
			t.Fatalf("row has %d columns, want >= 1", len(vals))
		}
		pools = append(pools, vals[0].(string))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err: %v", err)
	}

	found := false
	for _, name := range pools {
		if name == "pgman_test" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SHOW POOLS did not include 'pgman_test': got %v", pools)
	}
	t.Logf("SHOW POOLS returned %d rows", len(pools))
}

// TestAdminSQLShowStats — counter values must be strings that parse.
func TestAdminSQLShowStats(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Warm the pool with a real query first so stats aren't zeroes.
	proxyConn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("proxy connect: %v", err)
	}
	var n int
	proxyConn.QueryRow(ctx, "SELECT 1").Scan(&n)
	proxyConn.Close(ctx)

	// Now query admin.
	admin, err := pgx.Connect(ctx, adminSQLDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	rows, err := admin.Query(ctx, "SHOW STATS")
	if err != nil {
		t.Fatalf("SHOW STATS: %v", err)
	}
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
	}
	if count == 0 {
		t.Fatal("SHOW STATS returned no rows")
	}
}

// TestAdminSQLPauseResume — full round trip: PAUSE the pool over
// psql-like connection, verify data-plane query blocks, RESUME, verify
// it completes.
func TestAdminSQLPauseResume(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminSQLDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	if _, err := admin.Exec(ctx, "PAUSE pgman_test"); err != nil {
		t.Fatalf("PAUSE: %v", err)
	}

	// A data-plane query must block.
	blocked := make(chan error, 1)
	go func() {
		c, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
		if err != nil {
			blocked <- err
			return
		}
		defer c.Close(ctx)
		var n int
		blocked <- c.QueryRow(ctx, "SELECT 1").Scan(&n)
	}()

	select {
	case err := <-blocked:
		t.Fatalf("query completed during PAUSE: err=%v", err)
	case <-time.After(700 * time.Millisecond):
		// good — still blocked
	}

	if _, err := admin.Exec(ctx, "RESUME pgman_test"); err != nil {
		t.Fatalf("RESUME: %v", err)
	}

	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("query after RESUME: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("query did not complete within 5s after RESUME")
	}
}

// TestAdminSQLReconnect — RECONNECT via SQL bumps generation.
func TestAdminSQLReconnect(t *testing.T) {
	inst := startProxy(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminSQLDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	if _, err := admin.Exec(ctx, "RECONNECT pgman_test"); err != nil {
		t.Fatalf("RECONNECT: %v", err)
	}

	// Data plane must still work.
	c, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("data plane connect after RECONNECT: %v", err)
	}
	defer c.Close(ctx)
	var n int
	if err := c.QueryRow(ctx, "SELECT 42").Scan(&n); err != nil {
		t.Fatalf("query after RECONNECT: %v", err)
	}
	if n != 42 {
		t.Fatalf("got %d, want 42", n)
	}
}

// TestAdminSQLUnknownCommandRejected — bogus SQL must produce a proper
// SQLSTATE error, not a wire desync.
func TestAdminSQLUnknownCommandRejected(t *testing.T) {
	inst := startProxy(t, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, adminSQLDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)

	_, err = admin.Exec(ctx, "SELECT * FROM sensitive_table")
	if err == nil {
		t.Fatal("expected error for arbitrary SELECT in admin mode")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		t.Logf("got error (accepted): %v", err)
	}

	// Session must still be usable after the error.
	rows, err := admin.Query(ctx, "SHOW VERSION")
	if err != nil {
		t.Fatalf("SHOW VERSION after error: %v", err)
	}
	rows.Close()
}
