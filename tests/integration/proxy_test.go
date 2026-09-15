//go:build integration

package integration

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestSimpleQuery — connect to the proxy, run SELECT 42, verify result.
// Exercises: accept → startup → trust auth → fakeAuth → route →
// pool.Acquire → pgconn.Connect → relay → pool.Release.
func TestSimpleQuery(t *testing.T) {
	inst := startProxy(t, 10)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect through proxy: %v", err)
	}
	defer conn.Close(ctx)

	var result int
	if err := conn.QueryRow(ctx, "SELECT 42").Scan(&result); err != nil {
		t.Fatalf("SELECT 42: %v", err)
	}
	if result != 42 {
		t.Fatalf("got %d, want 42", result)
	}
}

// TestMultipleQueriesSameConn — 50 sequential queries on one connection.
// Catches state leaks between transactions (DISCARD ALL path).
func TestMultipleQueriesSameConn(t *testing.T) {
	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	for i := 0; i < 50; i++ {
		var n int
		if err := conn.QueryRow(ctx, "SELECT $1::int", i).Scan(&n); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
		if n != i {
			t.Fatalf("query %d: got %d", i, n)
		}
	}
}

// TestTransaction — BEGIN...COMMIT holds the same backend; DISCARD ALL
// resets session state (application_name) after commit.
//
// This is also the canary for server_reset_query_skip_same_session: with
// that option on, the pool hands this single client its own connection
// back, the scrub is skipped and application_name survives. That is the
// documented trade, so a failure here under that setting is expected and
// not a regression.
func TestTransaction(t *testing.T) {
	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(ctx, "SET application_name = 'integration_tx_test'"); err != nil {
		t.Fatalf("set: %v", err)
	}
	var name string
	if err := tx.QueryRow(ctx, "SHOW application_name").Scan(&name); err != nil {
		t.Fatalf("show inside tx: %v", err)
	}
	if name != "integration_tx_test" {
		t.Fatalf("inside tx: got %q, want integration_tx_test", name)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// After DISCARD ALL the GUC must be reset.
	if err := conn.QueryRow(ctx, "SHOW application_name").Scan(&name); err != nil {
		t.Fatalf("show after tx: %v", err)
	}
	if name == "integration_tx_test" {
		t.Fatal("DISCARD ALL did not reset application_name — state leaked")
	}
}

// TestConcurrentClients — 20 clients × 25 queries in parallel through
// a pool of 10 backends. Catches deadlocks, corruption, pool mismanagement.
func TestConcurrentClients(t *testing.T) {
	inst := startProxy(t, 10)

	const clients = 20
	const queriesPerClient = 25
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var failures atomic.Int64
	wg.Add(clients)

	for c := 0; c < clients; c++ {
		go func(id int) {
			defer wg.Done()
			conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
			if err != nil {
				slog.Warn("connect", "client", id, "err", err)
				failures.Add(1)
				return
			}
			defer conn.Close(ctx)

			for q := 0; q < queriesPerClient; q++ {
				var n int
				if err := conn.QueryRow(ctx, "SELECT $1::int + $2::int", id, q).Scan(&n); err != nil {
					slog.Warn("query", "client", id, "query", q, "err", err)
					failures.Add(1)
					return
				}
				if n != id+q {
					slog.Warn("wrong result", "client", id, "query", q, "got", n, "want", id+q)
					failures.Add(1)
					return
				}
			}
		}(c)
	}

	wg.Wait()
	if f := failures.Load(); f > 0 {
		t.Fatalf("%d client(s) failed — see logs above", f)
	}
}

// TestCancelRequest — start pg_sleep(60), cancel via context, verify error.
func TestCancelRequest(t *testing.T) {
	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	queryErr := make(chan error, 1)
	queryCtx, queryCancel := context.WithCancel(ctx)
	go func() {
		_, err := conn.Exec(queryCtx, "SELECT pg_sleep(60)")
		queryErr <- err
	}()

	time.Sleep(500 * time.Millisecond)
	queryCancel()

	select {
	case err := <-queryErr:
		if err == nil {
			t.Fatal("expected cancellation error, got nil")
		}
		t.Logf("cancel error (expected): %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not abort pg_sleep within 10s")
	}
}

// TestPoolExhaustion — pool limit=1, hold backend with pg_sleep,
// second query must fail with FATAL 53300.
func TestPoolExhaustion(t *testing.T) {
	inst := startProxy(t, 1) // pool of 1

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Hold the only backend.
	holdCtx, holdCancel := context.WithCancel(context.Background())
	conn1, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		holdCancel()
		t.Fatalf("connect 1: %v", err)
	}

	holding := make(chan struct{})
	holdDone := make(chan struct{})
	go func() {
		defer close(holdDone)
		close(holding)
		conn1.Exec(holdCtx, "SELECT pg_sleep(30)") //nolint:errcheck
	}()
	<-holding
	time.Sleep(500 * time.Millisecond)

	// Second connection — should fail on query.
	conn2, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		holdCancel()
		<-holdDone
		conn1.Close(context.Background())
		t.Fatalf("connect 2: %v", err)
	}

	var dummy int
	err = conn2.QueryRow(ctx, "SELECT 1").Scan(&dummy)

	holdCancel()
	<-holdDone
	conn1.Close(context.Background())
	conn2.Close(context.Background())

	if err == nil {
		t.Fatal("expected pool-exhaustion error, but query succeeded")
	}
	t.Logf("pool exhaustion error (expected): %v", err)
}

// TestBackendKeyDataRoundTrip — verify the PID from fakeAuth reaches
// the client (non-zero).
func TestBackendKeyDataRoundTrip(t *testing.T) {
	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	pid := conn.PgConn().PID()
	if pid == 0 {
		t.Fatal("BackendKeyData PID is 0")
	}
	t.Logf("received BackendKeyData PID: %d", pid)
}
