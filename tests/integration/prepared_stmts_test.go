//go:build integration

package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preparedStmtDSN — NO simple_protocol override. Uses pgx's default
// extended query mode with automatic prepared-statement caching. This
// is the harness that would previously (before the proxy learned to
// replay Parse on stmt-unaware backends) fail with:
//
//	"prepared statement \"stmtcache_...\" does not exist"
func preparedStmtDSN(proxyAddr string) string {
	return fmt.Sprintf(
		"postgres://pgman_test:anything@%s/pgman_test?sslmode=disable",
		proxyAddr,
	)
}

// TestPreparedStmtsSurviveBackendSwap — the flagship test. A single
// pgx client executes the same query many times; each execution may
// land on a different backend under transaction pooling, so the client's
// cached prepared statement must be lazy-replayed by the proxy.
func TestPreparedStmtsSurviveBackendSwap(t *testing.T) {
	inst := startProxy(t, 3) // small pool → lots of backend rotation
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, preparedStmtDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	// Warm the pool by fanning out 3 concurrent queries so idle stack
	// has multiple distinct backends.
	var warmWg sync.WaitGroup
	for i := 0; i < 3; i++ {
		warmWg.Add(1)
		go func() {
			defer warmWg.Done()
			c, err := pgx.Connect(ctx, preparedStmtDSN(inst.ProxyAddr))
			if err != nil {
				return
			}
			defer c.Close(ctx)
			var n int
			c.QueryRow(ctx, "SELECT 1").Scan(&n)
		}()
	}
	warmWg.Wait()

	// Now hammer the parameterized query many times through one client.
	// pgx caches "SELECT $1::int" as stmtcache_0001; every second-plus
	// call re-Binds it. Under transaction pooling those Binds land on
	// different backends; without lazy-Parse they'd error.
	const iterations = 100
	for i := 0; i < iterations; i++ {
		var got int
		if err := conn.QueryRow(ctx, "SELECT $1::int", i).Scan(&got); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if got != i {
			t.Fatalf("iteration %d: got %d, want %d", i, got, i)
		}
	}
}

// TestPreparedStmtsConcurrentClients — 10 clients each with their own
// prepared-statement cache, all doing parameterized queries into a
// small shared pool. Ensures per-session psCache doesn't leak across
// clients (would show up as stmt-name collisions).
func TestPreparedStmtsConcurrentClients(t *testing.T) {
	inst := startProxy(t, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const clients = 10
	const iterationsPerClient = 50

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			conn, err := pgx.Connect(ctx, preparedStmtDSN(inst.ProxyAddr))
			if err != nil {
				errs <- fmt.Errorf("client %d connect: %w", clientID, err)
				return
			}
			defer conn.Close(ctx)
			for i := 0; i < iterationsPerClient; i++ {
				var got int
				if err := conn.QueryRow(ctx, "SELECT $1::int + $2::int", clientID, i).Scan(&got); err != nil {
					errs <- fmt.Errorf("client %d iter %d: %w", clientID, i, err)
					return
				}
				if got != clientID+i {
					errs <- fmt.Errorf("client %d iter %d: got %d want %d", clientID, i, got, clientID+i)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestPreparedStmtsWithinTransaction — an explicit BEGIN/COMMIT tx
// with prepared statements. Backend must not be swapped mid-tx (that
// would be a transaction-pool contract violation anyway), and the
// stmt cache must be valid throughout.
func TestPreparedStmtsWithinTransaction(t *testing.T) {
	inst := startProxy(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, preparedStmtDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	for i := 0; i < 20; i++ {
		var got int
		if err := tx.QueryRow(ctx, "SELECT $1::int * 2", i).Scan(&got); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if got != i*2 {
			t.Fatalf("iter %d: got %d want %d", i, got, i*2)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
