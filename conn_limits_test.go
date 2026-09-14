package main

import (
	"strings"
	"sync"
	"testing"
)

func TestConnLimiter_PerDBCap(t *testing.T) {
	l := NewConnLimiter(2, 0)

	if err := l.Reserve("alice", "app"); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("bob", "app"); err != nil {
		t.Fatal(err)
	}
	err := l.Reserve("carol", "app")
	if err == nil {
		t.Fatal("expected max_db_connections rejection at 3rd session")
	}
	if !strings.Contains(err.Error(), "max_db_connections") {
		t.Fatalf("error should mention max_db_connections: %v", err)
	}

	// Different database — same user — should still succeed under
	// per-db-only cap.
	if err := l.Reserve("alice", "other"); err != nil {
		t.Fatalf("different db should not be capped: %v", err)
	}

	// Release one → next Reserve for "app" succeeds.
	l.Release("alice", "app")
	if err := l.Reserve("carol", "app"); err != nil {
		t.Fatalf("Reserve after Release should succeed: %v", err)
	}
}

func TestConnLimiter_PerUserCap(t *testing.T) {
	l := NewConnLimiter(0, 2)

	if err := l.Reserve("alice", "db1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("alice", "db2"); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve("alice", "db3"); err == nil {
		t.Fatal("expected max_user_connections rejection at 3rd session")
	}

	// Different user should be unaffected.
	if err := l.Reserve("bob", "db1"); err != nil {
		t.Fatalf("different user: %v", err)
	}
}

func TestConnLimiter_BothCapsAtomic(t *testing.T) {
	// Both caps in play; per-user cap hits first.
	l := NewConnLimiter(5, 2)

	_ = l.Reserve("alice", "app")
	_ = l.Reserve("alice", "app")
	if err := l.Reserve("alice", "app"); err == nil {
		t.Fatal("third Reserve should have failed on per-user cap")
	}
	// State check: per-db count is still 2 (we didn't accidentally
	// increment before checking the user cap).
	pd, pu := l.Snapshot()
	if pd["app"] != 2 {
		t.Errorf("perDB[app] = %d, want 2 (atomicity leak)", pd["app"])
	}
	if pu["alice"] != 2 {
		t.Errorf("perUser[alice] = %d, want 2", pu["alice"])
	}
}

func TestConnLimiter_NilIsNoop(t *testing.T) {
	var l *ConnLimiter // uninitialized
	if err := l.Reserve("x", "y"); err != nil {
		t.Fatalf("nil limiter Reserve should be no-op: %v", err)
	}
	l.Release("x", "y") // must not panic
}

func TestConnLimiter_ConcurrentReserveRelease(t *testing.T) {
	l := NewConnLimiter(50, 50)
	const workers = 20
	const iters = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if err := l.Reserve("shared", "shared"); err == nil {
					l.Release("shared", "shared")
				}
			}
		}()
	}
	wg.Wait()

	pd, pu := l.Snapshot()
	if pd["shared"] != 0 {
		t.Errorf("perDB[shared] leaked: %d", pd["shared"])
	}
	if pu["shared"] != 0 {
		t.Errorf("perUser[shared] leaked: %d", pu["shared"])
	}
}
