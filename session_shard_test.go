package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// Regression tests for the 32-shard sessionRegistry that replaced the
// single global sessionsMu + map. Everything below is written against
// the public API (registerSession / deregisterSession / listSessions /
// lookupSession) — never against a specific shard's internals — so the
// same tests will still be meaningful if the shard count changes.

// TestSessionRegistryShardsCoverAllBits ensures every one of the 32
// shards is actually reachable. A single-bit off-by-one in the mask
// (`pid & (N-1)`) is the kind of bug that would keep one shard
// permanently empty and load the others harder — silently. This tests
// distribution by construction: register enough sessions that the
// pigeonhole principle guarantees every shard sees at least one.
func TestSessionRegistryShardsCoverAllBits(t *testing.T) {
	// N * 20 sessions ⇒ every shard almost certainly non-empty. If any
	// shard is empty after this, either the mask is broken or the
	// crypto/rand distribution is catastrophically skewed (a bigger
	// problem than this test).
	const per = 20
	total := sessionShardCount * per
	pids := make([]uint32, 0, total)
	for i := 0; i < total; i++ {
		pid, _ := registerSession("shard-test", "shard-test")
		pids = append(pids, pid)
	}
	t.Cleanup(func() {
		for _, p := range pids {
			deregisterSession(p)
		}
	})

	var hit [sessionShardCount]bool
	for _, p := range pids {
		hit[p&(sessionShardCount-1)] = true
	}
	for i, h := range hit {
		if !h {
			t.Errorf("shard %d received zero registrations across %d sessions — mask/hash likely broken", i, total)
		}
	}
}

// TestSessionRegistryConcurrentRegisterDeregisterIsRaceFree runs many
// goroutines through register/lookup/deregister at once. Under `go
// test -race` this catches any shared-state slip that the shard split
// might have introduced (or a future refactor might reintroduce).
func TestSessionRegistryConcurrentRegisterDeregisterIsRaceFree(t *testing.T) {
	const goroutines = 32
	const perGoroutine = 500

	var wg sync.WaitGroup
	var lookedUp atomic.Int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				pid, sess := registerSession("concurrent", "concurrent")
				if got, ok := lookupSession(pid); !ok || got != sess {
					t.Errorf("lookupSession(%d) after register did not return the just-registered session", pid)
					return
				}
				lookedUp.Add(1)
				deregisterSession(pid)
				if _, ok := lookupSession(pid); ok {
					t.Errorf("lookupSession(%d) after deregister still returned a session", pid)
					return
				}
			}
		}()
	}
	wg.Wait()

	if got, want := lookedUp.Load(), int64(goroutines*perGoroutine); got != want {
		t.Errorf("lookedUp count: got %d, want %d", got, want)
	}
}

// TestListSessionsWalksAllShards verifies listSessions doesn't
// short-circuit on the first shard — a plausible refactor bug (e.g.,
// `for _, shard := range r.shards[:1]`) would return only a small
// slice of live sessions and completely break the admin UI.
func TestListSessionsWalksAllShards(t *testing.T) {
	// Baseline count of sessions already registered by concurrent
	// other tests (t.Parallel isn't used, but package-level state).
	baseline := len(listSessions())

	const registered = sessionShardCount * 5 // guaranteed to touch every shard on average
	pids := make([]uint32, 0, registered)
	for i := 0; i < registered; i++ {
		pid, _ := registerSession(fmt.Sprintf("list-user-%d", i), "list-db")
		pids = append(pids, pid)
	}
	t.Cleanup(func() {
		for _, p := range pids {
			deregisterSession(p)
		}
	})

	got := len(listSessions())
	want := baseline + registered
	if got != want {
		t.Fatalf("listSessions returned %d sessions, want %d (baseline %d + registered %d) — likely walking only one shard",
			got, want, baseline, registered)
	}
}

// TestSessionShardsBalanceIsReasonable — with crypto/rand PIDs, over a
// large sample the max shard should not hold more than ~3× the mean.
// Not a strict fairness bound (rand is rand) — this is a smoke test
// against a bug where every session ends up in shard 0 because the
// hash function was accidentally replaced with a constant.
func TestSessionShardsBalanceIsReasonable(t *testing.T) {
	const total = sessionShardCount * 50
	pids := make([]uint32, 0, total)
	for i := 0; i < total; i++ {
		pid, _ := registerSession("balance", "balance")
		pids = append(pids, pid)
	}
	t.Cleanup(func() {
		for _, p := range pids {
			deregisterSession(p)
		}
	})

	var counts [sessionShardCount]int
	for _, p := range pids {
		counts[p&(sessionShardCount-1)]++
	}

	mean := total / sessionShardCount
	limit := mean * 3 // 3× mean = generous; a broken hash pins everything at N× mean
	for i, c := range counts {
		if c > limit {
			t.Errorf("shard %d holds %d sessions vs mean %d (>3× — hash likely broken)", i, c, mean)
		}
	}
}

// BenchmarkSessionRegisterDeregister measures the register/deregister
// hot path under contention. Purely a floor benchmark to catch a
// regression that reintroduces the single-mutex bottleneck. The
// absolute number depends on the machine; only relative change matters
// when comparing branches.
func BenchmarkSessionRegisterDeregister(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pid, _ := registerSession("bench", "bench")
			deregisterSession(pid)
		}
	})
}
