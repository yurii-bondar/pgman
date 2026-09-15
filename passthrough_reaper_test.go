package main

import (
	"testing"
	"time"

	"github.com/xdg-go/scram"
)

// passthroughRegistry builds a registry with one pass-through pool and
// one live pass-through entry for user, the way Resolve creates it on
// that user's first connection.
func passthroughRegistry(t *testing.T, user string) *PoolRegistry {
	t.Helper()

	cfg := dummyPoolConfig(2)
	cfg.ScramPassthrough = true
	r := NewPoolRegistry(map[string]PoolConfig{"db": cfg}, NewEventLog(10))

	keys := newClientKeyStore()
	// The material is never used — nothing here dials — but its
	// presence is what makes the user eligible for its own pool.
	keys.remember(user, []byte("client-key"), scram.StoredCredentials{})
	r.SetClientKeyStore(keys)

	key, _, _, ok := r.Resolve("db", user)
	if !ok {
		t.Fatal("routing a pass-through user did not resolve to a pool")
	}
	if key != "db/"+user {
		t.Fatalf("resolved to %q, want the per-user key %q", key, "db/"+user)
	}
	return r
}

// idle backdates an entry's last-routed stamp so a test does not have
// to wait out a real idle window.
func idle(t *testing.T, r *PoolRegistry, key string, d time.Duration) {
	t.Helper()
	r.mu.RLock()
	e, ok := r.entries[key]
	r.mu.RUnlock()
	if !ok {
		t.Fatalf("no entry %q to backdate", key)
	}
	e.lastRouted.Store(time.Now().Add(-d).UnixNano())
}

// TestEvictIdlePassthroughReclaimsUnusedPools is the leak this closes:
// pass-through pools are created per role on demand and nothing ever
// removed them, so a long-lived process ended up holding a pool — with
// its connections, its reaper goroutine and its metric series — for
// every role that had ever connected.
func TestEvictIdlePassthroughReclaimsUnusedPools(t *testing.T) {
	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", time.Hour)

	keys, pools := r.EvictIdlePassthrough(30*time.Minute, nil)

	if len(keys) != 1 || keys[0] != "db/alice" {
		t.Fatalf("evicted %v, want [db/alice]", keys)
	}
	if len(pools) != 1 {
		t.Fatalf("got %d pools to drain, want 1", len(pools))
	}
	if _, still := r.Get("db/alice"); still {
		t.Error("the evicted entry is still routable")
	}
	// The configured pool it was derived from must survive: an idle
	// declared pool is not garbage, it is a pool waiting for traffic.
	if _, ok := r.Get("db"); !ok {
		t.Error("the configured pool was evicted along with the pass-through one")
	}
}

func TestEvictIdlePassthroughSparesRecentlyUsedPools(t *testing.T) {
	r := passthroughRegistry(t, "alice")

	if keys, _ := r.EvictIdlePassthrough(30*time.Minute, nil); len(keys) != 0 {
		t.Errorf("evicted %v, but the pool was just routed to", keys)
	}
}

// TestEvictIdlePassthroughSparesPoolsWithLiveSessions guards the
// dangerous case. A session between transactions holds no backend
// connection but still holds this pool pointer, so closing the pool
// underneath it turns its next Acquire into a fatal error — an eviction
// that would look, to that client, exactly like the proxy shutting
// down.
func TestEvictIdlePassthroughSparesPoolsWithLiveSessions(t *testing.T) {
	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", time.Hour)

	active := map[string]bool{"db/alice": true}
	if keys, _ := r.EvictIdlePassthrough(30*time.Minute, active); len(keys) != 0 {
		t.Errorf("evicted %v while a session was still routed there", keys)
	}
}

// TestEvictIdlePassthroughDisabled keeps "keep every pool for the life
// of the process" available as an explicit choice.
func TestEvictIdlePassthroughDisabled(t *testing.T) {
	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", 24*time.Hour)

	if keys, _ := r.EvictIdlePassthrough(-1, nil); len(keys) != 0 {
		t.Errorf("evicted %v with eviction disabled", keys)
	}
}

// TestResolveRecreatesEvictedPassthroughPool: eviction must cost the
// user one dial, not their access. The credential is still in the key
// store, so the next connection rebuilds the pool.
func TestResolveRecreatesEvictedPassthroughPool(t *testing.T) {
	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", time.Hour)
	r.EvictIdlePassthrough(30*time.Minute, nil)

	key, _, _, ok := r.Resolve("db", "alice")
	if !ok || key != "db/alice" {
		t.Fatalf("Resolve after eviction gave (%q, %v), want (db/alice, true)", key, ok)
	}
}

func TestPassthroughReapIntervalStaysSane(t *testing.T) {
	cases := []struct {
		idleFor time.Duration
		want    time.Duration
	}{
		{30 * time.Minute, 7*time.Minute + 30*time.Second},
		{time.Minute, 30 * time.Second},       // clamped up
		{30 * 24 * time.Hour, 24 * time.Hour}, // clamped down
	}
	for _, tc := range cases {
		if got := passthroughReapInterval(tc.idleFor); got != tc.want {
			t.Errorf("passthroughReapInterval(%v) = %v, want %v", tc.idleFor, got, tc.want)
		}
	}
}

func TestScramPassthroughIdleTimeoutDefault(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()
	if cfg.ScramPassthroughIdleTimeout != defaultScramPassthroughIdleTimeout {
		t.Errorf("default = %v, want %v",
			cfg.ScramPassthroughIdleTimeout, defaultScramPassthroughIdleTimeout)
	}
}
