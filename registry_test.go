package main

import (
	"sync"
	"testing"
)

// dummyPoolConfig is never actually dialed — pool.New doesn't touch the
// network until Acquire is called, and these tests never call Acquire, so
// a bogus DSN is fine.
func dummyPoolConfig(limit int) PoolConfig {
	return PoolConfig{
		BackendDSN:  "postgres://user:pass@127.0.0.1:1/db?sslmode=disable",
		BackendAddr: "127.0.0.1:1",
		Limit:       limit,
	}
}

func TestPoolRegistryAddGetRemove(t *testing.T) {
	r := NewPoolRegistry(nil, NewEventLog(10))

	if _, ok := r.Get("db1"); ok {
		t.Fatal("expected no pool before Add")
	}

	if err := r.Add("db1", dummyPoolConfig(2)); err != nil {
		t.Fatalf("add: %v", err)
	}
	p, ok := r.Get("db1")
	if !ok || p == nil {
		t.Fatal("expected pool to exist after Add")
	}
	if p.Stats().Limit != 2 {
		t.Errorf("expected limit 2, got %d", p.Stats().Limit)
	}

	removed, err := r.Remove("db1")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(removed) != 1 || removed[0] != p {
		t.Errorf("Remove should return the exact pool that was registered, got %d pool(s)", len(removed))
	}
	if _, ok := r.Get("db1"); ok {
		t.Fatal("pool should be gone from the registry immediately after Remove")
	}
}

func TestPoolRegistryAddDuplicateFails(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(1)}, NewEventLog(10))
	if err := r.Add("db1", dummyPoolConfig(1)); err == nil {
		t.Fatal("expected error adding a pool name that already exists")
	}
}

func TestPoolRegistryAddValidatesConfig(t *testing.T) {
	cases := []struct {
		label string
		name  string
		cfg   PoolConfig
	}{
		{"empty name", "", PoolConfig{BackendDSN: "x", BackendAddr: "y", Limit: 1}},
		{"missing dsn", "poolname", PoolConfig{BackendAddr: "y", Limit: 1}},
		{"missing addr", "poolname", PoolConfig{BackendDSN: "x", Limit: 1}},
		{"zero limit", "poolname", PoolConfig{BackendDSN: "x", BackendAddr: "y", Limit: 0}},
		{"negative limit", "poolname", PoolConfig{BackendDSN: "x", BackendAddr: "y", Limit: -1}},
	}
	for _, c := range cases {
		r := NewPoolRegistry(nil, NewEventLog(10))
		if err := r.Add(c.name, c.cfg); err == nil {
			t.Errorf("%s: expected validation error, got nil", c.label)
		}
	}
}

func TestPoolRegistryRemoveUnknownFails(t *testing.T) {
	r := NewPoolRegistry(nil, NewEventLog(10))
	if _, err := r.Remove("nope"); err == nil {
		t.Fatal("expected error removing an unknown pool")
	}
}

func TestPoolRegistryResizeSwapsPoolAndPreservesOtherFields(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	original, _ := r.Get("db1")

	old, err := r.Resize("db1", 9)
	if err != nil {
		t.Fatalf("resize: %v", err)
	}
	if len(old) != 1 || old[0] != original {
		t.Errorf("Resize should return the pool that was replaced, got %d pool(s)", len(old))
	}

	current, ok := r.Get("db1")
	if !ok {
		t.Fatal("pool should still exist after resize")
	}
	if current == original {
		t.Error("Resize must swap in a new *pool.Pool, not mutate the old one (semaphore capacity is fixed at creation)")
	}
	if current.Stats().Limit != 9 {
		t.Errorf("expected new limit 9, got %d", current.Stats().Limit)
	}

	cfg := r.Configs()["db1"]
	if cfg.BackendDSN != dummyPoolConfig(2).BackendDSN {
		t.Error("Resize must preserve the original DSN/addr, only changing the limit")
	}
	if cfg.Limit != 9 {
		t.Errorf("Configs() should reflect the new limit, got %d", cfg.Limit)
	}
}

func TestPoolRegistryResizeRejectsInvalidLimit(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	if _, err := r.Resize("db1", 0); err == nil {
		t.Fatal("expected error resizing to a non-positive limit")
	}
	if _, err := r.Resize("unknown", 5); err == nil {
		t.Fatal("expected error resizing an unknown pool")
	}
}

func TestPoolRegistryNamesSorted(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{
		"zebra": dummyPoolConfig(1),
		"alpha": dummyPoolConfig(1),
		"mid":   dummyPoolConfig(1),
	}, NewEventLog(10))

	got := r.Names()
	want := []string{"alpha", "mid", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestPoolRegistryPoolsSnapshotIsIndependent(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(1)}, NewEventLog(10))
	snapshot := r.Pools()

	if err := r.Add("db2", dummyPoolConfig(1)); err != nil {
		t.Fatalf("add: %v", err)
	}

	if _, ok := snapshot["db2"]; ok {
		t.Error("a snapshot taken before Add must not see pools added afterward")
	}
	if len(r.Pools()) != 2 {
		t.Error("a fresh snapshot must see the newly added pool")
	}
}

// TestPoolRegistryConcurrentAccess exercises Add/Get/Remove/Resize/Pools
// from many goroutines at once — this is exactly what handleConn (readers,
// via Router) and the admin UI (writers) do concurrently in the real
// process. -race is what actually verifies this test proves anything.
func TestPoolRegistryConcurrentAccess(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"seed": dummyPoolConfig(1)}, NewEventLog(100))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "concurrent"
			_ = r.Add(name, dummyPoolConfig(1)) // most will fail with "already exists" — fine
			r.Get("seed")
			r.Pools()
			r.Names()
			r.Configs()
			if i%3 == 0 {
				r.Resize("seed", i+1)
			}
		}(i)
	}
	wg.Wait()

	if _, ok := r.Get("seed"); !ok {
		t.Error("seed pool should still exist after concurrent access")
	}
}
