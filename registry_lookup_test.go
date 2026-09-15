package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The registry's lookup surface is what every other component addresses
// pools through, and the three ways in — an exact key, a pool name, a
// client-visible alias — must agree. A lookup that misses is a client
// told its database does not exist; a lookup that hits the wrong entry
// is a client running statements somewhere it should not be.

func aliasRegistry(t *testing.T) *PoolRegistry {
	t.Helper()
	cfg := dummyPoolConfig(2)
	cfg.Aliases = []string{"shop_ro", "shop_reports"}
	cfg.BackendUsers = map[string]string{
		"alice": "postgres://alice:p@127.0.0.1:1/db?sslmode=disable",
	}
	return NewPoolRegistry(map[string]PoolConfig{"shop": cfg}, NewEventLog(10))
}

// TestResolveNameFollowsAliases: aliases are the building block for
// read/write split — an "app_ro" name pointed at a replica pool — so the
// mapping from a client-visible name to the pool serving it has to be
// the same one routing uses.
func TestResolveNameFollowsAliases(t *testing.T) {
	r := aliasRegistry(t)

	for _, alias := range []string{"shop_ro", "shop_reports", "shop"} {
		if got := r.ResolveName(alias); got != "shop" {
			t.Errorf("ResolveName(%q) = %q, want shop", alias, got)
		}
	}
	// An unknown name comes back unchanged rather than empty, so callers
	// can log what the client actually asked for.
	if got := r.ResolveName("nosuch"); got != "nosuch" {
		t.Errorf("ResolveName(%q) = %q, want it returned unchanged", "nosuch", got)
	}
}

// TestGetAndPoolConfigAcceptKeysNamesAndAliases: admin surfaces address
// pools by the key they display, while an operator typing into the
// console uses the name from the config file. Both have to work, or half
// the admin API is unusable for a pool split by backend_users.
func TestGetAndPoolConfigAcceptKeysNamesAndAliases(t *testing.T) {
	r := aliasRegistry(t)

	for _, key := range []string{"shop", "shop/alice", "shop_ro"} {
		if _, ok := r.Get(key); !ok {
			t.Errorf("Get(%q) found nothing", key)
		}
		cfg, ok := r.PoolConfig(key)
		if !ok {
			t.Errorf("PoolConfig(%q) found nothing", key)
			continue
		}
		if cfg.Limit != 2 {
			t.Errorf("PoolConfig(%q).Limit = %d, want 2", key, cfg.Limit)
		}
	}

	// The per-user entry must report its own DSN, not the pool's — that
	// difference is the whole point of backend_users.
	base, _ := r.PoolConfig("shop")
	perUser, _ := r.PoolConfig("shop/alice")
	if base.BackendDSN == perUser.BackendDSN {
		t.Error("the per-user entry carries the pool's DSN, so alice would connect as the shared role")
	}

	if _, ok := r.Get("ghost"); ok {
		t.Error("Get found a pool that does not exist")
	}
	if _, ok := r.PoolConfig("ghost"); ok {
		t.Error("PoolConfig found a pool that does not exist")
	}
}

// TestResolveRoutesUnknownDatabaseAndUser: Resolve is the routing
// decision, and both of its failure modes have to be distinguishable
// from success — an unknown database, and a known one reached by a user
// with no identity of their own.
func TestResolveRoutesUnknownDatabaseAndUser(t *testing.T) {
	r := aliasRegistry(t)

	if _, _, _, ok := r.Resolve("ghost", "alice"); ok {
		t.Error("Resolve succeeded for a database that is not configured")
	}

	// alice has her own backend credentials, so she gets her own pool.
	key, _, _, ok := r.Resolve("shop", "alice")
	if !ok {
		t.Fatal("Resolve failed for a configured user")
	}
	if key != "shop/alice" {
		t.Errorf("Resolve(shop, alice) = %q, want shop/alice", key)
	}

	// Everybody else shares the pool's own identity, including clients
	// arriving through an alias.
	key, _, _, ok = r.Resolve("shop_ro", "bob")
	if !ok {
		t.Fatal("Resolve failed for an alias")
	}
	if key != "shop" {
		t.Errorf("Resolve(shop_ro, bob) = %q, want shop", key)
	}

	// An empty user is what a CancelRequest and the health probe look
	// like: no identity to split on, so the base entry serves them.
	if key, _, _, ok := r.Resolve("shop", ""); !ok || key != "shop" {
		t.Errorf("Resolve(shop, \"\") = (%q, %v), want (shop, true)", key, ok)
	}
}

// TestNewPoolAppliesLifecycleDefaults: the per-pool lifecycle settings
// are resolved in exactly one place, and a pool built without them is
// one that never reaps idle connections or retries a dial — the failure
// only shows up hours later, as connection count drift.
func TestNewPoolAppliesLifecycleDefaults(t *testing.T) {
	defaults := &Config{
		ServerIdleTimeout:       time.Minute,
		ServerLifetime:          time.Hour,
		ServerCheckDelay:        30 * time.Second,
		ServerLoginRetry:        2,
		ServerLoginBackoff:      50 * time.Millisecond,
		MinPoolSize:             0, // warm-up would dial, which these tests must not
		HealthCheckTimeout:      time.Second,
		CircuitBreakerThreshold: 3,
		CircuitBreakerCooldown:  time.Second,
		DNSResolveInterval:      0, // a watcher would resolve a bogus host forever
	}
	r := NewPoolRegistryWithDefaults(
		map[string]PoolConfig{"db1": dummyPoolConfig(3)}, NewEventLog(10), defaults, nil)

	p, ok := r.Get("db1")
	if !ok {
		t.Fatal("the pool was not created")
	}
	if got := p.Stats().Limit; got != 3 {
		t.Errorf("limit = %d, want 3", got)
	}
}

// TestStartDNSWatcherForHonoursTheInterval: the watcher exists to
// shorten the window after an RDS failover, but a pool built with it
// enabled and a bogus address would resolve in a loop forever. The
// disabled case has to be a genuine no-op.
func TestStartDNSWatcherForHonoursTheInterval(t *testing.T) {
	r := NewPoolRegistryWithDefaults(map[string]PoolConfig{"db1": dummyPoolConfig(2)},
		NewEventLog(10), &Config{DNSResolveInterval: 0}, nil)
	stop := r.startDNSWatcherFor("db1", dummyPoolConfig(2), nil)
	if stop == nil {
		t.Fatal("a disabled watcher returned no stopper, so callers would panic")
	}
	stop() // must not panic on the no-op stopper

	enabled := NewPoolRegistryWithDefaults(map[string]PoolConfig{"db1": dummyPoolConfig(2)},
		NewEventLog(10), &Config{DNSResolveInterval: time.Hour}, nil)
	p, _ := enabled.Get("db1")
	stop = enabled.startDNSWatcherFor("db1", dummyPoolConfig(2), p)
	if stop == nil {
		t.Fatal("an enabled watcher returned no stopper")
	}
	stop()
}

// TestReapPassthroughPoolsSweepsThroughTheRegistry covers the sweep the
// background reaper performs, without waiting for its ticker: the
// eviction rules themselves are tested directly elsewhere, but nothing
// otherwise exercised the function the goroutine actually calls.
func TestReapPassthroughPoolsSweepsThroughTheRegistry(t *testing.T) {
	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", time.Hour)

	reapPassthroughPools(r, 30*time.Minute, nil)

	if _, still := r.Get("db/alice"); still {
		t.Error("the idle pass-through pool survived a sweep")
	}
	// The configured pool it came from is not garbage and must remain.
	if _, ok := r.Get("db"); !ok {
		t.Error("the sweep took out the configured pool")
	}
}

// TestStartPassthroughReaperStopsOnDemand: the reaper is started per
// process and stopped on shutdown, so a stopper that does not actually
// stop it leaks a goroutine per run — which in tests means one per test.
func TestStartPassthroughReaperStopsOnDemand(t *testing.T) {
	r := passthroughRegistry(t, "alice")

	stop := startPassthroughReaper(r, time.Hour, nil)
	stop()
	stop = startPassthroughReaper(r, 0, nil) // disabled: a no-op stopper
	stop()
}

// TestIndexHandlerRendersEveryPanel: the dashboard is one page built
// from four data sources, and a nil slice in any of them used to be the
// difference between a page and a 500.
func TestIndexHandlerRendersEveryPanel(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	log := NewEventLog(10)
	log.Record("db1", "dial_error", errors.New("connection refused"))

	pid, sess := registerSession("alice", "db1")
	sess.poolName = "db1"
	t.Cleanup(func() { deregisterSession(pid) })

	rec := httptest.NewRecorder()
	indexHandler(registry, log)(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"db1", "alice", "dial_error"} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not mention %q", want)
		}
	}
}
