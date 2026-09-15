package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func perUserPoolConfig() PoolConfig {
	return PoolConfig{
		BackendDSN:  "postgres://app_ro:pw@127.0.0.1:5432/shop?sslmode=disable",
		BackendAddr: "127.0.0.1:5432",
		Limit:       3,
		Aliases:     []string{"shop_ro"},
		BackendUsers: map[string]string{
			"alice": "postgres://alice:pw@127.0.0.1:5432/shop?sslmode=disable",
			"bob":   "postgres://bob:pw@127.0.0.1:5432/shop?sslmode=disable",
		},
	}
}

func routeAs(t *testing.T, router Router, db, user string) RouteDecision {
	t.Helper()
	d, err := router.Route(&pgproto3.StartupMessage{
		ProtocolVersion: 196608,
		Parameters:      map[string]string{"database": db, "user": user},
	})
	if err != nil {
		t.Fatalf("route %s/%s: %v", db, user, err)
	}
	return d
}

// TestUsersWithOwnCredentialsGetSeparatePools is the point of the whole
// change. Two clients that reach Postgres as different roles must not
// share a connection: if alice's statements can run on bob's backend,
// GRANT and REVOKE stop distinguishing them, row-level security sees one
// identity, and pg_stat_activity attributes both to whoever dialed.
func TestUsersWithOwnCredentialsGetSeparatePools(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))
	router := NewDatabaseRouter(r)

	alice := routeAs(t, router, "shop", "alice")
	bob := routeAs(t, router, "shop", "bob")

	if alice.Pool == bob.Pool {
		t.Fatal("alice and bob have different backend credentials but were routed to the same pool")
	}
	if alice.PoolName != "shop/alice" || bob.PoolName != "shop/bob" {
		t.Errorf("pool keys = %q, %q; want shop/alice, shop/bob", alice.PoolName, bob.PoolName)
	}

	// The pool a user is routed to must be the one dialing as that user.
	cfg, ok := r.PoolConfig("shop/alice")
	if !ok {
		t.Fatal("no config behind shop/alice")
	}
	if cfg.BackendDSN != perUserPoolConfig().BackendUsers["alice"] {
		t.Errorf("shop/alice dials with %q, want alice's own DSN", cfg.BackendDSN)
	}
}

// TestUsersWithoutOwnCredentialsShareOnePool keeps the connection count
// from multiplying for the common case. Clients that all reach Postgres
// as the BackendDSN role are indistinguishable there, so giving each one
// its own pool would buy no isolation and cost real connections.
func TestUsersWithoutOwnCredentialsShareOnePool(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))
	router := NewDatabaseRouter(r)

	first := routeAs(t, router, "shop", "carol")
	second := routeAs(t, router, "shop", "dave")

	if first.Pool != second.Pool {
		t.Error("two users sharing the BackendDSN identity were given separate pools")
	}
	if first.PoolName != "shop" {
		t.Errorf("pool key = %q, want the bare pool name for the default identity", first.PoolName)
	}
}

// TestPoolKeysUnchangedWithoutBackendUsers pins backwards compatibility:
// a config that never mentions backend_users must produce exactly the
// keys, and therefore the metric labels and admin SQL rows, it produced
// before per-user pools existed.
func TestPoolKeysUnchangedWithoutBackendUsers(t *testing.T) {
	cfg := perUserPoolConfig()
	cfg.BackendUsers = nil
	r := NewPoolRegistry(map[string]PoolConfig{"shop": cfg}, NewEventLog(10))

	names := r.Names()
	if len(names) != 1 || names[0] != "shop" {
		t.Fatalf("registry keys = %v, want exactly [shop]", names)
	}

	router := NewDatabaseRouter(r)
	if d := routeAs(t, router, "shop", "alice"); d.PoolName != "shop" {
		t.Errorf("pool key = %q, want shop", d.PoolName)
	}
}

// TestAliasesResolveBeforeTheUserIsApplied covers the interaction the
// two features have: an alias names a pool, and the user then selects
// which identity within it.
func TestAliasesResolveBeforeTheUserIsApplied(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))
	router := NewDatabaseRouter(r)

	viaAlias := routeAs(t, router, "shop_ro", "alice")
	direct := routeAs(t, router, "shop", "alice")

	if viaAlias.Pool != direct.Pool {
		t.Error("an alias must reach the same per-user pool as the pool's own name")
	}
	if viaAlias.PoolName != "shop/alice" {
		t.Errorf("pool key via alias = %q, want shop/alice", viaAlias.PoolName)
	}
}

func TestRegistryCreatesOnePoolPerBackendIdentity(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))

	got := r.Names()
	want := []string{"shop", "shop/alice", "shop/bob"}
	if len(got) != len(want) {
		t.Fatalf("registry keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registry keys = %v, want %v", got, want)
		}
	}
}

// TestRemoveTakesEveryIdentity — leaving one user's pool behind after
// the pool was removed would route that user into a database the
// operator believes is gone, and nothing in the pool list would show it.
func TestRemoveTakesEveryIdentity(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))

	removed, err := r.Remove("shop")
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if len(removed) != 3 {
		t.Errorf("Remove returned %d pools, want all 3 identities", len(removed))
	}
	if names := r.Names(); len(names) != 0 {
		t.Errorf("registry still holds %v after removing the pool", names)
	}
	// The alias must go with it, or a client naming it gets a nil pool.
	router := NewDatabaseRouter(r)
	if _, err := router.Route(&pgproto3.StartupMessage{
		Parameters: map[string]string{"database": "shop_ro", "user": "alice"},
	}); err == nil {
		t.Error("the alias of a removed pool still routes")
	}
}

func TestResizeRebuildsEveryIdentity(t *testing.T) {
	r := NewPoolRegistry(map[string]PoolConfig{"shop": perUserPoolConfig()}, NewEventLog(10))

	old, err := r.Resize("shop", 9)
	if err != nil {
		t.Fatalf("resize: %v", err)
	}
	if len(old) != 3 {
		t.Errorf("Resize replaced %d pools, want all 3 identities", len(old))
	}
	for _, key := range []string{"shop", "shop/alice", "shop/bob"} {
		p, ok := r.Get(key)
		if !ok {
			t.Fatalf("%s is missing after resize", key)
		}
		if got := p.Stats().Limit; got != 9 {
			t.Errorf("%s limit = %d, want 9", key, got)
		}
	}
}

func TestPoolKey(t *testing.T) {
	if got := poolKey("shop", ""); got != "shop" {
		t.Errorf("default identity key = %q, want the bare name", got)
	}
	if got := poolKey("shop", "alice"); got != "shop/alice" {
		t.Errorf("per-user key = %q, want shop/alice", got)
	}
}
