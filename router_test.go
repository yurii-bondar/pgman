package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestDatabaseRouterRoutesToConfiguredPool(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"shop": dummyPoolConfig(2),
	}, NewEventLog(10))
	router := NewDatabaseRouter(registry)

	want, _ := registry.Get("shop")
	got, err := router.Route(&pgproto3.StartupMessage{Parameters: map[string]string{"database": "shop", "user": "rgs"}})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if got.Pool != want {
		t.Error("Route must return the exact pool registered under that database name")
	}
	if got.SessionMode {
		t.Error("default pool_mode should be transaction, not session")
	}
}

// TestDatabaseRouterReturnsSessionModeWhenConfigured — pool_mode: session
// in PoolConfig must flip the SessionMode bit in RouteDecision.
func TestDatabaseRouterReturnsSessionModeWhenConfigured(t *testing.T) {
	cfg := dummyPoolConfig(2)
	cfg.PoolMode = "session"
	registry := NewPoolRegistry(map[string]PoolConfig{"legacy": cfg}, NewEventLog(10))
	router := NewDatabaseRouter(registry)

	got, err := router.Route(&pgproto3.StartupMessage{Parameters: map[string]string{"database": "legacy"}})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	if !got.SessionMode {
		t.Fatal("pool_mode: session must set RouteDecision.SessionMode")
	}
}

func TestDatabaseRouterRejectsUnknownDatabase(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"shop": dummyPoolConfig(2)}, NewEventLog(10))
	router := NewDatabaseRouter(registry)

	_, err := router.Route(&pgproto3.StartupMessage{Parameters: map[string]string{"database": "nope", "user": "rgs"}})
	if err == nil {
		t.Fatal("expected error routing to an unconfigured database")
	}
}

// TestDatabaseRouterReflectsLiveRegistryChanges proves Route always reads
// through to the current registry state rather than caching anything —
// exactly what lets the admin UI's add/remove take effect for the very
// next session without DatabaseRouter itself changing (see its doc comment).
func TestDatabaseRouterReflectsLiveRegistryChanges(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	router := NewDatabaseRouter(registry)
	startup := &pgproto3.StartupMessage{Parameters: map[string]string{"database": "newdb", "user": "rgs"}}

	if _, err := router.Route(startup); err == nil {
		t.Fatal("expected error before the pool exists")
	}

	if err := registry.Add("newdb", dummyPoolConfig(1)); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := router.Route(startup); err != nil {
		t.Fatalf("expected routing to succeed once the pool is added, got: %v", err)
	}

	if _, err := registry.Remove("newdb"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := router.Route(startup); err == nil {
		t.Fatal("expected routing to fail again after the pool is removed")
	}
}
