package main

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// RouteDecision is what a Router hands back for a routed startup:
// the pool that will carry queries plus per-pool policy the relay
// needs to know about. Currently just the pooling mode; future
// extensions (read/write split, priorities) plug in here without
// changing the interface.
type RouteDecision struct {
	Pool *pool.Pool
	// PoolName is the registry key of the chosen pool, which is not
	// necessarily the database name the client asked for — aliases let
	// several names share one pool. Carried so per-query metrics are
	// labelled by the pool that actually did the work, matching the
	// label used by every other pgman_pool_* series.
	PoolName string
	// PoolMode is one of: "transaction" (default), "session", "statement".
	// Empty string means transaction. The relay reads this to decide
	// when to release the backend after RFQ.
	PoolMode string
	// SessionMode is a convenience alias kept for the older RouteDecision
	// callers — mirrors PoolMode=="session". Deprecated: use PoolMode.
	SessionMode bool
}

// Router picks which pool a session's queries should go through, based on
// what the client named in its StartupMessage. This is the extension point
// DEV_PLAN Етап 9 reserves for future routing logic — read/write split,
// sharding hints — without handleConn changing: only a new implementation
// of this interface.
type Router interface {
	Route(startup *pgproto3.StartupMessage) (RouteDecision, error)
}

// DatabaseRouter is today's only implementation: one pool per configured
// database name, matched exactly against StartupMessage's "database" param.
// It reads through the live registry on every Route call, so pools added,
// resized, or removed by the admin UI take effect for the very next session
// without DatabaseRouter itself needing to change.
type DatabaseRouter struct {
	registry *PoolRegistry
}

func NewDatabaseRouter(registry *PoolRegistry) *DatabaseRouter {
	return &DatabaseRouter{registry: registry}
}

func (r *DatabaseRouter) Route(startup *pgproto3.StartupMessage) (RouteDecision, error) {
	db := startup.Parameters["database"]
	// The user is half the pool key, not just an auth detail: a client
	// with its own backend credentials must not be handed a connection
	// opened under somebody else's role.
	user := startup.Parameters["user"]
	key, p, cfg, ok := r.registry.Resolve(db, user)
	if !ok {
		return RouteDecision{}, fmt.Errorf("database %q is not configured on this proxy", db)
	}
	mode := strings.ToLower(cfg.PoolMode)
	if mode == "" {
		mode = "transaction"
	}
	return RouteDecision{
		Pool:        p,
		PoolName:    key,
		PoolMode:    mode,
		SessionMode: mode == "session",
	}, nil
}
