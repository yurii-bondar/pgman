// Package main — per-user and per-database client-connection caps.
//
// Global max_client_conn already protects the proxy itself from
// runaway fanout. What it doesn't protect against is one noisy
// tenant (a runaway job, a mis-tuned worker pool) consuming every
// slot and starving everyone else. Two orthogonal caps close that
// gap:
//
//	max_db_connections   — per configured database
//	max_user_connections — per authenticated user, across databases
//
// Both are enforced at startup — after auth and routing succeed but
// BEFORE we advance into the relay loop. That order matters: it means
// we never block a legitimate client past the (fast) auth exchange
// only to reject them at the (slow) first query.
//
// Zero means "no cap" (matches PgBouncer's default for both keys).
package main

import (
	"fmt"
	"sync"
)

// ConnLimiter bounds the number of concurrent client sessions per
// user and per database. Safe for concurrent use.
type ConnLimiter struct {
	maxPerDB   int
	maxPerUser int

	mu      sync.Mutex
	perDB   map[string]int
	perUser map[string]int
}

// NewConnLimiter returns a limiter with the given caps. Either cap
// can be 0 to disable that axis independently.
func NewConnLimiter(maxPerDB, maxPerUser int) *ConnLimiter {
	return &ConnLimiter{
		maxPerDB:   maxPerDB,
		maxPerUser: maxPerUser,
		perDB:      make(map[string]int),
		perUser:    make(map[string]int),
	}
}

// Reserve tries to allocate one connection slot for (user, database).
// Returns nil on success; the caller MUST pair a successful Reserve
// with exactly one Release when the session ends. On failure returns
// an error naming which cap was hit.
//
// Atomicity: both counters are checked AND incremented under one lock,
// so two racing Reserves cannot both squeeze past the same cap.
func (c *ConnLimiter) Reserve(user, database string) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxPerDB > 0 {
		if c.perDB[database] >= c.maxPerDB {
			return fmt.Errorf("max_db_connections=%d reached for database %q", c.maxPerDB, database)
		}
	}
	if c.maxPerUser > 0 {
		if c.perUser[user] >= c.maxPerUser {
			return fmt.Errorf("max_user_connections=%d reached for user %q", c.maxPerUser, user)
		}
	}

	c.perDB[database]++
	c.perUser[user]++
	return nil
}

// Release returns one slot for (user, database) — must match a prior
// successful Reserve. Idempotent guard: never decrements below zero
// (defensive; a mispaired Release is a bug, but not one that should
// corrupt counters going forward).
func (c *ConnLimiter) Release(user, database string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if n := c.perDB[database]; n > 0 {
		if n == 1 {
			delete(c.perDB, database)
		} else {
			c.perDB[database] = n - 1
		}
	}
	if n := c.perUser[user]; n > 0 {
		if n == 1 {
			delete(c.perUser, user)
		} else {
			c.perUser[user] = n - 1
		}
	}
}

// Snapshot returns copies of both counter maps — used by admin SQL
// (SHOW USERS / SHOW DATABASES) to report live utilization.
func (c *ConnLimiter) Snapshot() (perDB, perUser map[string]int) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	dbCopy := make(map[string]int, len(c.perDB))
	for k, v := range c.perDB {
		dbCopy[k] = v
	}
	userCopy := make(map[string]int, len(c.perUser))
	for k, v := range c.perUser {
		userCopy[k] = v
	}
	return dbCopy, userCopy
}
