// Package main — reclaiming idle SCRAM pass-through pools.
//
// A pass-through pool cannot be declared in the config file: it dials
// as a specific client role using the ClientKey recovered from that
// client's own handshake, so it can only be built the first time that
// role connects. That made them the one kind of pool nothing ever
// removed, and the cost is not just memory: each one holds up to Limit
// Postgres backends, a reaper goroutine of its own, and a set of
// Prometheus series.
//
// "Bounded by the number of roles" was the original argument, and it is
// true in the sense that a client cannot inflate the set by asking. It
// stops being reassuring the moment roles are per-tenant or per-person:
// a process that has been up for a month holds a pool for every role
// that connected during that month, including the ones that have since
// been dropped from the cluster.
//
// What is deliberately NOT reclaimed here is the ClientKey in
// clientKeyStore. Forgetting it would look like the same cleanup, but
// backendIdentityFor consults the store to decide whether a user gets
// its own identity on the backend at all — and a session that has
// authenticated but not yet routed would then be silently routed to the
// shared BackendDSN role instead. Trading a few hundred bytes for a
// race that runs statements as the wrong role is not a trade. The key
// is re-derived on every login anyway, so it is never stale, only
// resident.
package main

import (
	"log/slog"
	"time"
)

// passthroughReapInterval decides how often to sweep, given how long a
// pool is allowed to sit idle. A quarter of the idle window means a
// pool lives at most 1.25 × idleFor, which is close enough for
// something whose only job is to stop unbounded growth, and the clamps
// keep a pathological configuration from either spinning or never
// running: a one-minute idle window does not deserve a 15-second
// ticker, and a one-week window still wants checking daily.
func passthroughReapInterval(idleFor time.Duration) time.Duration {
	interval := idleFor / 4
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	if interval > 24*time.Hour {
		interval = 24 * time.Hour
	}
	return interval
}

// startPassthroughReaper sweeps idle pass-through pools until the
// returned function is called. A non-positive idleFor starts nothing
// and returns a no-op, so "keep every pool forever" stays available as
// an explicit choice.
func startPassthroughReaper(registry *PoolRegistry, idleFor time.Duration, metrics *proxyMetrics) func() {
	if idleFor <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(passthroughReapInterval(idleFor))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				reapPassthroughPools(registry, idleFor, metrics)
			}
		}
	}()
	return func() { close(stop) }
}

// reapPassthroughPools is one sweep, factored out so a test can run it
// directly instead of waiting for a ticker.
func reapPassthroughPools(registry *PoolRegistry, idleFor time.Duration, metrics *proxyMetrics) {
	keys, pools := registry.EvictIdlePassthrough(idleFor, activeSessionPoolKeys())
	metrics.observePassthroughEvictions(len(keys))
	for i, key := range keys {
		// Drained in the background like every other displaced pool.
		// The eviction conditions mean there is nothing in flight to
		// wait for, but Close still has connections to shut down and
		// the sweep should not be the thing that blocks on them.
		drainPoolsInBackground(key, pools[i:i+1])
		slog.Info("pool: closed an idle SCRAM pass-through pool",
			"pool", key, "idle_for", idleFor)
	}
}
