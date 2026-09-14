// Package main — per-user session-open rate limiting.
//
// Applied at startup, right before the auth handshake, to defend
// against connection storms from a single user (misbehaving service,
// runaway retry loop, credential leak abuse). Enforced as a classic
// token bucket per username: burst controls the initial capacity,
// rate controls sustained fills.
//
// Design note: this is NOT per-query QPS throttling. Doing that
// inside relay is fraught — refusing a query mid-batch after
// Parse/Bind have already gone to the backend leaves the extended-
// protocol state desynchronized. Session-open limiting sidesteps
// every one of those complications while still solving the actual
// operational pain (one user monopolising resources).
//
// PgBouncer doesn't ship this; we do because the parity dashboard
// pattern (one app tenant per DB, cross-tenant fairness required)
// makes it worth the tiny amount of code.
package main

import (
	"sync"
	"time"
)

// RateLimiter is a per-key token bucket. Zero rate disables the whole
// limiter (all Allow calls return true). Safe for concurrent use.
type RateLimiter struct {
	// tokensPerSec is the sustained refill rate.
	tokensPerSec float64
	// burst is the bucket capacity — how many events can happen back-
	// to-back before the rate cap kicks in.
	burst float64

	mu      sync.Mutex
	buckets map[string]*rlBucket
}

type rlBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter returns a limiter that permits at most `rate` events
// per second per key, with a burst of `burst`. Both must be > 0 for
// the limiter to be active; nil-limiter Allow is a no-op that returns
// true, letting callers short-circuit without extra branching.
func NewRateLimiter(ratePerSec, burst int) *RateLimiter {
	if ratePerSec <= 0 || burst <= 0 {
		return nil
	}
	return &RateLimiter{
		tokensPerSec: float64(ratePerSec),
		burst:        float64(burst),
		buckets:      make(map[string]*rlBucket),
	}
}

// Allow consumes one token for key. Returns true if the caller may
// proceed, false if the bucket is empty (caller should reject).
// nil-safe: a nil *RateLimiter always allows.
func (r *RateLimiter) Allow(key string) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	b := r.buckets[key]
	if b == nil {
		// Fresh bucket starts full so a legitimate first-ever
		// connection isn't penalized just for being cold.
		b = &rlBucket{tokens: r.burst, lastRefill: time.Now()}
		r.buckets[key] = b
	}
	// Refill based on wallclock delta. Cap at burst so idle keys
	// don't accumulate infinite credit.
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.tokensPerSec
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.lastRefill = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
