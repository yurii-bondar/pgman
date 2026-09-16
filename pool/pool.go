// Package pool implements a bounded, LIFO pool of backend connections
// with production-grade lifecycle controls: idle timeout, max lifetime,
// health-check throttling, minimum warm capacity, dial retry, and
// observable wait-time hooks for percentile metrics.
package pool

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPoolClosed is returned by Acquire once Close has been called — the
// pool is draining and admits no new work.
var ErrPoolClosed = errors.New("pool: closed")

// ErrPoolPaused is returned by Acquire when the pool is paused AND the
// caller passed a ctx that expired while waiting for Resume. During a
// normal pause Acquire simply blocks on the resume channel; this error
// only surfaces if the client's own deadline runs out first.
var ErrPoolPaused = errors.New("pool: paused")

// ErrCircuitOpen is returned by Acquire when consecutive dial failures
// have tripped the circuit breaker and the cooldown has not elapsed.
//
// It exists as a distinct sentinel so callers can tell "the backend is
// down" apart from "you waited too long for a free slot" — the two
// deserve different SQLSTATEs and different operator dashboards.
var ErrCircuitOpen = errors.New("pool: circuit breaker open")

// Dialer creates a new backend connection.
type Dialer func(ctx context.Context) (net.Conn, error)

// HealthCheck validates a pooled connection before it's handed to a caller.
// A non-nil error means conn is dead and must be discarded, not reused.
type HealthCheck func(net.Conn) error

// EventFunc observes rare, noteworthy pool events — a discard, dial
// failure, or reaper close — for diagnostics. Called synchronously from
// hot paths, so it must be cheap and non-blocking. May be nil.
type EventFunc func(kind string, err error)

// ObserveWaitFunc receives the total time an Acquire call spent waiting
// (semaphore wait + health-check + dial), for histogram/percentile
// metrics. Called once per completed Acquire. May be nil.
type ObserveWaitFunc func(wait time.Duration)

// idleConn is a pooled connection plus the metadata the reaper and
// health-check throttle need — when it was first dialed (for
// max_lifetime) and when it was last released (for idle_timeout and
// server_check_delay).
type idleConn struct {
	conn       net.Conn
	createdAt  time.Time
	releasedAt time.Time
}

// connMeta is the dial-time record kept for every live connection, in
// Pool.connMeta. It survives Acquire → Release cycles, which idleConn
// does not.
type connMeta struct {
	gen       uint64    // reconnectGen as of dial
	createdAt time.Time // true dial time, never rewritten
}

// Pool hands out up to limit backend connections at a time, reusing the
// most recently released one first (LIFO — warm connections stay warm).
type Pool struct {
	dial        Dialer
	healthCheck HealthCheck
	onEvent     EventFunc
	observeWait ObserveWaitFunc

	// tunables — see Options below
	idleTimeout      time.Duration // 0 = never expire idle conns
	maxLifetime      time.Duration // 0 = no lifetime cap
	healthCheckDelay time.Duration // skip healthcheck if idle for < this
	minIdle          int           // warm-up target
	dialRetryMax     int           // additional dial attempts on failure (0 = no retry)
	dialRetryBackoff time.Duration // initial backoff between dial retries

	// Circuit breaker. 0 threshold disables it entirely.
	//
	// Without one, a backend that is down turns every Acquire into
	// (health check + dialRetryMax retries with backoff) before the
	// client sees an error. With N clients that is a dial storm aimed
	// at a server which is, by assumption, already unwell — and the
	// storm peaks exactly when it starts recovering.
	cbThreshold int
	cbCooldown  time.Duration
	// cbFailures counts consecutive dial failures; reset by any
	// success. cbOpenUntil is a unix-nano deadline, 0 meaning closed.
	cbFailures  atomic.Int64
	cbOpenUntil atomic.Int64

	sem  chan struct{}
	done chan struct{} // closed by Close() to wake waiters and reaper

	// closed is checked on every Acquire — moving it from mu-protected
	// bool to atomic.Bool removes both mu ops from the hot pre-check
	// path. Correctness is preserved because Close still takes p.mu
	// after storing closed=true, and every mutator of p.idle re-reads
	// closed AFTER taking p.mu (see Release / warmUp). That two-step
	// dance is what stops a "closed but idle repopulated" race.
	closed atomic.Bool

	// paused: when true, Acquire blocks until Resume closes resumeCh
	// (or the caller's ctx expires). Mirrors PgBouncer's PAUSE — used
	// for zero-downtime backend switchover: PAUSE, wait for in-flight
	// to drain, switch DNS/failover, RESUME. Never affects Release;
	// held connections finish their current transaction normally.
	paused   atomic.Bool
	pauseMu  sync.Mutex    // guards resumeCh swap
	resumeCh chan struct{} // closed by Resume, replaced by Pause

	// reconnectGen bumps every time Reconnect is called. Release
	// discards any conn whose generation is older than reconnectGen —
	// so RECONNECT drops idle immediately and forces in-flight conns
	// to be dropped the moment they're released, without killing any
	// active transaction. Mirrors PgBouncer's RECONNECT.
	reconnectGen atomic.Uint64
	// connMeta tracks per-conn dial-time facts: the reconnect
	// generation and the dial timestamp. sync.Map (read-heavy pattern)
	// avoids extending mu-hot-path work: Release looks it up once;
	// writes only happen on dial and Discard.
	//
	// createdAt lives here rather than in idleConn because Acquire
	// hands the bare net.Conn to the caller — the idleConn wrapper (and
	// with it any timestamp stored only there) is destroyed on pop. A
	// side table keyed by conn is what lets Release restore the true
	// dial age instead of inventing a fresh one.
	connMeta sync.Map // net.Conn → connMeta

	mu   sync.Mutex
	idle []idleConn

	// waiting counts goroutines currently parked on the semaphore. Read
	// atomically by Stats — never held under mu, which would defeat the
	// point of a cheap gauge.
	waiting atomic.Int64

	waitCount  atomic.Int64
	waitNanos  atomic.Int64
	discards   atomic.Int64
	dialErrors atomic.Int64
	reaped     atomic.Int64 // conns closed by idle/lifetime reaper
}

// Stats is a point-in-time snapshot of pool counters.
type Stats struct {
	Limit      int
	InUse      int
	Idle       int
	Waiting    int           // goroutines currently parked in Acquire waiting for a slot
	WaitCount  int64         // total Acquire calls (including instant ones)
	WaitTime   time.Duration // cumulative time inside Acquire
	Discards   int64
	DialErrors int64
	Reaped     int64
	// CircuitOpen is true while the breaker is rejecting dials. Drives
	// the readiness probe and the pgman_pool_circuit_open gauge.
	CircuitOpen bool
}

// Stats returns a snapshot of the pool's current counters.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	idle := len(p.idle)
	p.mu.Unlock()

	return Stats{
		Limit:       cap(p.sem),
		InUse:       len(p.sem),
		Idle:        idle,
		Waiting:     int(p.waiting.Load()),
		WaitCount:   p.waitCount.Load(),
		WaitTime:    time.Duration(p.waitNanos.Load()),
		Discards:    p.discards.Load(),
		DialErrors:  p.dialErrors.Load(),
		Reaped:      p.reaped.Load(),
		CircuitOpen: p.CircuitOpen(),
	}
}

// Option tunes a Pool at construction time. Options are additive; unset
// options preserve the pool's permissive defaults (no timeouts, no retry,
// no warm-up, no metric hook).
type Option func(*Pool)

// WithIdleTimeout closes any pooled connection that's sat idle longer
// than d — mirrors PgBouncer's server_idle_timeout. 0 disables.
func WithIdleTimeout(d time.Duration) Option { return func(p *Pool) { p.idleTimeout = d } }

// WithMaxLifetime closes any pooled connection older than d, even if
// currently healthy — mirrors PgBouncer's server_lifetime. Prevents stale
// backends and enables silent credential rotation. 0 disables.
func WithMaxLifetime(d time.Duration) Option { return func(p *Pool) { p.maxLifetime = d } }

// WithHealthCheckDelay skips the health check for connections that were
// released more recently than d — mirrors PgBouncer's server_check_delay.
// Fresh, hot connections skip the round-trip; only stale ones pay. 0
// means "always health-check" (the pre-tunable behaviour).
func WithHealthCheckDelay(d time.Duration) Option {
	return func(p *Pool) { p.healthCheckDelay = d }
}

// WithMinIdle keeps at least n connections warm — mirrors PgBouncer's
// min_pool_size. Warm-up runs in the background; Acquire never blocks on
// it. 0 disables.
func WithMinIdle(n int) Option { return func(p *Pool) { p.minIdle = n } }

// WithDialRetry retries a failed dial up to attempts extra times with
// exponential backoff starting at backoff — mirrors PgBouncer's
// server_login_retry. The retry loop honors the caller's Acquire ctx.
func WithDialRetry(attempts int, backoff time.Duration) Option {
	return func(p *Pool) {
		p.dialRetryMax = attempts
		p.dialRetryBackoff = backoff
	}
}

// WithObserveWait installs a per-Acquire wait-time observer for
// histogram/percentile metrics.
func WithObserveWait(fn ObserveWaitFunc) Option {
	return func(p *Pool) { p.observeWait = fn }
}

// WithCircuitBreaker trips the pool after threshold consecutive dial
// failures: for the next cooldown, Acquire fails immediately with
// ErrCircuitOpen instead of attempting a dial. Once the cooldown
// elapses a single Acquire is allowed through as a probe — if it
// succeeds the breaker closes, if it fails the cooldown restarts.
//
// This is the "fail fast while the backend is down" half of resilience;
// the other half is that callers must treat ErrCircuitOpen as a
// retryable, query-scoped error rather than a fatal one.
//
// threshold <= 0 disables the breaker (the pre-existing behaviour).
func WithCircuitBreaker(threshold int, cooldown time.Duration) Option {
	return func(p *Pool) {
		p.cbThreshold = threshold
		p.cbCooldown = cooldown
	}
}

// New creates a Pool that dials new connections via dial, never holding
// more than limit of them outstanding at once. healthCheck may be nil.
// onEvent may be nil. Options tune lifecycle behaviour; see each With*.
func New(dial Dialer, limit int, healthCheck HealthCheck, onEvent EventFunc, opts ...Option) *Pool {
	p := &Pool{
		dial:        dial,
		healthCheck: healthCheck,
		onEvent:     onEvent,
		sem:         make(chan struct{}, limit),
		done:        make(chan struct{}),
	}
	// resumeCh starts closed — the pool is not paused. Pause() replaces
	// it with a fresh open channel; Resume() closes that channel to
	// wake every parked Acquire in one broadcast.
	resumeCh := make(chan struct{})
	close(resumeCh)
	p.resumeCh = resumeCh
	for _, o := range opts {
		o(p)
	}

	if p.idleTimeout > 0 || p.maxLifetime > 0 {
		go p.reaper()
	}
	if p.minIdle > 0 {
		go p.warmUp()
	}

	return p
}

func (p *Pool) emit(kind string, err error) {
	if p.onEvent != nil {
		p.onEvent(kind, err)
	}
}

// circuitAllows reports whether a dial may proceed, and takes the
// half-open probe slot if the cooldown has just elapsed.
//
// The CAS is what makes "half-open" mean one probe rather than a
// thundering herd: every goroutine that finds an elapsed deadline races
// to push it forward, and exactly one wins. The losers keep failing
// fast, so a recovering backend sees a single connection attempt, not
// one per waiting client.
func (p *Pool) circuitAllows() bool {
	if p.cbThreshold <= 0 {
		return true
	}
	until := p.cbOpenUntil.Load()
	if until == 0 {
		return true // closed
	}
	now := time.Now().UnixNano()
	if now < until {
		return false
	}
	return p.cbOpenUntil.CompareAndSwap(until, now+p.cbCooldown.Nanoseconds())
}

// circuitRecordSuccess closes the breaker. Called after any successful
// dial, including the half-open probe.
func (p *Pool) circuitRecordSuccess() {
	if p.cbThreshold <= 0 {
		return
	}
	p.cbFailures.Store(0)
	if p.cbOpenUntil.Swap(0) != 0 {
		p.emit("circuit_close", nil)
	}
}

// circuitRecordFailure counts a failed dial and opens the breaker once
// the threshold is reached.
func (p *Pool) circuitRecordFailure(err error) {
	if p.cbThreshold <= 0 {
		return
	}
	if p.cbFailures.Add(1) < int64(p.cbThreshold) {
		return
	}
	wasOpen := p.cbOpenUntil.Swap(time.Now().Add(p.cbCooldown).UnixNano()) != 0
	if !wasOpen {
		p.emit("circuit_open", err)
	}
}

// CircuitOpen reports whether the breaker is currently rejecting dials.
// Cheap atomic load — safe to call from a readiness probe or a metrics
// scrape on any goroutine.
func (p *Pool) CircuitOpen() bool {
	if p.cbThreshold <= 0 {
		return false
	}
	until := p.cbOpenUntil.Load()
	return until != 0 && time.Now().UnixNano() < until
}

// loadMeta reads the dial-time record for conn. Absent means the conn
// was never tagged (only reachable if a caller Releases something this
// pool never handed out), so callers fall back to safe defaults.
func (p *Pool) loadMeta(conn net.Conn) (connMeta, bool) {
	v, ok := p.connMeta.Load(conn)
	if !ok {
		return connMeta{}, false
	}
	m, ok := v.(connMeta)
	return m, ok
}

// retire closes conn for good and drops its metadata. Every permanent
// close goes through here so connMeta can't outlive the connection —
// a leaked entry pins the net.Conn and its buffers forever.
func (p *Pool) retire(conn net.Conn) {
	p.connMeta.Delete(conn)
	_ = conn.Close()
}

// Acquire blocks until a connection is available or ctx is done. Idle
// connections that fail healthCheck (or exceed max_lifetime) are
// discarded and skipped, not returned. On Pool.Close it fails with
// ErrPoolClosed — waiters parked here are woken via p.done.
func (p *Pool) Acquire(ctx context.Context) (net.Conn, error) {
	// Fast pre-check without mu: atomic load is one uncontended
	// LDAR on arm64 (or a plain MOV + memory barrier on amd64). This
	// used to be `mu.Lock; b := closed; mu.Unlock` — two mutex round
	// trips on every single Acquire, even under zero contention.
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	// Pause gate: park here until Resume closes resumeCh. Held under
	// pauseMu only long enough to snapshot the current channel — we
	// never wait on the mutex, only on the channel value, so Resume
	// swapping the channel doesn't strand us. Zero cost when not
	// paused (already-closed channel returns instantly).
	if p.paused.Load() {
		p.pauseMu.Lock()
		ch := p.resumeCh
		p.pauseMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			return nil, ErrPoolClosed
		}
	}

	start := time.Now()
	defer func() {
		wait := time.Since(start)
		p.waitCount.Add(1)
		p.waitNanos.Add(int64(wait))
		if p.observeWait != nil {
			p.observeWait(wait)
		}
	}()

	p.waiting.Add(1)
	select {
	case p.sem <- struct{}{}:
		p.waiting.Add(-1)
	case <-p.done:
		p.waiting.Add(-1)
		return nil, ErrPoolClosed
	case <-ctx.Done():
		p.waiting.Add(-1)
		return nil, ctx.Err()
	}

	// Re-check closed after acquiring the slot — Close may have fired
	// between our select cases resolving and here. Atomic load; no mu.
	if p.closed.Load() {
		p.releaseSlot()
		return nil, ErrPoolClosed
	}

	for {
		ic, ok := p.popIdle()
		if !ok {
			break
		}

		// max_lifetime: even a healthy connection past its lifetime is
		// closed and replaced. Prevents stale backends and enables
		// silent credential rotation without a full pool bounce.
		if p.maxLifetime > 0 && time.Since(ic.createdAt) > p.maxLifetime {
			p.retire(ic.conn)
			p.reaped.Add(1)
			p.emit("reap_lifetime", nil)
			continue
		}

		// server_check_delay: freshly-released connections skip the
		// health-check round-trip entirely — this is the difference
		// between adding ~1ms to every hot query and only paying when
		// a connection has actually gone cold.
		skipCheck := p.healthCheckDelay > 0 && time.Since(ic.releasedAt) < p.healthCheckDelay
		if p.healthCheck == nil || skipCheck || p.healthCheck(ic.conn) == nil {
			return ic.conn, nil
		}
		p.retire(ic.conn)
		p.discards.Add(1)
		p.emit("discard", nil)
	}

	// No idle connection was usable, so we have to dial — which is
	// exactly where the breaker belongs. Note this is *after* the idle
	// scan on purpose: a tripped breaker must not stop us handing out a
	// perfectly good warm connection.
	if !p.circuitAllows() {
		p.releaseSlot()
		return nil, ErrCircuitOpen
	}

	conn, err := p.dialWithRetry(ctx)
	if err != nil {
		p.releaseSlot()
		p.dialErrors.Add(1)
		p.emit("dial_error", err)
		p.circuitRecordFailure(err)
		return nil, fmt.Errorf("dial: %w", err)
	}
	p.circuitRecordSuccess()
	// Tag this conn with the reconnect generation as-of-now plus its
	// dial time. If Reconnect fires later while this conn is in flight,
	// Release will see gen < reconnectGen and discard; createdAt is
	// what makes max_lifetime measure real connection age.
	p.connMeta.Store(conn, connMeta{gen: p.reconnectGen.Load(), createdAt: time.Now()})
	return conn, nil
}

// dialWithRetry runs p.dial up to (1 + dialRetryMax) times with
// exponential backoff, aborting on ctx cancellation. Mirrors PgBouncer's
// server_login_retry: a transient backend blip during failover shouldn't
// surface as an immediate client error.
func (p *Pool) dialWithRetry(ctx context.Context) (net.Conn, error) {
	attempts := 1 + p.dialRetryMax
	backoff := p.dialRetryBackoff
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		conn, err := p.dial(ctx)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		// Never retry if the caller's context is already done — waiting
		// past that would violate their explicit deadline.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if i == attempts-1 {
			break
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			return nil, ErrPoolClosed
		}
		backoff *= 2
	}
	return nil, lastErr
}

func (p *Pool) popIdle() (idleConn, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := len(p.idle)
	if n == 0 {
		return idleConn{}, false
	}
	ic := p.idle[n-1]
	p.idle = p.idle[:n-1]
	return ic, true
}

// Release returns conn to the pool for reuse — unless the pool has been
// Closed in the meantime, in which case there's no idle stack left to
// reuse it from, so it's just closed instead. If Reconnect has been
// called since this conn was dialed, it's also discarded here — that's
// how RECONNECT retires in-flight connections without disturbing the
// active transaction they're carrying.
func (p *Pool) Release(conn net.Conn) {
	// One lookup serves three purposes: the ownership check here, the
	// stale-generation check below, and the true dial time used for
	// max_lifetime.
	meta, haveMeta := p.loadMeta(conn)
	if !haveMeta {
		p.rejectForeign(conn, "release")
		return
	}

	// Fast path: atomically check closed BEFORE taking mu.
	if p.closed.Load() {
		p.connMeta.Delete(conn)
		_ = conn.Close()
		p.releaseSlot()
		return
	}

	// Stale-generation check: Reconnect() bumped reconnectGen after
	// this conn was dialed. Discard so the next Acquire dials fresh.
	if haveMeta && meta.gen < p.reconnectGen.Load() {
		p.connMeta.Delete(conn)
		_ = conn.Close()
		p.releaseSlot()
		p.discards.Add(1)
		p.emit("reconnect_discard", nil)
		return
	}

	now := time.Now()
	// max_lifetime is measured from dial, exactly as PgBouncer's
	// server_lifetime is. Re-stamping createdAt on every release (the
	// previous behaviour) meant a connection under steady traffic was
	// never old enough to retire, so credential rotation and failover
	// cleanup silently never happened.
	createdAt := now
	if haveMeta {
		createdAt = meta.createdAt
	}
	p.mu.Lock()
	// Re-check under mu: Close orders `closed.Store(true)` BEFORE
	// `mu.Lock(); idle = nil; mu.Unlock()`. Without this second check,
	// a race window exists where we've already loaded closed=false in
	// the fast path but Close has swapped the idle slice out from under
	// us — appending here would put a live conn on a slice that Close
	// no longer holds a reference to, and it would leak forever.
	if p.closed.Load() {
		p.mu.Unlock()
		p.connMeta.Delete(conn)
		_ = conn.Close()
		p.releaseSlot()
		return
	}
	// A connection already sitting in the idle stack is being released a
	// second time. Appending it again would leave the same conn in the
	// stack twice, and two Acquires would then hand one connection to two
	// sessions — they would interleave their traffic on it and the
	// protocol stream would make no sense to either. Cheaper to notice:
	// the scan is over at most `limit` pointers, against a release path
	// that usually involves a round trip to Postgres.
	for _, ic := range p.idle {
		if ic.conn == conn {
			p.mu.Unlock()
			p.emit("double_release", errDoubleRelease)
			return
		}
	}
	p.idle = append(p.idle, idleConn{
		conn:       conn,
		createdAt:  createdAt,
		releasedAt: now,
	})
	p.mu.Unlock()

	p.releaseSlot()
}

// releaseSlot gives a semaphore slot back without being able to block.
//
// A plain `<-p.sem` deadlocks if the accounting is ever off by one — a
// connection returned twice, say — and a pooler that hangs inside Release
// takes its caller's goroutine with it. Refusing to block turns a caller
// bug into a logged event, which is recoverable and diagnosable.
func (p *Pool) releaseSlot() {
	select {
	case <-p.sem:
	default:
		p.emit("slot_underflow", errSlotUnderflow)
	}
}

// Discard closes conn and frees its slot without returning it to the idle
// stack — use when conn is known broken and must never be handed out again.
func (p *Pool) Discard(conn net.Conn) {
	if _, haveMeta := p.loadMeta(conn); !haveMeta {
		p.rejectForeign(conn, "discard")
		return
	}
	p.retire(conn)
	p.releaseSlot()
	p.discards.Add(1)
	p.emit("discard", nil)
}

// rejectForeign handles a connection handed back to a pool that has no
// record of it: one dialed by a different pool, or the same connection
// returned twice.
//
// The connection is closed — nobody else is going to — but the semaphore
// is left alone, and that is the whole point. A slot is fungible: freeing
// one for a connection this pool never issued frees a slot that belongs
// to a connection still in flight, so the pool believes it has capacity
// it does not and hands out more than its limit. Losing a slot is
// self-limiting; inventing one is not.
//
// This is a caller bug either way, so it is reported rather than
// absorbed silently.
func (p *Pool) rejectForeign(conn net.Conn, op string) {
	_ = conn.Close()
	p.emit("foreign_"+op, errForeignConn)
}

// errForeignConn marks the event above, so a reader of the event log sees
// a cause rather than an empty error column.
var errForeignConn = errors.New("connection was not issued by this pool (or was returned twice)")

// errDoubleRelease and errSlotUnderflow mark the two shapes a
// return-path accounting bug takes: the same connection handed back
// twice, and a slot freed that nobody had taken.
var (
	errDoubleRelease = errors.New("connection was already idle in this pool")
	errSlotUnderflow = errors.New("a pool slot was freed that nothing had taken")
)

// reaper periodically closes idle connections that have exceeded either
// idleTimeout or maxLifetime. Runs until Close signals done.
func (p *Pool) reaper() {
	// Tick at half the smaller of the two thresholds — fine-grained
	// enough to hit the actual timeout within one interval, coarse
	// enough not to hammer the lock. Minimum 1s to avoid runaway
	// wake-ups in a mis-configured pool.
	interval := p.idleTimeout
	if p.maxLifetime > 0 && (interval == 0 || p.maxLifetime < interval) {
		interval = p.maxLifetime
	}
	interval /= 2
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.reapExpired()
		}
	}
}

func (p *Pool) reapExpired() {
	if p.closed.Load() {
		return // Close already handled the drain
	}
	now := time.Now()

	p.mu.Lock()
	if p.closed.Load() {
		p.mu.Unlock()
		return
	}
	kept := p.idle[:0]
	var expired []net.Conn
	for _, ic := range p.idle {
		expiredIdle := p.idleTimeout > 0 && now.Sub(ic.releasedAt) > p.idleTimeout
		expiredAge := p.maxLifetime > 0 && now.Sub(ic.createdAt) > p.maxLifetime
		if expiredIdle || expiredAge {
			expired = append(expired, ic.conn)
			continue
		}
		kept = append(kept, ic)
	}
	p.idle = kept
	p.mu.Unlock()

	for _, c := range expired {
		p.retire(c)
		p.reaped.Add(1)
		p.emit("reap_idle", nil)
	}
}

// warmUp dials up to minIdle connections on startup and puts them
// straight into the idle stack — Acquire never has to pay a dial for
// steady-state traffic. Fails silently on dial errors (event log will
// pick them up); a cold pool is not a fatal condition.
func (p *Pool) warmUp() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	target := p.minIdle
	if target > cap(p.sem) {
		target = cap(p.sem)
	}

	for i := 0; i < target; i++ {
		select {
		case <-p.done:
			return
		default:
		}

		// Warm-up feeds the breaker below, so it has to obey it too.
		// Without this a pool with min_pool_size against a dead backend
		// performs the whole burst the breaker exists to prevent — and
		// performs most of it after the breaker has already opened,
		// which is the one moment the backend should be left alone.
		//
		// Giving up rather than waiting out the cooldown: warm-up is an
		// optimisation for the first client, and a backend that is down
		// at startup will be dialed again by that client anyway.
		if !p.circuitAllows() {
			return
		}

		select {
		case p.sem <- struct{}{}:
		case <-p.done:
			return
		}

		conn, err := p.dial(ctx)
		if err != nil {
			p.releaseSlot()
			p.dialErrors.Add(1)
			p.emit("dial_error", err)
			// Warm-up talks to the same backend as Acquire, so its
			// failures are the same evidence. Feeding them in means a
			// pool that starts against a dead backend is already open
			// by the time the first client arrives.
			p.circuitRecordFailure(err)
			continue
		}
		p.circuitRecordSuccess()

		now := time.Now()
		p.mu.Lock()
		if p.closed.Load() {
			p.mu.Unlock()
			_ = conn.Close()
			p.releaseSlot()
			return
		}
		p.connMeta.Store(conn, connMeta{gen: p.reconnectGen.Load(), createdAt: now})
		p.idle = append(p.idle, idleConn{conn: conn, createdAt: now, releasedAt: now})
		p.mu.Unlock()
		p.releaseSlot()
	}
}

// Pause stops handing out connections. Any Acquire called after Pause
// parks on the resume channel until Resume() is called or the caller's
// ctx expires (whichever comes first). In-flight conns are never
// touched — the transactions they carry finish normally and release
// back to idle, where the next Acquire (post-Resume) will pick them
// up. Mirrors PgBouncer's PAUSE.
//
// Double-Pause is a cheap no-op.
//
// The flag and the channel are changed together under pauseMu, and that
// pairing is the whole correctness argument. Setting paused=true first
// and swapping the channel afterwards leaves a window in which a
// concurrent Resume wins its own compare-and-swap, reads the *previous*
// resumeCh — which is already closed — and closes it a second time.
// That panics, and since PAUSE and RESUME are both reachable from the
// admin API, two operators or one retrying script could take the whole
// proxy down with it.
func (p *Pool) Pause() {
	p.pauseMu.Lock()
	paused := p.paused.CompareAndSwap(false, true)
	if paused {
		p.resumeCh = make(chan struct{})
	}
	p.pauseMu.Unlock()

	// Outside the lock: emit hands control to caller-supplied code, and
	// nothing it might do should be able to block Pause's counterpart.
	if paused {
		p.emit("pause", nil)
	}
}

// Resume undoes Pause: closes the current resumeCh, waking every
// parked Acquire in one broadcast. Safe to call when not paused
// (no-op then).
func (p *Pool) Resume() {
	p.pauseMu.Lock()
	if !p.paused.CompareAndSwap(true, false) {
		p.pauseMu.Unlock()
		return
	}
	ch := p.resumeCh
	// Install a pre-closed channel so a later Pause-then-Acquire
	// without an intervening Resume can't race (Acquire loads
	// resumeCh and blocks on it; if we left the closed one in place
	// nothing breaks, but the invariant "resumeCh is closed iff not
	// paused" is easier to reason about).
	closed := make(chan struct{})
	close(closed)
	p.resumeCh = closed
	p.pauseMu.Unlock()

	close(ch)
	p.emit("resume", nil)
}

// IsPaused reports whether the pool is currently paused. Cheap atomic
// load — safe from any goroutine.
func (p *Pool) IsPaused() bool { return p.paused.Load() }

// Reconnect bumps the pool's generation counter and drains the entire
// idle stack immediately. Any in-flight conns are marked stale by the
// generation bump — the next Release of each will close them instead
// of returning them to idle, forcing the next Acquire to dial fresh.
//
// This is the graceful "backend endpoint changed" primitive — use it
// after a DNS flip, an RDS failover, or a credential rotation, and
// let active transactions finish rather than killing them mid-flight.
// Returns the number of idle conns closed immediately.
func (p *Pool) Reconnect() int {
	p.reconnectGen.Add(1)

	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, ic := range idle {
		p.retire(ic.conn)
		p.reaped.Add(1)
	}
	p.emit("reconnect", nil)
	return len(idle)
}

// Close stops the pool from admitting new work: every Acquire from this
// point on fails with ErrPoolClosed (including goroutines already parked
// on the semaphore, which are woken via p.done), and idle connections
// are closed right away. It then blocks until every checked-out
// connection has been returned via Release/Discard.
func (p *Pool) Close(ctx context.Context) error {
	// CompareAndSwap so double-Close is a cheap no-op — no mu needed
	// on the second call at all.
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	// The mu.Lock here is what pairs with Release/warmUp's "re-check
	// closed under mu" pattern: after we release this mutex, every
	// subsequent Release will see closed=true under mu and refuse to
	// touch p.idle. So this critical section is where the pool's
	// "no more appends" invariant becomes true.
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	close(p.done) // wake all waiters and stop the reaper

	for _, ic := range idle {
		p.retire(ic.conn)
	}

	// Poll for in-flight drain. We can't wake a Release path without
	// coordinating with the caller, so a short-interval poll is the
	// simplest correct approach — this only fires during shutdown, not
	// on the hot path.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for len(p.sem) > 0 {
		select {
		case <-ctx.Done():
			return fmt.Errorf("close: %w (still %d connection(s) in flight)", ctx.Err(), len(p.sem))
		case <-ticker.C:
		}
	}
	return nil
}
