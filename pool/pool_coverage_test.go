package pool

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// waitForIdle blocks until the pool reports at least n idle conns, or
// fails the test. Warm-up is asynchronous by design — Acquire must
// never wait on it — so tests have to poll rather than assume the
// background goroutine has already finished.
func waitForIdle(t *testing.T, p *Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.Stats().Idle < n {
		if time.Now().After(deadline) {
			t.Fatalf("idle = %d after 2s, want >= %d", p.Stats().Idle, n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestIdleTimeoutReaperRetiresConnsInTheBackground covers the reason the
// reaper goroutine exists at all: server_idle_timeout must fire on its
// own, without an Acquire to trigger it. A pool that only expires
// connections on the next Acquire holds file descriptors and backend
// sessions open indefinitely on an idle deployment — which is exactly
// the window in which PostgreSQL's own max_connections gets exhausted by
// a neighbouring service.
func TestIdleTimeoutReaperRetiresConnsInTheBackground(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil, WithIdleTimeout(10*time.Millisecond))

	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(c)

	// The reaper floors its tick at one second regardless of how short
	// the timeout is, so this has to wait out a real interval.
	deadline := time.Now().Add(4 * time.Second)
	for p.Stats().Reaped == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the reaper never retired an idle conn past its timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d after the reap, want 0", got)
	}

	// Close must also stop the reaper; a goroutine still ticking against
	// a closed pool is a leak that outlives every hot-reload cycle.
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
}

// TestReapExpiredRetiresOnlyConnsPastTheirTimeout pins the reaper's
// selectivity. The failure mode is not "nothing gets reaped" but the
// opposite: a partition bug that drops healthy, just-released
// connections turns every reap tick into a full pool bounce, so steady
// traffic pays a fresh dial per query and the LIFO warm-connection
// design stops meaning anything.
func TestReapExpiredRetiresOnlyConnsPastTheirTimeout(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil, WithIdleTimeout(20*time.Millisecond))
	ctx := context.Background()

	stale, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire stale: %v", err)
	}
	fresh, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire fresh: %v", err)
	}

	p.Release(stale)
	time.Sleep(40 * time.Millisecond) // push `stale` past the idle timeout
	p.Release(fresh)

	p.reapExpired()

	if got := p.Stats().Reaped; got != 1 {
		t.Fatalf("reaped = %d, want exactly 1", got)
	}
	if got := p.Stats().Idle; got != 1 {
		t.Fatalf("idle = %d after the reap, want 1", got)
	}
	survivor, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire survivor: %v", err)
	}
	if survivor != fresh {
		t.Error("the reaper kept the stale conn and dropped the fresh one")
	}
	p.Release(survivor)
}

// TestReapExpiredIsNoOpOnAClosedPool guards the ordering contract
// between Close and the reaper: Close has already retired every idle
// conn and set p.idle to nil, so a tick that slipped through must not
// touch the slice again. Without the early return the reaper would
// double-count drains into Stats().Reaped and, worse, race Close for
// ownership of connections it no longer owns.
func TestReapExpiredIsNoOpOnAClosedPool(t *testing.T) {
	p := New(pipeDialer(), 1, nil, nil, WithIdleTimeout(time.Millisecond))
	ctx := context.Background()

	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(c)
	if err := p.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	p.reapExpired()

	if got := p.Stats().Reaped; got != 0 {
		t.Errorf("reaped = %d on a closed pool, want 0 — Close owns the drain", got)
	}
}

// TestReapExpiredBailsOutWhenCloseWinsUnderMutex covers the reaper's
// second closed check, the one inside the critical section. The reaper
// reads the flag once without mu and once with it, and only the second
// read orders against Close: a tick that passed the first check and
// then waited out Close on mu would take ownership of connections Close
// has already retired, closing them twice and inflating Reaped with
// work it never did.
//
// Holding mu from the test stalls the reaper at exactly that lock, which
// is the only way to visit the window on purpose.
func TestReapExpiredBailsOutWhenCloseWinsUnderMutex(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil, WithIdleTimeout(time.Millisecond))

	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(c)
	time.Sleep(10 * time.Millisecond) // the idle conn is now reapable

	p.mu.Lock()
	reaped := make(chan struct{})
	go func() {
		p.reapExpired()
		close(reaped)
	}()
	time.Sleep(50 * time.Millisecond) // let the reaper block on mu

	p.closed.Store(true)
	p.mu.Unlock()

	select {
	case <-reaped:
	case <-time.After(2 * time.Second):
		t.Fatal("reapExpired never completed after mu was handed over")
	}

	if got := p.Stats().Reaped; got != 0 {
		t.Errorf("reaped = %d, want 0 — Close owns the drain once closed is set", got)
	}
}

// TestWarmUpAbandonsTheSemaphoreWhenPoolCloses covers the done case on
// warm-up's semaphore wait. A saturated pool leaves warm-up parked
// there indefinitely, and that is the state a shutdown is most likely
// to find it in: min_pool_size only matters when clients are scarce, so
// the wait is longest exactly when traffic has just spiked. Without the
// done case the goroutine outlives the pool and, if a slot ever frees,
// dials a backend for a pool nobody can use.
//
// Close is spelled out by hand here (set the flag, close the channel)
// because the real Close blocks draining the very slot this test needs
// to keep held.
func TestWarmUpAbandonsTheSemaphoreWhenPoolCloses(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	held, err := p.Acquire(context.Background()) // the only slot is now taken
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	p.minIdle = 1
	warmedUp := make(chan struct{})
	go func() {
		p.warmUp()
		close(warmedUp)
	}()
	time.Sleep(50 * time.Millisecond) // let warm-up park on the full semaphore

	p.closed.Store(true)
	close(p.done)

	select {
	case <-warmedUp:
	case <-time.After(2 * time.Second):
		t.Fatal("warm-up stayed parked on the semaphore after the pool closed")
	}

	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Errorf("dials = %d, want 1: warm-up dialed for a closed pool", got)
	}
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d on a closed pool, want 0", got)
	}
	p.Release(held)
}

// TestMinIdleWarmsThePoolBeforeTheFirstAcquire is the whole point of
// min_pool_size: the first client after a restart or a hot-reload must
// not pay for a TCP connect plus a Postgres startup handshake. If
// warm-up silently stops working, that cost reappears as a latency
// spike on exactly the requests that follow a deploy.
func TestMinIdleWarmsThePoolBeforeTheFirstAcquire(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 4, nil, nil, WithMinIdle(2))
	ctx := context.Background()

	waitForIdle(t, p, 2)

	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Errorf("dials = %d, want 2: Acquire dialed instead of taking a warm conn", got)
	}
	p.Release(c)
	if err := p.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestMinIdleNeverExceedsThePoolLimit covers the clamp. A misconfigured
// min_pool_size larger than the pool limit must not make warm-up park
// forever on a semaphore it can never fill — that would strand a
// goroutine holding slots that clients need, turning a typo in the
// config into a pool that never serves anyone.
func TestMinIdleNeverExceedsThePoolLimit(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil, WithMinIdle(5))
	ctx := context.Background()

	waitForIdle(t, p, 2)
	time.Sleep(50 * time.Millisecond) // give a runaway warm-up time to overshoot

	if got := p.Stats().Idle; got != 2 {
		t.Errorf("idle = %d, want 2 (clamped to the pool limit)", got)
	}
	if got := atomic.LoadInt32(&dials); got != 2 {
		t.Errorf("dials = %d, want 2: warm-up ignored the limit", got)
	}
	if err := p.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestWarmUpDialFailuresFeedTheCircuitBreaker locks in that a pool
// started against a dead backend is already tripped by the time the
// first client arrives. Warm-up talks to the same server as Acquire, so
// ignoring its failures would mean every client after a restart has to
// re-discover the outage one slow dial at a time before the breaker
// finally opens.
func TestWarmUpDialFailuresFeedTheCircuitBreaker(t *testing.T) {
	var attempts atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("connection refused")
	}
	p := New(dial, 4, nil, nil, WithMinIdle(3), WithCircuitBreaker(2, time.Hour))

	deadline := time.Now().Add(2 * time.Second)
	for !p.CircuitOpen() {
		if time.Now().After(deadline) {
			t.Fatal("warm-up failures never opened the breaker")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d against a dead backend, want 0", got)
	}
	if got := p.Stats().DialErrors; got == 0 {
		t.Error("warm-up dial failures were not counted in Stats().DialErrors")
	}
	// The breaker opens on the second consecutive failure, and warm-up
	// obeys its own evidence: the third dial is refused before it is
	// made. Warm-up used to keep going for the full min_idle, which is
	// the burst the breaker exists to stop — performed, of all moments,
	// just after it opened.
	if got := attempts.Load(); got != 2 {
		t.Errorf("warm-up made %d dials against a dead backend, want 2 (the breaker's threshold)", got)
	}
}

// TestWarmUpStopsDialingOnceThePoolCloses covers the done check at the
// top of the warm-up loop. Close is expected to return with the backend
// quiet; a warm-up that keeps working through the loop would keep
// dialing a server the operator has just decided to disconnect from,
// and would race Close for the semaphore slots it is trying to drain.
func TestWarmUpStopsDialingOnceThePoolCloses(t *testing.T) {
	gate := make(chan struct{})
	dialing := make(chan struct{}, 1)
	var attempts atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		select {
		case dialing <- struct{}{}:
		default:
		}
		<-gate
		return nil, errors.New("backend down")
	}
	p := New(dial, 4, nil, nil, WithMinIdle(3))

	<-dialing // warm-up is now inside its first dial

	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close(context.Background()) }()
	time.Sleep(50 * time.Millisecond) // let Close flip closed and close done
	close(gate)                       // now let the in-flight dial fail

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close never drained the slot warm-up was holding")
	}

	time.Sleep(50 * time.Millisecond) // let warm-up reach its loop head
	if got := attempts.Load(); got != 1 {
		t.Errorf("warm-up made %d dials, want 1: it kept going after Close", got)
	}
}

// TestWarmUpClosesConnDialedAfterCloseWon covers the re-check under mu
// on the warm-up side. A dial that lands after Close has emptied p.idle
// must close its connection instead of appending it, otherwise the conn
// is pushed onto a slice nobody holds a reference to any more: the
// backend session stays open for the lifetime of the process and Close
// reports a clean shutdown that never happened.
func TestWarmUpClosesConnDialedAfterCloseWon(t *testing.T) {
	gate := make(chan struct{})
	dialing := make(chan struct{}, 1)
	var obs atomic.Pointer[observableConn]
	dial := func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		o := &observableConn{Conn: client}
		obs.Store(o)
		dialing <- struct{}{}
		<-gate
		return o, nil
	}
	p := New(dial, 2, nil, nil, WithMinIdle(1))

	<-dialing

	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close(context.Background()) }()
	time.Sleep(50 * time.Millisecond)
	close(gate)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close never drained the slot warm-up was holding")
	}

	if o := obs.Load(); o == nil || !o.wasClosed.Load() {
		t.Fatal("a conn dialed after Close was leaked instead of closed")
	}
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d after Close, want 0", got)
	}
}

// TestReleaseOfForeignConnDoesNotInventASlot: a connection this pool
// never issued — one belonging to another pool, or the same connection
// returned twice — used to free a semaphore slot anyway. Slots are
// fungible, so the one it freed belonged to a connection still in
// flight: the pool then believed it had capacity it did not and handed
// out more connections than its limit, which is how a limit of 20
// becomes 21 backends against a server sized for 20.
//
// Losing a slot would be self-limiting. Inventing one is not, so the
// foreign connection is closed and the accounting is left alone.
func TestReleaseOfForeignConnDoesNotInventASlot(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)
	ctx := context.Background()

	held, err := p.Acquire(ctx) // occupies the pool's only slot
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	foreign, server := net.Pipe()
	t.Cleanup(func() { foreign.Close(); server.Close() })

	p.Release(foreign)

	// Nothing was parked on the idle stack, and the slot `held` occupies
	// is still occupied.
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d after a foreign release, want 0", got)
	}
	if got := p.Stats().InUse; got != 1 {
		t.Errorf("in use = %d, want 1: the held connection still has its slot", got)
	}

	// The proof: an Acquire now must wait rather than succeed, because
	// the pool's one slot is genuinely taken. Before the fix the foreign
	// release freed it and this returned a second connection.
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if second, err := p.Acquire(waitCtx); err == nil {
		p.Discard(second)
		t.Error("a foreign release handed out a slot that was still in use")
	}

	// The foreign connection is closed on the way out — nobody else is
	// going to, and leaving it open would leak it.
	if _, err := foreign.Write([]byte("x")); err == nil {
		t.Error("the foreign connection was left open")
	}

	if got := atomic.LoadInt32(&dials); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
	p.Release(held)
}

// TestDoubleReleaseDoesNotDuplicateAnIdleConn: the second release of a
// connection that is already parked would append it to the idle stack
// twice, and the next two Acquires would then hand one connection to two
// sessions — which interleaves their protocol streams and makes nonsense
// of both. It must also not deadlock: the slot was already given back,
// so taking another would block inside Release forever.
func TestDoubleReleaseDoesNotDuplicateAnIdleConn(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)
	ctx := context.Background()

	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(c)
	p.Release(c) // the bug

	if got := p.Stats().Idle; got != 1 {
		t.Fatalf("idle = %d after releasing one connection twice, want 1", got)
	}

	// Both slots are free, so two Acquires must produce two distinct
	// connections: one reused, one freshly dialed.
	first, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	second, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if first == second {
		t.Error("two sessions were handed the same connection")
	}
	p.Release(first)
	p.Release(second)
}

// TestDiscardOfForeignConnDoesNotInventASlot is the same contract on the
// other return path: Discard frees a slot too, so it has to be just as
// careful about which connection it is freeing it for.
func TestDiscardOfForeignConnDoesNotInventASlot(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	held, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	foreign, server := net.Pipe()
	t.Cleanup(func() { foreign.Close(); server.Close() })
	p.Discard(foreign)

	if got := p.Stats().InUse; got != 1 {
		t.Errorf("in use = %d, want 1", got)
	}
	if got := p.Stats().Discards; got != 0 {
		t.Errorf("discards = %d, want 0: a foreign connection is not one of this pool's", got)
	}
	p.Release(held)
}

// TestAcquireParkedOnPauseWakesClosedWhenPoolCloses covers the shutdown
// path through the pause gate. PAUSE followed by a shutdown is a normal
// operator sequence — pause, discover the switchover is off, stop the
// process — and an Acquire parked on the resume channel with a
// background ctx has nothing else to wake it. Without the done case it
// would hang until the process-wide shutdown timeout kills it.
func TestAcquireParkedOnPauseWakesClosedWhenPoolCloses(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)
	p.Pause()

	acquireErr := make(chan error, 1)
	go func() {
		_, err := p.Acquire(context.Background())
		acquireErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the Acquire park on resumeCh

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-acquireErr:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("parked Acquire returned %v, want ErrPoolClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an Acquire parked on the pause gate never woke up after Close")
	}
}

// TestAcquireHandsBackSlotWhenCloseWinsAfterSemAdmit covers the closed
// re-check that sits between taking a semaphore slot and using it.
// Close can land in that window, and an Acquire that skipped the check
// would dial a fresh backend connection into a pool that is already
// draining — the conn would never be tracked, and the slot it holds
// would keep Close's drain loop spinning until the caller's deadline.
//
// The pause gate is used as a deterministic stand-in for that window:
// parking the Acquire there lets the test flip the closed flag at the
// exact point Close would have.
func TestAcquireHandsBackSlotWhenCloseWinsAfterSemAdmit(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)
	p.Pause()

	acquireErr := make(chan error, 1)
	go func() {
		_, err := p.Acquire(context.Background())
		acquireErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	p.closed.Store(true)
	p.Resume()

	select {
	case err := <-acquireErr:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("Acquire returned %v, want ErrPoolClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire never returned after the pool was closed")
	}
	if got := p.Stats().InUse; got != 0 {
		t.Errorf("in use = %d, want 0: the semaphore slot was not handed back", got)
	}
	if got := atomic.LoadInt32(&dials); got != 0 {
		t.Errorf("dials = %d, want 0: a closed pool dialed a new backend conn", got)
	}
}

// TestReleaseClosesConnWhenCloseWinsUnderMutex is the mirror of the
// Acquire re-check, on the path that actually leaks. Release reads the
// closed flag before taking mu; if Close completes in between, the idle
// slice Release is about to append to has already been handed to Close
// and replaced with nil. The conn would then be unreachable and never
// closed, and Close would have returned "clean" with a live backend
// session still open.
//
// Holding mu from the test is what makes the window deterministic:
// Release is stalled at exactly the lock acquisition Close orders
// against.
func TestReleaseClosesConnWhenCloseWinsUnderMutex(t *testing.T) {
	// The dialer produces the observable connection, so the pool tracks
	// and the test releases the same value: a wrapper made afterwards is
	// a connection this pool never issued, which Release now refuses.
	dial := func(context.Context) (net.Conn, error) {
		a, _ := net.Pipe()
		return &observableConn{Conn: a}, nil
	}
	p := New(dial, 1, nil, nil)

	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	obs, ok := c.(*observableConn)
	if !ok {
		t.Fatalf("pool handed back %T, want the dialer's wrapper", c)
	}

	p.mu.Lock()
	released := make(chan struct{})
	go func() {
		p.Release(obs)
		close(released)
	}()
	time.Sleep(50 * time.Millisecond) // let Release block on mu

	p.closed.Store(true)
	p.mu.Unlock()

	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("Release never completed after mu was handed over")
	}

	if !obs.wasClosed.Load() {
		t.Fatal("Release appended to a discarded idle slice instead of closing the conn")
	}
	if got := p.Stats().Idle; got != 0 {
		t.Errorf("idle = %d on a closed pool, want 0", got)
	}
	if got := p.Stats().InUse; got != 0 {
		t.Errorf("in use = %d, want 0: the semaphore slot was not handed back", got)
	}
}

// TestDialRetryStopsWhenCallerGivesUpMidDial covers the context check
// that runs before the backoff sleep. query_wait_timeout is the
// caller's hard budget; once it is spent, sleeping out a retry backoff
// burns the client's connection on work whose result nobody will read.
// The one-hour backoff here is deliberate — if the check regresses, the
// test hangs instead of quietly passing.
func TestDialRetryStopsWhenCallerGivesUpMidDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var attempts atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		cancel() // the caller's deadline expires while we are on the wire
		return nil, errors.New("backend down")
	}
	p := New(dial, 1, nil, nil, WithDialRetry(3, time.Hour))

	_, err := p.Acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire returned %v, want context.Canceled", err)
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("dial attempts = %d, want 1: the retry loop ignored the dead ctx", got)
	}
	if got := p.Stats().InUse; got != 0 {
		t.Errorf("in use = %d, want 0: the failed Acquire kept its slot", got)
	}
}

// TestDialRetryAbortsBackoffWhenPoolCloses covers the done case inside
// the backoff wait. During shutdown the retry loop is the longest-lived
// thing in the pool — server_login_retry backoff doubles, so a few
// attempts can outlast the shutdown grace period entirely. It has to
// abandon the wait when the pool closes, or Close blocks on a slot that
// is being held purely to sleep.
func TestDialRetryAbortsBackoffWhenPoolCloses(t *testing.T) {
	var attempts atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("backend down")
	}
	p := New(dial, 1, nil, nil, WithDialRetry(5, 2*time.Second))

	acquireErr := make(chan error, 1)
	go func() {
		_, err := p.Acquire(context.Background())
		acquireErr <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for attempts.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first dial never happened")
		}
		time.Sleep(time.Millisecond)
	}

	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-acquireErr:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("Acquire returned %v, want ErrPoolClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire sat out its retry backoff after the pool closed")
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("dial attempts = %d, want 1: the loop retried after Close", got)
	}
}

// TestCloseReportsConnsStillInFlightOnDeadline covers the drain
// timeout. A client stuck in a long transaction must not be able to
// hold shutdown open forever, and the error has to name the problem:
// "still N connection(s) in flight" is what tells an operator that the
// abrupt exit was caused by their own workload rather than by pgman
// losing track of a connection.
func TestCloseReportsConnsStillInFlightOnDeadline(t *testing.T) {
	p := New(pipeDialer(), 2, nil, nil)

	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = p.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close returned %v, want a DeadlineExceeded wrapper", err)
	}
	if !strings.Contains(err.Error(), "still 1 connection(s) in flight") {
		t.Errorf("Close error %q does not report the stuck connection count", err)
	}

	p.Release(c)
}

// TestReleaseSlotDoesNotBlockOnAnEmptySemaphore is the last line of
// defence on the return path. If the accounting is ever off by one — a
// bug here or a caller returning something twice in a way the checks
// above cannot see — a plain `<-p.sem` would block inside Release
// forever, and with it the session goroutine that called it. Reporting
// and carrying on is recoverable; hanging the caller is not.
func TestReleaseSlotDoesNotBlockOnAnEmptySemaphore(t *testing.T) {
	var kinds []string
	p := New(pipeDialer(), 1, nil, func(kind string, err error) {
		kinds = append(kinds, kind)
	})

	done := make(chan struct{})
	go func() {
		p.releaseSlot() // nothing has taken a slot
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("releaseSlot blocked on an empty semaphore")
	}

	var reported bool
	for _, k := range kinds {
		if k == "slot_underflow" {
			reported = true
		}
	}
	if !reported {
		t.Error("the underflow was absorbed silently, so the accounting bug would never be found")
	}
}
