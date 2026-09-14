package pool

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// failingDialer returns an error until `healAfter` is flipped, then
// hands back a live pipe. dials counts every attempt so tests can assert
// the breaker actually suppressed work rather than just relabelling the
// error.
func failingDialer(t *testing.T, dials *int32, healthy *atomic.Bool) Dialer {
	t.Helper()
	return func(context.Context) (net.Conn, error) {
		atomic.AddInt32(dials, 1)
		if !healthy.Load() {
			return nil, errors.New("connection refused")
		}
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}
}

// TestCircuitOpensAfterThresholdAndFailsFast is the core of the breaker:
// once the backend has proven itself down, Acquire must stop dialing.
//
// Asserting on the dial count (not just the error) is the point. The
// failure mode this guards against is a breaker that returns a nice
// error while still hammering a backend that is trying to recover.
func TestCircuitOpensAfterThresholdAndFailsFast(t *testing.T) {
	var dials int32
	var healthy atomic.Bool

	p := New(failingDialer(t, &dials, &healthy), 4, nil, nil,
		WithCircuitBreaker(3, time.Hour)) // cooldown long enough to never elapse mid-test

	// Three failures to reach the threshold.
	for i := 0; i < 3; i++ {
		if _, err := p.Acquire(context.Background()); err == nil {
			t.Fatalf("acquire %d: expected a dial failure", i)
		}
	}
	if got := atomic.LoadInt32(&dials); got != 3 {
		t.Fatalf("dials = %d, want 3 before the breaker trips", got)
	}
	if !p.CircuitOpen() {
		t.Fatal("breaker should be open after reaching the failure threshold")
	}

	// Everything from here must be rejected without touching the network.
	for i := 0; i < 10; i++ {
		_, err := p.Acquire(context.Background())
		if !errors.Is(err, ErrCircuitOpen) {
			t.Fatalf("acquire %d after trip: err = %v, want ErrCircuitOpen", i, err)
		}
	}
	if got := atomic.LoadInt32(&dials); got != 3 {
		t.Errorf("dials = %d, want 3: the open breaker kept dialing the dead backend", got)
	}
	if s := p.Stats(); !s.CircuitOpen {
		t.Error("Stats().CircuitOpen should mirror the breaker state")
	}
}

// TestCircuitHalfOpenAdmitsExactlyOneProbe pins the recovery path. A
// breaker that releases every waiter at once when the cooldown expires
// just reschedules the stampede it was built to prevent.
func TestCircuitHalfOpenAdmitsExactlyOneProbe(t *testing.T) {
	var dials int32
	var healthy atomic.Bool

	const cooldown = 40 * time.Millisecond
	p := New(failingDialer(t, &dials, &healthy), 8, nil, nil,
		WithCircuitBreaker(2, cooldown))

	for i := 0; i < 2; i++ {
		_, _ = p.Acquire(context.Background())
	}
	if !p.CircuitOpen() {
		t.Fatal("breaker did not open")
	}
	before := atomic.LoadInt32(&dials)

	time.Sleep(cooldown + 10*time.Millisecond)

	// Backend is still down. Many concurrent acquires, exactly one dial.
	const callers = 8
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		go func() {
			_, err := p.Acquire(context.Background())
			errs <- err
		}()
	}
	var rejected int
	for i := 0; i < callers; i++ {
		if errors.Is(<-errs, ErrCircuitOpen) {
			rejected++
		}
	}

	probes := atomic.LoadInt32(&dials) - before
	if probes != 1 {
		t.Errorf("half-open let %d dials through, want exactly 1", probes)
	}
	if rejected != callers-1 {
		t.Errorf("%d callers fast-failed, want %d (one is the prober)", rejected, callers-1)
	}
}

// TestCircuitClosesAfterSuccessfulProbe completes the lifecycle: a
// recovered backend must return the pool to normal service, including
// resetting the failure count so one later blip does not re-trip it.
func TestCircuitClosesAfterSuccessfulProbe(t *testing.T) {
	var dials int32
	var healthy atomic.Bool

	const cooldown = 30 * time.Millisecond
	p := New(failingDialer(t, &dials, &healthy), 4, nil, nil,
		WithCircuitBreaker(2, cooldown))

	for i := 0; i < 2; i++ {
		_, _ = p.Acquire(context.Background())
	}
	if !p.CircuitOpen() {
		t.Fatal("breaker did not open")
	}

	healthy.Store(true)
	time.Sleep(cooldown + 10*time.Millisecond)

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("probe acquire after recovery: %v", err)
	}
	p.Release(conn)

	if p.CircuitOpen() {
		t.Error("a successful probe must close the breaker")
	}

	// And normal service resumes.
	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire after close: %v", err)
	}
	p.Release(c2)
}

// TestCircuitDisabledByDefault guards the opt-in contract: pools built
// without WithCircuitBreaker must behave exactly as before.
func TestCircuitDisabledByDefault(t *testing.T) {
	var dials int32
	var healthy atomic.Bool

	p := New(failingDialer(t, &dials, &healthy), 2, nil, nil)

	for i := 0; i < 5; i++ {
		_, err := p.Acquire(context.Background())
		if errors.Is(err, ErrCircuitOpen) {
			t.Fatal("breaker tripped on a pool that never enabled it")
		}
	}
	if got := atomic.LoadInt32(&dials); got != 5 {
		t.Errorf("dials = %d, want 5 — every Acquire should still dial", got)
	}
	if p.CircuitOpen() {
		t.Error("CircuitOpen must be false when the breaker is disabled")
	}
}

// TestCircuitDoesNotBlockIdleReuse is the ordering guarantee: the
// breaker guards dials, not the pool. A warm connection must still be
// handed out while the backend is unreachable — otherwise one dead
// replica takes out traffic that the existing connections could serve.
func TestCircuitDoesNotBlockIdleReuse(t *testing.T) {
	var dials int32
	var healthy atomic.Bool
	healthy.Store(true)

	p := New(failingDialer(t, &dials, &healthy), 2, nil, nil,
		WithCircuitBreaker(1, time.Hour))

	warm, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	p.Release(warm)

	// Backend goes away; force a dial failure to trip the breaker.
	healthy.Store(false)
	c1, err := p.Acquire(context.Background()) // reuses the warm conn
	if err != nil {
		t.Fatalf("acquire warm conn: %v", err)
	}
	if _, err := p.Acquire(context.Background()); err == nil {
		t.Fatal("second acquire should have failed to dial")
	}
	if !p.CircuitOpen() {
		t.Fatal("breaker did not open")
	}

	// Put the warm conn back; it must still be servable.
	p.Release(c1)
	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("idle reuse blocked by an open breaker: %v", err)
	}
	p.Release(c2)
}
