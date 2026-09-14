package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestCloseUnblocksParkedAcquire proves the P0 fix: goroutines already
// parked in Acquire waiting for a semaphore slot must wake up with
// ErrPoolClosed when Close fires, instead of blocking until the caller's
// own ctx cancels — which under the pre-existing "context.Background()
// in relay" contract meant "block forever, only saved by the process-
// wide shutdown timeout".
func TestCloseUnblocksParkedAcquire(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	defer p.Release(c1)

	acquireErr := make(chan error, 1)
	go func() {
		_, err := p.Acquire(context.Background()) // pool at capacity — parks here
		acquireErr <- err
	}()

	// Let the second Acquire fully enter its select {} before we Close.
	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		_ = p.Close(context.Background())
		close(closeDone)
	}()

	select {
	case err := <-acquireErr:
		if !errors.Is(err, ErrPoolClosed) {
			t.Fatalf("parked Acquire returned err=%v, want ErrPoolClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parked Acquire never woke up after Close — the whole point of the done channel")
	}
	// Close should still complete on its own (c1 is released above via
	// defer once this test returns).
	_ = closeDone
}

func TestAcquireWaitObserverFires(t *testing.T) {
	var dials int32
	var observations int32
	var lastWait atomic.Int64

	obs := func(d time.Duration) {
		atomic.AddInt32(&observations, 1)
		lastWait.Store(int64(d))
	}
	p := New(fakeDialer(t, &dials), 1, nil, nil, WithObserveWait(obs))

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(c1)

	if atomic.LoadInt32(&observations) != 1 {
		t.Fatalf("expected observer to fire once, got %d", observations)
	}
	if lastWait.Load() <= 0 {
		t.Errorf("expected a positive wait duration, got %d", lastWait.Load())
	}
}

func TestHealthCheckDelaySkipsRecentIdleConns(t *testing.T) {
	var dials, checks int32
	hc := func(net.Conn) error {
		atomic.AddInt32(&checks, 1)
		return nil
	}
	// 1 hour delay — every Acquire that follows a Release within the
	// hour must skip the healthcheck entirely.
	p := New(fakeDialer(t, &dials), 1, hc, nil, WithHealthCheckDelay(time.Hour))

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	p.Release(c1)

	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}
	defer p.Release(c2)

	if checks != 0 {
		t.Errorf("expected 0 healthchecks (idle < delay), got %d", checks)
	}
}

func TestMaxLifetimeExpiresIdleConn(t *testing.T) {
	var dials int32
	// 10ms lifetime is instant enough for a test to observe reliably.
	p := New(fakeDialer(t, &dials), 1, nil, nil, WithMaxLifetime(10*time.Millisecond))

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	p.Release(c1)

	time.Sleep(50 * time.Millisecond) // wait past the 10ms lifetime

	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}
	defer p.Release(c2)

	if c2 == c1 {
		t.Error("expected max_lifetime to expire c1 and force a fresh dial")
	}
	if dials != 2 {
		t.Errorf("expected 2 dials (c1 aged out), got %d", dials)
	}
}

// TestMaxLifetimeMeasuredFromDialNotRelease pins the definition of
// max_lifetime: it is the age of the connection since it was dialed, the
// same as PgBouncer's server_lifetime.
//
// The regression this guards against is subtle and only shows up under
// load: if Release re-stamps createdAt, then a pool whose connections are
// constantly checked out and returned never sees an idle conn older than
// one release cycle, so max_lifetime never fires at all. That silently
// breaks the two things it exists for — retiring backends after a
// failover, and picking up rotated credentials.
func TestMaxLifetimeMeasuredFromDialNotRelease(t *testing.T) {
	var dials int32
	const lifetime = 40 * time.Millisecond
	p := New(fakeDialer(t, &dials), 1, nil, nil, WithMaxLifetime(lifetime))

	// Churn the single connection well past its lifetime, never letting
	// it sit idle long enough to expire between two adjacent acquires.
	deadline := time.Now().Add(4 * lifetime)
	for time.Now().Before(deadline) {
		c, err := p.Acquire(context.Background())
		if err != nil {
			t.Fatalf("acquire: %v", err)
		}
		p.Release(c)
		time.Sleep(lifetime / 8)
	}

	if got := atomic.LoadInt32(&dials); got < 2 {
		t.Fatalf("dials = %d, want >= 2: the connection was re-dialed on no "+
			"cycle, so max_lifetime never expired under churn", got)
	}
}

func TestDialRetryEventuallySucceeds(t *testing.T) {
	var attempts int32
	dial := func(ctx context.Context) (net.Conn, error) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			return nil, errors.New("transient")
		}
		client, server := net.Pipe()
		go io.Copy(io.Discard, server)
		return client, nil
	}
	p := New(dial, 1, nil, nil, WithDialRetry(5, 5*time.Millisecond))
	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire with retry: %v", err)
	}
	defer p.Release(c1)

	if attempts != 3 {
		t.Errorf("expected 3 dial attempts (2 fails + 1 success), got %d", attempts)
	}
}

func TestDialRetryHonorsContextCancellation(t *testing.T) {
	var attempts int32
	dial := func(ctx context.Context) (net.Conn, error) {
		atomic.AddInt32(&attempts, 1)
		return nil, errors.New("always fails")
	}
	p := New(dial, 1, nil, nil, WithDialRetry(10, 50*time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := p.Acquire(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestAcquireRespectsQueryWaitTimeout(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	defer p.Release(c1)

	// This is what relayImpl does under query_wait_timeout: pass a
	// bounded ctx so a saturated pool doesn't park the caller forever.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = p.Acquire(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if elapsed < 40*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Errorf("timeout not honored: elapsed=%v", elapsed)
	}
}

func TestStatsExposeWaiting(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}

	go func() {
		_, _ = p.Acquire(context.Background())
	}()

	// Give the second Acquire a moment to park.
	deadline := time.After(time.Second)
	for p.Stats().Waiting < 1 {
		select {
		case <-deadline:
			t.Fatalf("Stats().Waiting never reached 1; got %+v", p.Stats())
		case <-time.After(5 * time.Millisecond):
		}
	}

	p.Release(c1) // let the waiter finish
}
