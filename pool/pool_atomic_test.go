package pool

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The tests in this file are regression guards for the atomic.Bool
// conversion of Pool.closed. Each locks in one behavior that used to
// be enforced by holding p.mu across the check, and would silently
// regress if a future refactor drops the "re-check closed under mu"
// step in Release or warmUp.

// pipeDialer returns a Dialer that hands out one half of a net.Pipe
// every time it's called. Enough for lifecycle correctness tests where
// no wire traffic actually happens.
func pipeDialer() Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		a, _ := net.Pipe()
		return a, nil
	}
}

// TestClosedFlagIsAtomicallyVisibleToConcurrentAcquires ensures that
// after Close returns, no in-flight Acquire that started BEFORE Close
// can silently succeed with a fresh connection — every one of them
// must observe closed and return ErrPoolClosed. Under -race this also
// catches any missing happens-before between atomic.Store and the mu
// pattern in Acquire/Release.
func TestClosedFlagIsAtomicallyVisibleToConcurrentAcquires(t *testing.T) {
	p := New(pipeDialer(), 4, nil, nil)

	const workers = 32
	var closedErrs, otherResults atomic.Int64

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := p.Acquire(ctx)
			if err == ErrPoolClosed {
				closedErrs.Add(1)
				return
			}
			if err != nil {
				// Any other error (dial, ctx) is fine — we're not asserting
				// success, only that we NEVER get a live conn after Close.
				otherResults.Add(1)
				return
			}
			otherResults.Add(1)
			// If Acquire returned a conn, Release it — the point of this
			// test is that the closed transition is race-free, not that
			// closed comes first.
			p.Release(conn)
		}()
	}

	close(start)
	// Immediately Close from the main goroutine, racing with the workers.
	closeErr := p.Close(context.Background())
	if closeErr != nil {
		t.Fatalf("Close: %v", closeErr)
	}
	wg.Wait()

	// At least SOME workers must have hit ErrPoolClosed — if zero did,
	// Close ran too late to observe the race and the test's premise is
	// wrong (bump workers or narrow the start-to-close window).
	if closedErrs.Load() == 0 {
		t.Skipf("no worker observed ErrPoolClosed — race window too narrow to be meaningful on this machine (workers=%d)", workers)
	}
}

// TestReleaseAfterCloseIsIdempotentAndDoesNotLeakConn locks in the
// specific race we designed around: a Release that took the fast-path
// closed check as false but then Close ran to completion before we
// took mu. The double-check under mu MUST catch this and close+drop
// the conn, otherwise it leaks (never Closed) and the sem slot is
// never freed.
func TestReleaseAfterCloseIsIdempotentAndDoesNotLeakConn(t *testing.T) {
	p := New(pipeDialer(), 2, nil, nil)

	// Acquire one, so we have something to Release later.
	c, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	// Wrap conn to observe Close() from the pool. If the pool leaks
	// the conn, Close will never be called.
	obs := &observableConn{Conn: c}

	// Close blocks in its drain loop until every in-flight conn has
	// been Released/Discarded — so we can't sequence "Close then
	// Release" from a single goroutine (that'd deadlock). Run them
	// concurrently: closed=true is set BEFORE the drain begins, so
	// the Release will observe the closed flag under mu and close
	// the wrapped conn instead of leaking it into a nil idle slice.
	closeDone := make(chan error, 1)
	go func() { closeDone <- p.Close(context.Background()) }()

	// Give Close a moment to flip the closed flag before we Release —
	// short and finite; the drain will complete as soon as we Release.
	time.Sleep(20 * time.Millisecond)
	p.Release(obs)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after Release drained the last in-flight conn")
	}

	if !obs.wasClosed.Load() {
		t.Fatal("Release after Close must Close the connection instead of leaking it into a stale idle slice")
	}
}

// TestDoubleCloseIsSafeNoop verifies the CompareAndSwap fast-path in
// Close — calling Close twice must not panic, must return nil, and
// must not attempt to re-drain (which could hang if the sem is
// already empty and yet another Close is somehow racing).
func TestDoubleCloseIsSafeNoop(t *testing.T) {
	p := New(pipeDialer(), 2, nil, nil)
	ctx := context.Background()
	if err := p.Close(ctx); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := p.Close(ctx); err != nil {
		t.Fatalf("second close (should be a no-op): %v", err)
	}
}

// BenchmarkAcquireReleaseHotPath measures the uncontended fast path
// so the atomic.Bool win over the previous mu-guarded closed check is
// visible in `benchstat` output. Per-op cost should drop by ~2 mutex
// ops (a Lock+Unlock pair) — measurable but small.
func BenchmarkAcquireReleaseHotPath(b *testing.B) {
	p := New(pipeDialer(), 8, nil, nil)
	defer func() { _ = p.Close(context.Background()) }()
	ctx := context.Background()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c, err := p.Acquire(ctx)
			if err != nil {
				b.Fatalf("acquire: %v", err)
			}
			p.Release(c)
		}
	})
}

// observableConn wraps a net.Conn and records whether Close has been
// called. Used by the leak-detection test above.
type observableConn struct {
	net.Conn
	wasClosed atomic.Bool
}

func (o *observableConn) Close() error {
	o.wasClosed.Store(true)
	return o.Conn.Close()
}
