package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPauseBlocksNewAcquiresUntilResume — Pause parks Acquire; Resume
// wakes every parked waiter in one broadcast; existing in-flight conns
// stay in flight and can be released normally throughout the pause.
func TestPauseBlocksNewAcquiresUntilResume(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 5, nil, nil)

	ctx := context.Background()

	// One conn in flight before pause — proves Pause doesn't disturb
	// active connections.
	inflight, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire pre-pause: %v", err)
	}

	p.Pause()
	if !p.IsPaused() {
		t.Fatal("IsPaused=false after Pause")
	}

	// Kick off N Acquires — all must block.
	const waiters = 4
	acquired := make(chan struct{}, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			c, err := p.Acquire(ctx)
			if err == nil {
				p.Release(c)
			}
			acquired <- struct{}{}
		}()
	}

	// Give them a moment to park, then confirm none escaped.
	time.Sleep(100 * time.Millisecond)
	select {
	case <-acquired:
		t.Fatal("Acquire returned during pause — should have blocked")
	default:
	}

	// Release in-flight during pause — must NOT unblock the paused
	// Acquires (they're waiting on resume, not the semaphore).
	p.Release(inflight)
	time.Sleep(50 * time.Millisecond)
	select {
	case <-acquired:
		t.Fatal("Acquire returned after Release-during-pause; should still wait for Resume")
	default:
	}

	// Resume — every waiter must complete quickly.
	p.Resume()
	if p.IsPaused() {
		t.Fatal("IsPaused=true after Resume")
	}
	deadline := time.After(2 * time.Second)
	for i := 0; i < waiters; i++ {
		select {
		case <-acquired:
		case <-deadline:
			t.Fatalf("only %d/%d waiters woke after Resume", i, waiters)
		}
	}
}

// TestPauseRespectsContextDeadline — a paused pool must still honor
// the caller's ctx timeout instead of parking forever.
func TestPauseRespectsContextDeadline(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)
	p.Pause()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.Acquire(ctx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Acquire returned in %s — should be ~50ms", elapsed)
	}
}

// TestDoublePauseIsIdempotent / TestDoubleResumeIsIdempotent
func TestDoublePauseAndResumeAreIdempotent(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)

	p.Pause()
	p.Pause() // must not deadlock or panic
	if !p.IsPaused() {
		t.Fatal("IsPaused after double Pause")
	}
	p.Resume()
	p.Resume() // must not deadlock or panic
	if p.IsPaused() {
		t.Fatal("IsPaused after double Resume")
	}

	// Sanity: pool works normally after the double-toggle cycle.
	ctx := context.Background()
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("post-cycle Acquire: %v", err)
	}
	p.Release(c)
}

// TestReconnectDrainsIdleImmediately — Reconnect() closes every idle
// conn right now, and reports how many it dropped.
func TestReconnectDrainsIdleImmediately(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 3, nil, nil)
	ctx := context.Background()

	// Populate idle with 3 distinct conns by acquiring all 3 first
	// (LIFO reuse would otherwise return the same conn on every
	// acquire-release cycle).
	var acquired []net.Conn
	for i := 0; i < 3; i++ {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		acquired = append(acquired, c)
	}
	for _, c := range acquired {
		p.Release(c)
	}

	dropped := p.Reconnect()
	if dropped != 3 {
		t.Fatalf("Reconnect dropped %d, want 3", dropped)
	}
	if got := p.Stats().Idle; got != 0 {
		t.Fatalf("idle after Reconnect = %d, want 0", got)
	}

	// Next Acquire must dial fresh — dial count grows past 3.
	before := atomic.LoadInt32(&dials)
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("post-reconnect acquire: %v", err)
	}
	after := atomic.LoadInt32(&dials)
	if after <= before {
		t.Fatalf("expected fresh dial after Reconnect; dials %d → %d", before, after)
	}
	p.Release(c)
}

// TestReconnectDiscardsInFlightOnRelease — a conn acquired BEFORE
// Reconnect is discarded when it comes back via Release, forcing a
// fresh dial on the next Acquire. Active transactions are not
// interrupted; they simply lose their backend on release.
func TestReconnectDiscardsInFlightOnRelease(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)
	ctx := context.Background()

	// Acquire — this conn now holds a slot and has gen=0.
	inflight, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	firstDials := atomic.LoadInt32(&dials)

	// Bump generation while conn is in flight.
	p.Reconnect()

	// Release: must NOT return to idle (stale generation).
	p.Release(inflight)
	if got := p.Stats().Idle; got != 0 {
		t.Fatalf("stale conn returned to idle: idle=%d, want 0", got)
	}

	// Next Acquire dials fresh.
	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("post-reconnect acquire: %v", err)
	}
	if got := atomic.LoadInt32(&dials); got != firstDials+1 {
		t.Fatalf("dial count %d, want %d", got, firstDials+1)
	}
	p.Release(c)
}

// TestReconnectWhilePausedIsSafe — the two ops don't interfere.
func TestReconnectWhilePausedIsSafe(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 3, nil, nil)
	ctx := context.Background()

	// Fill idle (acquire all first, then release, to get 3 distinct conns).
	var acquired []net.Conn
	for i := 0; i < 3; i++ {
		c, err := p.Acquire(ctx)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		acquired = append(acquired, c)
	}
	for _, c := range acquired {
		p.Release(c)
	}

	p.Pause()
	dropped := p.Reconnect()
	if dropped != 3 {
		t.Fatalf("Reconnect during pause: dropped %d, want 3", dropped)
	}
	p.Resume()

	c, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire after pause+reconnect+resume: %v", err)
	}
	p.Release(c)
}

// TestPauseResumeUnderConcurrentAcquires — repeated pause/resume with
// many goroutines contending. Failure = deadlock or lost wake-up.
func TestPauseResumeUnderConcurrentAcquires(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 8, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const workers = 20
	const iters = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	var errs atomic.Int64
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				c, err := p.Acquire(ctx)
				if err != nil {
					errs.Add(1)
					return
				}
				p.Release(c)
			}
		}()
	}

	// Toggle pause/resume rapidly.
	toggle := time.NewTicker(5 * time.Millisecond)
	defer toggle.Stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-toggle.C:
			p.Pause()
			time.Sleep(1 * time.Millisecond)
			p.Resume()
		}
	}

	if e := errs.Load(); e > 0 {
		t.Fatalf("%d Acquire errors under concurrent pause/resume", e)
	}
}
