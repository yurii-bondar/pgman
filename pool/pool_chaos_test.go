package pool

// Concurrency chaos: every public entry point on one pool, from many
// goroutines, at once.
//
// The existing tests cover each operation carefully and in isolation —
// pause then acquire, reconnect then release, close while warming up.
// That is the right way to pin behaviour, and it is also the reason a
// whole class of bug survives it: the pool has several pieces of state
// that are guarded differently on purpose (an atomic for `closed`, a
// mutex for the idle stack, a second mutex for the pause channel,
// atomics for the breaker), and the interesting failures live in the
// gaps between them, not inside any one operation.
//
// So this file does not assert on outcomes of individual calls. Under
// chaos almost every outcome is legal: an Acquire may succeed, or fail
// closed, or fail paused, or fail with an open breaker. What it asserts
// is the handful of invariants that must hold no matter the
// interleaving, plus -race's own verdict, which is the real product
// here.

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chaosConn is a net.Conn that records whether it was closed, so the
// test can prove the pool never leaks or double-closes one.
type chaosConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *chaosConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// TestPoolUnderConcurrentChaos hammers one pool with every operation at
// once and checks what must survive it.
//
// The invariants:
//
//   - No data race. The -race detector is the point; everything below
//     is secondary.
//   - Never more than `limit` connections checked out at once. The
//     semaphore is the pool's one hard promise, and an accounting slip
//     under concurrency is how a pooler quietly overruns
//     max_connections on the database it is supposed to protect.
//   - No connection is closed twice, and every connection the pool
//     dialled is closed exactly once by the time Close returns. A leak
//     here is a file descriptor leak in production.
//   - Close terminates. A pool that cannot drain hangs shutdown, which
//     turns a rolling deploy into an outage.
func TestPoolUnderConcurrentChaos(t *testing.T) {
	const (
		limit    = 8
		workers  = 48
		duration = 2 * time.Second
	)

	var (
		dialed   sync.Mutex
		allConns []*chaosConn
		inFlight atomic.Int32
		maxSeen  atomic.Int32
	)

	dial := func(ctx context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		// The server end is never read from; closing it when the test
		// ends keeps the pipe from pinning memory.
		t.Cleanup(func() { _ = server.Close() })
		c := &chaosConn{Conn: client}
		dialed.Lock()
		allConns = append(allConns, c)
		dialed.Unlock()
		return c, nil
	}

	// A health check that fails sometimes, because "the idle connection
	// turned out to be dead" is a path with its own discard/retry
	// bookkeeping and it should be exercised alongside everything else.
	healthCheck := func(net.Conn) error {
		if rand.Intn(8) == 0 {
			return errors.New("chaos: pretend this connection is dead")
		}
		return nil
	}

	p := New(dial, limit, healthCheck, nil,
		WithIdleTimeout(15*time.Millisecond),
		WithMaxLifetime(40*time.Millisecond),
		WithHealthCheckDelay(5*time.Millisecond),
		WithCircuitBreaker(3, 20*time.Millisecond),
	)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Acquire/Release workers — the hot path.
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for {
				select {
				case <-stop:
					return
				default:
				}

				ctx, cancel := context.WithTimeout(context.Background(),
					time.Duration(rng.Intn(5)+1)*time.Millisecond)
				conn, err := p.Acquire(ctx)
				cancel()
				if err != nil {
					// Every error here is legitimate: closed, paused,
					// breaker open, or the caller's own deadline.
					continue
				}

				n := inFlight.Add(1)
				for {
					m := maxSeen.Load()
					if n <= m || maxSeen.CompareAndSwap(m, n) {
						break
					}
				}
				time.Sleep(time.Duration(rng.Intn(3)) * time.Millisecond)
				inFlight.Add(-1)

				// Mix the two return paths; a caller that discards is
				// as normal as one that releases.
				if rng.Intn(6) == 0 {
					p.Discard(conn)
				} else {
					p.Release(conn)
				}
			}
		}(i)
	}

	// Control-plane workers: the operations an admin triggers, which in
	// production arrive at arbitrary moments rather than between tests.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				// Leave the pool resumed so Close is not racing a pause
				// as well; Close handles it either way, but a hung test
				// is harder to read than a failed one.
				p.Resume()
				return
			case <-time.After(7 * time.Millisecond):
				p.Pause()
				time.Sleep(3 * time.Millisecond)
				p.Resume()
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(11 * time.Millisecond):
				p.Reconnect()
			}
		}
	}()

	// Stats and the readiness probe run on their own goroutines in the
	// real process (metrics scrape, /ready), so they are read
	// concurrently here too.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				_ = p.Stats()
				_ = p.CircuitOpen()
				_ = p.IsPaused()
			}
		}
	}()

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	closeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.Close(closeCtx); err != nil {
		t.Fatalf("Close did not drain: %v", err)
	}

	if got := maxSeen.Load(); got > limit {
		t.Errorf("%d connections were checked out at once, limit is %d", got, limit)
	}

	dialed.Lock()
	defer dialed.Unlock()
	if len(allConns) == 0 {
		t.Fatal("no connections were dialled — the chaos did not run")
	}
	var unclosed, doubleClosed int
	for _, c := range allConns {
		switch n := c.closes.Load(); {
		case n == 0:
			unclosed++
		case n > 1:
			doubleClosed++
		}
	}
	if unclosed > 0 {
		t.Errorf("%d of %d connections were never closed — that is a descriptor leak", unclosed, len(allConns))
	}
	if doubleClosed > 0 {
		t.Errorf("%d of %d connections were closed more than once", doubleClosed, len(allConns))
	}
	t.Logf("chaos survived: %d connections dialled, peak %d in flight (limit %d)",
		len(allConns), maxSeen.Load(), limit)
}

// TestPoolCloseRacesEveryOperation targets the shutdown boundary
// specifically.
//
// Close is the one operation that changes what every other operation is
// allowed to do, and it does it in two steps — an atomic store, then a
// critical section — which is precisely the shape that hides races. The
// test starts Close while the pool is fully busy and asserts the two
// things that must remain true afterwards: nothing hangs, and no
// connection survives.
func TestPoolCloseRacesEveryOperation(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		var (
			mu    sync.Mutex
			conns []*chaosConn
		)
		dial := func(ctx context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = server.Close() })
			c := &chaosConn{Conn: client}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			return c, nil
		}

		p := New(dial, 4, nil, nil, WithMinIdle(2))

		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				conn, err := p.Acquire(ctx)
				if err != nil {
					return
				}
				p.Release(conn)
			}()
		}
		wg.Add(3)
		go func() { defer wg.Done(); p.Pause() }()
		go func() { defer wg.Done(); p.Reconnect() }()
		go func() { defer wg.Done(); p.Resume() }()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := p.Close(ctx)
		cancel()
		wg.Wait()
		if err != nil {
			t.Fatalf("attempt %d: Close did not drain: %v", attempt, err)
		}

		mu.Lock()
		for _, c := range conns {
			if n := c.closes.Load(); n != 1 {
				t.Errorf("attempt %d: connection closed %d times, want exactly 1", attempt, n)
			}
		}
		mu.Unlock()
	}
}

// TestPauseAndResumeRaceDoesNotPanic is the regression for a panic that
// took the whole process down.
//
// Pause used to set the paused flag and only then swap the resume
// channel under pauseMu. In the window between those two steps a
// concurrent Resume would win its own compare-and-swap, read the
// previous resumeCh — already closed — and close it again. "close of
// closed channel" is not recoverable, and PAUSE and RESUME are both
// reachable from the admin API and the admin SQL console, so two
// operators during an incident, or one script that retries, could stop
// the proxy outright.
//
// Found by TestPoolCloseRacesEveryOperation, which fires Pause,
// Reconnect and Resume from separate goroutines. Pinned separately here
// because a chaos test that happens to catch a bug is not the same as a
// test that says what the bug was.
func TestPauseAndResumeRaceDoesNotPanic(t *testing.T) {
	for attempt := 0; attempt < 200; attempt++ {
		p := New(func(ctx context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			return client, nil
		}, 2, nil, nil)

		var wg sync.WaitGroup
		// Several of each, in both orders, so the interleaving that
		// matters is reached quickly rather than eventually.
		for i := 0; i < 4; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); p.Pause() }()
			go func() { defer wg.Done(); p.Resume() }()
		}
		wg.Wait()

		// Whatever the interleaving settled on, the pool must still be
		// usable: a pool left paused with nobody to resume it is a
		// quieter version of the same outage.
		p.Resume()
		if p.IsPaused() {
			t.Fatalf("attempt %d: pool stayed paused after a final Resume", attempt)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := p.Acquire(ctx)
		cancel()
		if err != nil {
			t.Fatalf("attempt %d: pool unusable after the race: %v", attempt, err)
		}
		p.Release(conn)

		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = p.Close(closeCtx)
		closeCancel()
	}
}
