package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/yurii-bondar/pgman/pool"
)

// scriptedResolver returns a different answer on each call, so a test
// can make an address change happen at a precise moment.
type scriptedResolver struct {
	mu      sync.Mutex
	answers [][]string
	errs    []error
	calls   int
}

func (r *scriptedResolver) LookupHost(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls
	r.calls++
	if i < len(r.errs) && r.errs[i] != nil {
		return nil, r.errs[i]
	}
	if i >= len(r.answers) {
		// Keep returning the last answer once the script runs out.
		i = len(r.answers) - 1
	}
	return append([]string(nil), r.answers[i]...), nil
}

func (r *scriptedResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// idlePool returns a pool holding one idle connection, so Reconnect has
// something observable to drop.
func idlePool(t *testing.T) *pool.Pool {
	t.Helper()
	p := pool.New(func(context.Context) (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { c.Close(); s.Close() })
		return c, nil
	}, 2, nil, nil)

	conn, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("seed acquire: %v", err)
	}
	p.Release(conn)
	return p
}

// startWatcher builds a watcher wired to a scripted resolver and starts
// its loop, mirroring what startDNSWatcher does for the real thing.
func startWatcher(t *testing.T, p *pool.Pool, r hostResolver, interval time.Duration, seed []string) *dnsWatcher {
	t.Helper()
	w := &dnsWatcher{
		poolName: "test",
		host:     "db.example.com",
		pool:     p,
		interval: interval,
		resolver: r,
		lastIPs:  seed,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go w.loop()
	t.Cleanup(w.stop)
	return w
}

func waitFor(t *testing.T, within time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestDNSWatcherReconnectsOnAddressChange is the whole point of the
// watcher: after a managed-database failover the DNS record flips, and
// every idle connection is still pointing at the demoted node.
func TestDNSWatcherReconnectsOnAddressChange(t *testing.T) {
	p := idlePool(t)
	if s := p.Stats(); s.Idle != 1 {
		t.Fatalf("setup: Idle = %d, want 1", s.Idle)
	}

	r := &scriptedResolver{answers: [][]string{{"10.0.0.2"}}}
	startWatcher(t, p, r, 10*time.Millisecond, []string{"10.0.0.1"})

	waitFor(t, 2*time.Second, func() bool { return p.Stats().Idle == 0 },
		"the watcher never dropped idle connections after the address changed")
}

// TestDNSWatcherIgnoresStableAddresses: a reconnect throws away every
// warm connection in the pool, so it must only happen on a real change.
// Firing every tick would mean the pool is permanently cold.
func TestDNSWatcherIgnoresStableAddresses(t *testing.T) {
	p := idlePool(t)

	r := &scriptedResolver{answers: [][]string{{"10.0.0.1"}}}
	startWatcher(t, p, r, 5*time.Millisecond, []string{"10.0.0.1"})

	// Let several ticks go by.
	waitFor(t, 2*time.Second, func() bool { return r.callCount() >= 4 },
		"the resolver was never polled")

	if s := p.Stats(); s.Idle != 1 {
		t.Errorf("Idle = %d, want 1: an unchanged record must not reconnect the pool", s.Idle)
	}
}

// TestDNSWatcherIgnoresAddressOrder guards against reconnect churn from
// round-robin DNS, which returns the same A records in a rotating order
// on every query.
func TestDNSWatcherIgnoresAddressOrder(t *testing.T) {
	p := idlePool(t)

	r := &scriptedResolver{answers: [][]string{
		{"10.0.0.2", "10.0.0.1"},
		{"10.0.0.1", "10.0.0.2"},
		{"10.0.0.2", "10.0.0.1"},
	}}
	// resolve() sorts, so the seed must be in sorted form too.
	startWatcher(t, p, r, 5*time.Millisecond, []string{"10.0.0.1", "10.0.0.2"})

	waitFor(t, 2*time.Second, func() bool { return r.callCount() >= 3 },
		"the resolver was never polled")

	if s := p.Stats(); s.Idle != 1 {
		t.Errorf("Idle = %d, want 1: reordered records are the same record set", s.Idle)
	}
}

// TestDNSWatcherSurvivesLookupFailure: a DNS blip must not be read as
// "all addresses disappeared" and trigger a pool bounce.
func TestDNSWatcherSurvivesLookupFailure(t *testing.T) {
	p := idlePool(t)

	r := &scriptedResolver{
		answers: [][]string{nil, nil, {"10.0.0.1"}},
		errs:    []error{errors.New("SERVFAIL"), errors.New("SERVFAIL"), nil},
	}
	startWatcher(t, p, r, 5*time.Millisecond, []string{"10.0.0.1"})

	waitFor(t, 2*time.Second, func() bool { return r.callCount() >= 3 },
		"the resolver was never polled")

	if s := p.Stats(); s.Idle != 1 {
		t.Errorf("Idle = %d, want 1: a failed lookup must be skipped, not treated as a change", s.Idle)
	}
}

// TestDNSWatcherStopIsDeterministic: stop must not return until the
// goroutine is gone, or a pool removed from the registry keeps a
// watcher alive holding a reference to it.
func TestDNSWatcherStopTerminatesLoop(t *testing.T) {
	// Built inline rather than via startWatcher: this test owns the
	// single call to stop() and must not have a cleanup call it too.
	w := &dnsWatcher{
		poolName: "test",
		host:     "db.example.com",
		pool:     idlePool(t),
		interval: time.Hour, // never ticks; only stop can end the loop
		resolver: &scriptedResolver{answers: [][]string{{"10.0.0.1"}}},
		lastIPs:  []string{"10.0.0.1"},
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go w.loop()

	done := make(chan struct{})
	go func() {
		w.stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() blocked — the watcher goroutine never exited")
	}

	// stop() waits on doneCh, so by here the loop has returned. A
	// watcher that outlived its pool would keep a removed pool alive.
	select {
	case <-w.doneCh:
	default:
		t.Error("stop() returned before the loop finished")
	}
}

// TestStartDNSWatcherSkipsWhenPointless covers the two cases where
// polling buys nothing: the feature is off, or the backend is an IP
// literal that cannot change.
func TestStartDNSWatcherSkipsWhenPointless(t *testing.T) {
	p := idlePool(t)

	cases := map[string]struct {
		addr     string
		interval time.Duration
	}{
		"disabled":     {"db.example.com:5432", 0},
		"ipv4 literal": {"10.0.0.1:5432", time.Millisecond},
		"ipv6 literal": {"[2001:db8::1]:5432", time.Millisecond},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stop := startDNSWatcher("test", tc.addr, p, tc.interval)
			time.Sleep(20 * time.Millisecond)
			stop() // must not block: no goroutine should have started
			if s := p.Stats(); s.Idle != 1 {
				t.Errorf("Idle = %d, want 1: no watcher should be running", s.Idle)
			}
		})
	}
}

func TestStringSlicesEqual(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{}, nil, true},
		{[]string{"a"}, []string{"a"}, true},
		{[]string{"a"}, []string{"b"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{"a", "b"}, []string{"b", "a"}, false}, // callers sort first
	}
	for _, tc := range cases {
		if got := stringSlicesEqual(tc.a, tc.b); got != tc.want {
			t.Errorf("stringSlicesEqual(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
