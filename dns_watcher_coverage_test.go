package main

import (
	"testing"
	"time"
)

// TestStartDNSWatcherSeedsBeforeFirstTick covers the constructor the
// registry actually calls, and the seeding step inside it.
//
// Without the seed, lastIPs starts empty and the very first tick reads
// every address as new — so enabling dns_lookup_interval would bounce
// every pool once, throwing away all warm connections, at a moment
// nothing had changed. That is a self-inflicted latency spike right
// after startup, when the pool is already cold.
//
// The host is localhost on purpose: it resolves out of the system hosts
// file, so this exercises the real net.DefaultResolver path without a
// query leaving the machine, and it is an address that cannot change
// underneath the test.
func TestStartDNSWatcherSeedsBeforeFirstTick(t *testing.T) {
	p := idlePool(t)
	if s := p.Stats(); s.Idle != 1 {
		t.Fatalf("setup: Idle = %d, want 1", s.Idle)
	}

	stop := startDNSWatcher("test", "localhost:5432", p, 5*time.Millisecond)

	// Long enough for many ticks against a fixed address. Any reconnect
	// at all here is a spurious one.
	time.Sleep(150 * time.Millisecond)
	if s := p.Stats(); s.Idle != 1 {
		t.Errorf("Idle = %d, want 1: the watcher reconnected without an address change", s.Idle)
	}

	// The returned stop is the registry's only handle on the goroutine,
	// and it must join rather than merely signal — a pool removed from
	// the registry while its watcher is mid-Reconnect would otherwise
	// still be reachable through that watcher.
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() blocked — the watcher goroutine never exited")
	}
}

// TestStartDNSWatcherAcceptsHostWithoutPort: backend_addr is allowed to
// omit the port, and SplitHostPort fails on that form. Treating the
// failure as fatal instead of as "the whole string is the host" would
// leave those pools with no watcher and no message saying so.
func TestStartDNSWatcherAcceptsHostWithoutPort(t *testing.T) {
	p := idlePool(t)

	stop := startDNSWatcher("test", "localhost", p, 5*time.Millisecond)
	defer stop()

	time.Sleep(50 * time.Millisecond)
	if s := p.Stats(); s.Idle != 1 {
		t.Errorf("Idle = %d, want 1: a host-only addr was mis-parsed into a changing host", s.Idle)
	}
}
