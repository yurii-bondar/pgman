package main

import (
	"sync"
	"testing"
	"time"
)

func TestAuthLimiterAllowsUntilThreshold(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.1"

	for i := 0; i < authLockThreshold-1; i++ {
		if !l.Allowed(addr) {
			t.Fatalf("attempt %d: expected still allowed before threshold", i)
		}
		l.RecordFailure(addr)
	}
	if !l.Allowed(addr) {
		t.Fatal("should still be allowed exactly at threshold-1 failures recorded")
	}
}

func TestAuthLimiterLocksOutAtThreshold(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.2"

	for i := 0; i < authLockThreshold; i++ {
		l.RecordFailure(addr)
	}
	if l.Allowed(addr) {
		t.Fatal("expected lockout immediately after reaching authLockThreshold failures")
	}
}

func TestAuthLimiterLockoutExpires(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.3"

	for i := 0; i < authLockThreshold; i++ {
		l.RecordFailure(addr)
	}
	if l.Allowed(addr) {
		t.Fatal("expected lockout right after threshold")
	}

	// Force the lock to already be in the past instead of sleeping
	// authLockBase in a unit test — same effect, deterministic and instant.
	l.mu.Lock()
	l.state[addr].lockedUntil = time.Now().Add(-time.Second)
	l.mu.Unlock()

	if !l.Allowed(addr) {
		t.Fatal("expected access restored once lockedUntil is in the past")
	}
}

func TestAuthLimiterBackoffIncreasesWithRepeatedFailures(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.4"

	for i := 0; i < authLockThreshold; i++ {
		l.RecordFailure(addr)
	}
	l.mu.Lock()
	first := l.state[addr].lockedUntil
	l.mu.Unlock()

	// Keep failing (as if the lockout weren't enforced by the caller) and
	// confirm the backoff grows rather than staying flat.
	for i := 0; i < 3; i++ {
		l.RecordFailure(addr)
	}
	l.mu.Lock()
	later := l.state[addr].lockedUntil
	l.mu.Unlock()

	if !later.After(first) {
		t.Fatalf("expected lockout to extend further with more failures: first=%v later=%v", first, later)
	}
}

func TestAuthLimiterBackoffCapsAtMax(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.5"

	for i := 0; i < authLockThreshold+20; i++ {
		l.RecordFailure(addr)
	}
	l.mu.Lock()
	lockedUntil := l.state[addr].lockedUntil
	l.mu.Unlock()

	if max := time.Now().Add(authLockMax + time.Second); lockedUntil.After(max) {
		t.Fatalf("lockout duration must be capped at authLockMax, got lockedUntil=%v (cap+margin=%v)", lockedUntil, max)
	}
}

func TestAuthLimiterRecordSuccessClearsState(t *testing.T) {
	l := newAuthLimiter()
	const addr = "10.0.0.6"

	for i := 0; i < authLockThreshold; i++ {
		l.RecordFailure(addr)
	}
	if l.Allowed(addr) {
		t.Fatal("expected lockout before RecordSuccess")
	}

	l.RecordSuccess(addr)
	if !l.Allowed(addr) {
		t.Fatal("RecordSuccess must clear any lockout immediately")
	}

	l.mu.Lock()
	_, exists := l.state[addr]
	l.mu.Unlock()
	if exists {
		t.Error("RecordSuccess should remove the address's entry entirely, not just clear the lock")
	}
}

func TestAuthLimiterUnknownAddressIsAllowed(t *testing.T) {
	l := newAuthLimiter()
	if !l.Allowed("never-seen-before") {
		t.Fatal("an address with no history must be allowed")
	}
}

func TestAuthLimiterConcurrentUse(t *testing.T) {
	l := newAuthLimiter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := "concurrent"
			l.Allowed(addr)
			l.RecordFailure(addr)
			if i%2 == 0 {
				l.RecordSuccess(addr)
			}
		}(i)
	}
	wg.Wait()
}
