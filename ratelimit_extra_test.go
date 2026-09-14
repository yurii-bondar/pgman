package main

import (
	"fmt"
	"testing"
)

// TestAuthLimiterBoundedLRUEvictsOldest is the regression for the
// pre-fix unbounded-map OOM vector under IP-rotation credential
// stuffing. Once capacity is reached, every new address must push out
// the least-recently-touched one.
func TestAuthLimiterBoundedLRUEvictsOldest(t *testing.T) {
	const cap = 3
	l := newAuthLimiterWithCapacity(cap)

	for i := 0; i < 5; i++ {
		l.RecordFailure(fmt.Sprintf("addr-%d", i))
	}

	if got := l.Size(); got != cap {
		t.Fatalf("expected size capped at %d, got %d", cap, got)
	}

	// addr-0 and addr-1 should have been evicted (oldest); addr-2..4
	// should still be tracked.
	if entry, ok := l.state["addr-0"]; ok {
		t.Errorf("addr-0 should have been evicted, still present: %+v", entry)
	}
	if _, ok := l.state["addr-4"]; !ok {
		t.Error("addr-4 (most recent) must still be tracked")
	}
}

// TestAuthLimiterAllowedTouchesLRU proves that repeated Allowed() calls
// for the same address rescue it from eviction — a chatty-but-legitimate
// caller shouldn't be pushed out just because they've been around a
// while.
func TestAuthLimiterAllowedTouchesLRU(t *testing.T) {
	const cap = 2
	l := newAuthLimiterWithCapacity(cap)

	l.RecordFailure("chatty")
	l.RecordFailure("stale")

	// Keep "chatty" fresh in the LRU by touching it.
	for i := 0; i < 5; i++ {
		l.Allowed("chatty")
	}

	// Push in a new one — "stale" (older by recency) must be the victim.
	l.RecordFailure("newcomer")

	if _, ok := l.state["stale"]; ok {
		t.Error("stale should have been evicted (LRU) — chatty was touched more recently")
	}
	if _, ok := l.state["chatty"]; !ok {
		t.Error("chatty should have survived — Allowed() touches must refresh LRU position")
	}
}
