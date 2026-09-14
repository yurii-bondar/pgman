package main

import (
	"testing"
	"time"
)

func TestRateLimiter_NilIsNoop(t *testing.T) {
	var r *RateLimiter
	for i := 0; i < 1000; i++ {
		if !r.Allow("x") {
			t.Fatal("nil limiter must always allow")
		}
	}
}

func TestRateLimiter_ZeroConfigReturnsNil(t *testing.T) {
	if NewRateLimiter(0, 5) != nil {
		t.Fatal("rate=0 should return nil (disabled)")
	}
	if NewRateLimiter(5, 0) != nil {
		t.Fatal("burst=0 should return nil (disabled)")
	}
}

func TestRateLimiter_BurstThenRefuse(t *testing.T) {
	r := NewRateLimiter(1, 3) // 1/sec, burst 3
	// First 3 in the burst should pass instantly.
	for i := 0; i < 3; i++ {
		if !r.Allow("alice") {
			t.Fatalf("Allow #%d should pass in burst window", i+1)
		}
	}
	// 4th should be refused (no refill yet).
	if r.Allow("alice") {
		t.Fatal("4th Allow should be refused (bucket empty)")
	}
	// Different key has its own bucket.
	if !r.Allow("bob") {
		t.Fatal("different user's bucket should be independent")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	r := NewRateLimiter(100, 1) // 100/sec, burst 1 → refills fast
	if !r.Allow("k") {
		t.Fatal("first token should pass")
	}
	if r.Allow("k") {
		t.Fatal("second immediate token should fail (burst=1)")
	}
	// Wait for 2 tokens' worth of refill = 20ms.
	time.Sleep(30 * time.Millisecond)
	if !r.Allow("k") {
		t.Fatal("after refill window Allow should pass")
	}
}
