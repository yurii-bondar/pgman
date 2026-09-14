package main

import (
	"net"
	"testing"
	"time"
)

// TestRegisterSessionPIDsAreRandom is the regression for the pre-fix
// sequential-PID leak: with a monotonic counter starting at 1, an
// attacker probing low pids right after process startup could target
// exactly the first N sessions. crypto/rand-derived pids scatter across
// the full uint32 range instead.
func TestRegisterSessionPIDsAreRandom(t *testing.T) {
	const n = 100
	pids := make(map[uint32]struct{}, n)
	var low, high uint32 = ^uint32(0), 0

	for i := 0; i < n; i++ {
		pid, _ := registerSession("u", "d")
		defer deregisterSession(pid)
		pids[pid] = struct{}{}
		if pid < low {
			low = pid
		}
		if pid > high {
			high = pid
		}
	}

	if len(pids) != n {
		t.Fatalf("expected %d unique pids, got %d — pid allocator produced collisions", n, len(pids))
	}

	// If pids were monotonic, high - low ≈ n. Random uint32 pids should
	// spread out across most of the range — check the spread is at
	// least a couple of orders of magnitude beyond monotonic.
	spread := high - low
	if spread < uint32(n)*1000 {
		t.Errorf("pids look suspiciously monotonic: low=%d high=%d spread=%d (want much larger)", low, high, spread)
	}
}

func TestSendRealCancelRequestTimeoutOnUnreachable(t *testing.T) {
	// TEST-NET-3 (RFC 5737) — reserved, guaranteed unreachable.
	orig := cancelDialTimeout
	cancelDialTimeout = 200 * time.Millisecond
	t.Cleanup(func() { cancelDialTimeout = orig })

	start := time.Now()
	err := sendRealCancelRequest("203.0.113.1:65432", 1, secretBytes(2))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error dialing an unreachable address")
	}
	// Must not exceed the timeout by much — the fix is exactly this:
	// no more open-ended net.Dial. Allow generous slack for slow CI.
	if elapsed > 3*time.Second {
		t.Errorf("dial did not honor timeout: elapsed=%v", elapsed)
	}
}

// TestSendRealCancelRequestFast verifies the happy path still works
// with a real listener (paired with the timeout test above so the two
// paths of cancelDialTimeout don't drift silently).
func TestSendRealCancelRequestFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_, _ = conn.Read(buf) // discard whatever CancelRequest was sent
	}()

	if err := sendRealCancelRequest(ln.Addr().String(), 1, secretBytes(2)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fake backend never saw the cancel bytes")
	}
}
