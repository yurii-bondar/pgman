package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// TestClientWriteTimeoutUnblocksAStalledWrite is the whole point of the
// wrapper: without it a peer that has stopped reading parks the writing
// goroutine — and the backend connection it holds — until TCP gives up,
// which on Linux is on the order of fifteen minutes.
//
// net.Pipe is synchronous and unbuffered, so a write with no reader is
// exactly the "send buffer full, peer not draining it" condition,
// reachable without a real socket.
func TestClientWriteTimeoutUnblocksAStalledWrite(t *testing.T) {
	proxySide, clientSide := net.Pipe()
	defer proxySide.Close()
	defer clientSide.Close() // never read from

	w := newClientWriter(proxySide, 50*time.Millisecond)

	start := time.Now()
	_, err := w.Write([]byte("no one is reading this"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write to a stalled peer returned %v, want a deadline error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the write took %v to give up, so the deadline is not the thing that unblocked it", elapsed)
	}
}

// TestClientWriterClearsDeadlineAfterWrite: a deadline left armed would
// fire during an unrelated later write, which is the same class of bug
// as a leftover read deadline travelling with a pooled backend.
func TestClientWriterClearsDeadlineAfterWrite(t *testing.T) {
	proxySide, clientSide := net.Pipe()
	defer proxySide.Close()
	defer clientSide.Close()

	read := make(chan struct{})
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
			read <- struct{}{}
		}
	}()

	w := newClientWriter(proxySide, 50*time.Millisecond)
	if _, err := w.Write([]byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	<-read

	// Past the first deadline. A second write must arm its own, not
	// inherit an expired one.
	time.Sleep(80 * time.Millisecond)
	if _, err := w.Write([]byte("second")); err != nil {
		t.Fatalf("second write failed with %v — the first write's deadline was left armed", err)
	}
	<-read
}

// TestClientWriterDisabledReturnsConnUnchanged keeps the opt-out free:
// with no timeout configured, pgproto3 writes straight to the
// connection with no extra indirection on the hot path.
func TestClientWriterDisabledReturnsConnUnchanged(t *testing.T) {
	proxySide, clientSide := net.Pipe()
	defer proxySide.Close()
	defer clientSide.Close()

	for _, timeout := range []time.Duration{0, -time.Second} {
		if got := newClientWriter(proxySide, timeout); got != proxySide {
			t.Errorf("timeout %v: got %T, want the connection itself", timeout, got)
		}
	}
}

// TestSessionTimeoutDefaults: these used to default to zero, which is
// PgBouncer's default and reads as prudence, but left the shipped
// configuration with no ceiling on any of the ways a client can hold a
// backend without doing work.
func TestSessionTimeoutDefaults(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()

	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"query_timeout", cfg.QueryTimeout, defaultQueryTimeout},
		{"client_idle_timeout", cfg.ClientIdleTimeout, defaultClientIdleTimeout},
		{"idle_transaction_timeout", cfg.IdleTransactionTimeout, defaultIdleTransactionTimeout},
		{"client_write_timeout", cfg.ClientWriteTimeout, defaultClientWriteTimeout},
	} {
		if tc.got != tc.want {
			t.Errorf("%s default = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestSessionTimeoutsDisabledByNegativeValue: a deployment that
// genuinely has no ceiling — multi-hour reports through the proxy —
// must be able to say so, and the relay reads "disabled" as <= 0. A
// negative value is the only way to express it, since yaml cannot tell
// an explicit 0 from an unset field.
func TestSessionTimeoutsDisabledByNegativeValue(t *testing.T) {
	cfg := Config{
		QueryTimeout:           -1,
		ClientIdleTimeout:      -1,
		IdleTransactionTimeout: -1,
		ClientWriteTimeout:     -1,
	}
	cfg.applyDefaults()

	if cfg.QueryTimeout != -1 || cfg.ClientIdleTimeout != -1 ||
		cfg.IdleTransactionTimeout != -1 || cfg.ClientWriteTimeout != -1 {
		t.Errorf("an explicit opt-out was overwritten by defaults: %+v", cfg)
	}
}
