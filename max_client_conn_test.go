package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestMaxClientConnIsSharedAcrossListeners is the regression for the
// cap being counted per accept loop.
//
// A pgman with unix_socket_dir set runs two accept loops, and each used
// to allocate its own semaphore from the same number — so the real
// ceiling was 2 × max_client_conn. Every file-descriptor and memory
// budget derived from that setting was half of what the process would
// actually do under load, which is the kind of error that only shows up
// when the box is already in trouble.
//
// Two TCP listeners stand in for TCP + Unix here: the sharing is a
// property of runtimeOpts, not of the socket family.
func TestMaxClientConnIsSharedAcrossListeners(t *testing.T) {
	opts := defaultRuntimeOpts()
	opts.setMaxClientConn(1)
	// A short login timeout bounds the parked probe connection so the
	// test can't hang if something goes wrong.
	opts.clientLoginTimeout = 2 * time.Second

	// Not waited on: the accept loops keep running until their
	// listeners close in cleanup, so a Wait here would race their
	// Add(1) — WaitGroup misuse the detector rightly flags. The
	// handlers unwind on their own via clientLoginTimeout.
	var wg sync.WaitGroup
	first := newRejectingListener(t, opts, &wg)
	second := newRejectingListener(t, opts, &wg)

	// Fill the single slot on the first listener. No startup message is
	// sent, so handleConn parks in ReceiveStartupMessage and holds it.
	held, err := net.Dial("tcp", first)
	if err != nil {
		t.Fatalf("dial first listener: %v", err)
	}
	defer held.Close()

	waitForAcceptedConn(t, opts)

	// The second listener must now find the semaphore full and hang up
	// immediately, rather than admitting a connection against a budget
	// of its own.
	probe, err := net.Dial("tcp", second)
	if err != nil {
		t.Fatalf("dial second listener: %v", err)
	}
	defer probe.Close()

	if err := expectClosedByPeer(probe, 2*time.Second); err != nil {
		t.Errorf("the second listener admitted a connection past max_client_conn=1: %v", err)
	}
}

// TestMaxClientConnUnlimited keeps the documented escape hatch honest —
// a non-positive cap must leave the semaphore nil, not create one of
// size zero, which would reject every single connection.
func TestMaxClientConnUnlimited(t *testing.T) {
	for _, n := range []int{0, -1} {
		opts := defaultRuntimeOpts()
		opts.setMaxClientConn(n)
		if opts.clientSlots != nil {
			t.Errorf("setMaxClientConn(%d) built a semaphore of capacity %d, want nil (unlimited)",
				n, cap(opts.clientSlots))
		}
	}
}

// newRejectingListener starts an accept loop whose router always fails,
// so any connection that does get admitted is disposed of quickly.
// Returns the address to dial.
func newRejectingListener(t *testing.T, opts *runtimeOpts, wg *sync.WaitGroup) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go acceptLoopWithOpts(ln, staticRouter{err: fmt.Errorf("no pools")},
		TrustAuth{}, nil, newAuthLimiter(), wg, opts)
	return ln.Addr().String()
}

// waitForAcceptedConn blocks until the shared semaphore shows a taken
// slot. Polling beats a sleep here: the handoff from Accept to the
// handler goroutine is fast but not instant, and a fixed sleep would
// either be flaky or slow.
func waitForAcceptedConn(t *testing.T, opts *runtimeOpts) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(opts.clientSlots) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the first listener never took its slot in the shared semaphore")
}

// expectClosedByPeer reports nil when conn is closed by the other side
// without sending anything — which is how acceptLoop rejects a
// connection over max_client_conn.
func expectClosedByPeer(conn net.Conn, within time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(within)); err != nil {
		return err
	}
	var buf [1]byte
	n, err := conn.Read(buf[:])
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return fmt.Errorf("expected EOF, got %w", err)
	}
	return fmt.Errorf("expected EOF, but the peer sent %d byte(s)", n)
}
