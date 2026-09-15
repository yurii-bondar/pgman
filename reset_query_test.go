package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// resetHarness is one scripted backend behind a pool of limit 1, so
// every session in a test is guaranteed to land on the same connection.
// It records every simple Query the backend receives, which is how the
// tests below observe whether a scrub or a parameter replay happened.
type resetHarness struct {
	pool    *pool.Pool
	seen    chan string
	backend *backendConn
}

func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	proxySide, backendSide := net.Pipe()
	t.Cleanup(func() { proxySide.Close(); backendSide.Close() })

	h := &resetHarness{
		seen:    make(chan string, 32),
		backend: &backendConn{Conn: proxySide, addr: "fake", pid: 1, secretKey: secretBytes(2)},
	}
	h.pool = pool.New(func(context.Context) (net.Conn, error) { return h.backend, nil }, 1, nil, nil)

	go func() {
		be := pgproto3.NewBackend(backendSide, backendSide)
		for {
			msg, err := be.Receive()
			if err != nil {
				return
			}
			q, ok := msg.(*pgproto3.Query)
			if !ok {
				continue
			}
			h.seen <- q.String
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		}
	}()
	return h
}

// runTransaction drives one complete client transaction through
// relayImpl and returns once the backend has been released.
func (h *resetHarness) runTransaction(t *testing.T, sess *session, opts *runtimeOpts, sql string) {
	t.Helper()
	clientConn, proxyConn := net.Pipe()

	done := make(chan struct{})
	go func() {
		defer close(done)
		relayImpl(proxyConn, pgproto3.NewBackend(proxyConn, proxyConn), h.pool, sess, opts)
	}()

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	fe.Send(&pgproto3.Query{String: sql})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send %q: %v", sql, err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive after %q: %v", sql, err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return")
	}
}

// queries drains everything the backend has seen so far.
func (h *resetHarness) queries() []string {
	var out []string
	for {
		select {
		case q := <-h.seen:
			out = append(out, q)
		default:
			return out
		}
	}
}

func countQueries(queries []string, substr string) int {
	n := 0
	for _, q := range queries {
		if strings.Contains(q, substr) {
			n++
		}
	}
	return n
}

// TestResetQueryRunsWhenAnotherSessionTakesOver is the isolation
// guarantee. It no longer matters that the scrub happens on release —
// what matters is that no statement from a new session can reach a
// backend still carrying the previous one's state.
func TestResetQueryRunsWhenAnotherSessionTakesOver(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.healthCheckTimeout = 2 * time.Second

	pidA, sessA := registerSession("a", "d")
	defer deregisterSession(pidA)
	h.runTransaction(t, sessA, opts, "SELECT 'a'")

	pidB, sessB := registerSession("b", "d")
	defer deregisterSession(pidB)
	h.runTransaction(t, sessB, opts, "SELECT 'b'")

	queries := h.queries()
	if countQueries(queries, "DISCARD ALL") != 1 {
		t.Fatalf("expected exactly one DISCARD ALL on the handover, got %v", queries)
	}
	// Order is the whole point: the scrub has to precede the new
	// session's first statement, not merely occur somewhere.
	var discardAt, queryBAt = -1, -1
	for i, q := range queries {
		if strings.Contains(q, "DISCARD ALL") && discardAt < 0 {
			discardAt = i
		}
		if strings.Contains(q, "'b'") && queryBAt < 0 {
			queryBAt = i
		}
	}
	if discardAt < 0 || queryBAt < 0 || discardAt > queryBAt {
		t.Errorf("DISCARD ALL must precede the new session's query; got %v", queries)
	}
}

// TestResetQuerySkippedWhenSameSessionReusesBackend is the optimisation
// itself. A scrub between two transactions of the same session isolates
// that session from itself: it discards state the session owns and then
// the parameter replay puts it straight back, for two round trips of no
// benefit. With a LIFO pool that was the common case, not the rare one.
func TestResetQuerySkippedWhenSameSessionReusesBackend(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.resetSkipSameSession = true
	opts.healthCheckTimeout = 2 * time.Second

	pid, sess := registerSession("solo", "d")
	defer deregisterSession(pid)

	for i := 0; i < 3; i++ {
		h.runTransaction(t, sess, opts, "SELECT 1")
	}

	queries := h.queries()
	if n := countQueries(queries, "DISCARD ALL"); n != 0 {
		t.Errorf("one session reusing its own backend ran %d scrub(s): %v", n, queries)
	}
	if n := countQueries(queries, "SELECT 1"); n != 3 {
		t.Errorf("expected the 3 client queries to reach the backend, got %v", queries)
	}
}

// TestTrackedParamsReplayedOnlyOnHandover covers the second round trip
// the same-session skip removes: with track_extra_parameters on by
// default, every acquire used to re-SET application_name and friends,
// including when the connection came straight back from this session.
func TestTrackedParamsReplayedOnlyOnHandover(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.resetSkipSameSession = true
	opts.healthCheckTimeout = 2 * time.Second

	params := []trackedParam{{Name: "application_name", Value: "billing"}}

	pidA, sessA := registerSession("a", "d")
	defer deregisterSession(pidA)
	sessA.trackedParams = params
	h.runTransaction(t, sessA, opts, "SELECT 'a1'")
	h.runTransaction(t, sessA, opts, "SELECT 'a2'")

	queries := h.queries()
	if n := countQueries(queries, "application_name"); n != 1 {
		t.Errorf("params should be applied once for the session, not per transaction; got %v", queries)
	}

	// A different session must get its own replay — the scrub it just
	// ran wiped the previous owner's GUCs along with everything else.
	pidB, sessB := registerSession("b", "d")
	defer deregisterSession(pidB)
	sessB.trackedParams = []trackedParam{{Name: "application_name", Value: "reports"}}
	h.runTransaction(t, sessB, opts, "SELECT 'b'")

	queries = h.queries()
	if n := countQueries(queries, "reports"); n != 1 {
		t.Errorf("the new session's params were not replayed after the scrub; got %v", queries)
	}
}

// TestScrubRunsEveryHandoverByDefault pins the default: the skip is
// opt-in, so out of the box a session's own state is still discarded
// between its transactions exactly as it was before the option existed.
func TestScrubRunsEveryHandoverByDefault(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.resetSkipSameSession = false
	opts.healthCheckTimeout = 2 * time.Second

	pid, sess := registerSession("solo", "d")
	defer deregisterSession(pid)

	h.runTransaction(t, sess, opts, "SELECT 1")
	h.runTransaction(t, sess, opts, "SELECT 1")

	// One scrub, not two: the first transaction got a freshly dialed
	// connection, which has nobody's state to discard.
	if n := countQueries(h.queries(), "DISCARD ALL"); n != 1 {
		t.Errorf("by default the reuse must still be scrubbed, scrubs = %d", n)
	}
}

// TestResetQueryNotRunOnFreshBackend keeps the skip from costing a
// round trip where there was never anything to scrub.
func TestResetQueryNotRunOnFreshBackend(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.healthCheckTimeout = 2 * time.Second

	pid, sess := registerSession("first", "d")
	defer deregisterSession(pid)
	h.runTransaction(t, sess, opts, "SELECT 1")

	if n := countQueries(h.queries(), "DISCARD ALL"); n != 0 {
		t.Errorf("a freshly dialed backend carries nobody's state, but was scrubbed %d time(s)", n)
	}
}

// TestAnonymousSessionsNeverSkipTheScrub pins the fail-closed rule.
// Sessions built outside registerSession have id 0; if 0 were allowed
// to match a connection's stateOwner, two such sessions would hand each
// other an unscrubbed backend.
func TestAnonymousSessionsNeverSkipTheScrub(t *testing.T) {
	h := newResetHarness(t)
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "DISCARD ALL"
	opts.healthCheckTimeout = 2 * time.Second

	first := &session{user: "x", database: "d", poolMode: "transaction"}
	second := &session{user: "y", database: "d", poolMode: "transaction"}
	if first.id != 0 || second.id != 0 {
		t.Fatal("this test is meaningless unless both sessions have id 0")
	}

	h.runTransaction(t, first, opts, "SELECT 'x'")
	h.runTransaction(t, second, opts, "SELECT 'y'")

	if n := countQueries(h.queries(), "DISCARD ALL"); n != 1 {
		t.Errorf("an unidentified session must never inherit unscrubbed state; scrubs = %d", n)
	}
}
