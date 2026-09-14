package main

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/yurii-bondar/pgman/pool"
)

// timeoutHarness is a minimal relay rig: a client pipe, a pool whose
// dialer is supplied by the caller, and a running relayImpl. Separate
// from relayHarness because these tests need to control the dialer and
// the runtimeOpts, which relayHarness fixes.
type timeoutHarness struct {
	client    net.Conn
	fe        *pgproto3.Frontend
	pool      *pool.Pool
	relayDone chan struct{}
}

func newTimeoutHarness(t *testing.T, dial pool.Dialer, limit int, opts *runtimeOpts) *timeoutHarness {
	t.Helper()

	p := pool.New(dial, limit, nil, nil)
	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })

	pid, sess := registerSession("timeout-user", "timeout-db")
	sess.poolName = "timeout-pool"
	t.Cleanup(func() { deregisterSession(pid) })

	h := &timeoutHarness{
		client:    clientConn,
		fe:        pgproto3.NewFrontend(clientConn, clientConn),
		pool:      p,
		relayDone: make(chan struct{}),
	}
	go func() {
		defer close(h.relayDone)
		relayImpl(proxyConn, pgproto3.NewBackend(proxyConn, proxyConn), p, sess, opts)
	}()
	return h
}

func (h *timeoutHarness) waitDone(t *testing.T, within time.Duration, what string) {
	t.Helper()
	select {
	case <-h.relayDone:
	case <-time.After(within):
		t.Fatalf("relay did not return: %s", what)
	}
}

// deadBackendDialer hands out a backend that accepts writes but never
// answers — the "server accepted my query and vanished" case.
func deadBackendDialer(t *testing.T) pool.Dialer {
	t.Helper()
	return func(context.Context) (net.Conn, error) {
		proxySide, serverSide := net.Pipe()
		// Drain whatever the proxy sends so writes don't block, but
		// never reply.
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, err := serverSide.Read(buf); err != nil {
					return
				}
			}
		}()
		t.Cleanup(func() { proxySide.Close(); serverSide.Close() })
		return &backendConn{Conn: proxySide, addr: "dead", pid: 1, secretKey: secretBytes(2)}, nil
	}
}

// TestClientIdleTimeoutClosesSilentSession: a client that connects and
// then says nothing must be reclaimed.
//
// In session pooling such a client holds its backend for as long as the
// socket survives, and with default OS keepalives that is hours after
// the peer is actually gone.
func TestClientIdleTimeoutClosesSilentSession(t *testing.T) {
	opts := defaultRuntimeOpts()
	opts.clientIdleTimeout = 80 * time.Millisecond

	h := newTimeoutHarness(t, deadBackendDialer(t), 1, opts)

	// Say nothing at all; just wait to be told to go away.
	msg, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "57P05" {
		t.Errorf("SQLSTATE = %s, want 57P05 (idle_session_timeout)", errResp.Code)
	}
	if errResp.Severity != "FATAL" {
		t.Errorf("severity = %q, want FATAL: the connection really is being closed", errResp.Severity)
	}

	h.waitDone(t, 2*time.Second, "client_idle_timeout did not end the session")
}

// TestClientIdleTimeoutDisabledByDefault guards the opt-in contract —
// a zero timeout must not start severing idle connections.
func TestClientIdleTimeoutDisabledByDefault(t *testing.T) {
	opts := defaultRuntimeOpts() // all timeouts zero

	h := newTimeoutHarness(t, deadBackendDialer(t), 1, opts)

	_ = h.client.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := h.fe.Receive()
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected no traffic from an idle relay, got err=%v", err)
	}
	_ = h.client.SetReadDeadline(time.Time{})

	select {
	case <-h.relayDone:
		t.Fatal("relay closed an idle session even though client_idle_timeout is disabled")
	default:
	}
}

// TestIdleTransactionTimeoutClosesSession: a client that leaves a
// transaction open and goes quiet is the worst kind of idle, because it
// pins a backend *and* whatever locks and snapshot that transaction has
// already taken.
func TestIdleTransactionTimeoutClosesSession(t *testing.T) {
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })
	backendSide := pgproto3.NewBackend(backendServerSide, backendServerSide)

	dial := func(context.Context) (net.Conn, error) {
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}

	opts := defaultRuntimeOpts()
	// Generous session timeout, tight in-transaction one, so a failure
	// can only be attributed to the timeout under test.
	opts.clientIdleTimeout = 10 * time.Second
	opts.idleTransactionTimeout = 80 * time.Millisecond

	h := newTimeoutHarness(t, dial, 1, opts)

	// Fake Postgres answers BEGIN and stays in a transaction.
	go func() {
		if _, err := backendSide.Receive(); err != nil {
			return
		}
		backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
		backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
		_ = backendSide.Flush()
	}()

	h.fe.Send(&pgproto3.Query{String: "BEGIN"})
	if err := h.fe.Flush(); err != nil {
		t.Fatalf("send BEGIN: %v", err)
	}

	// Drain to ReadyForQuery{T}, then deliberately go silent.
	for {
		msg, err := h.fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if rfq, ok := msg.(*pgproto3.ReadyForQuery); ok {
			if rfq.TxStatus != 'T' {
				t.Fatalf("TxStatus = %q, want 'T'", rfq.TxStatus)
			}
			break
		}
	}

	msg, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive after going idle in transaction: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "25P03" {
		t.Errorf("SQLSTATE = %s, want 25P03 (idle_in_transaction_session_timeout)", errResp.Code)
	}

	h.waitDone(t, 2*time.Second, "idle_transaction_timeout did not end the session")

	// The backend was mid-transaction, so it must have been discarded
	// rather than handed to the next client with open locks.
	if s := h.pool.Stats(); s.InUse != 0 || s.Idle != 0 {
		t.Errorf("pool stats = %+v, want the backend discarded (InUse=0, Idle=0)", s)
	}
}

// TestQueryTimeoutAbortsAndDiscardsBackend: a backend that accepts a
// query and never answers must not hold a pool slot indefinitely.
//
// Discarding rather than releasing is the load-bearing part: the
// statement is still running server-side, and closing the socket is what
// actually aborts it. Returning that connection to the idle stack would
// hand the next client a backend busy with someone else's query.
func TestQueryTimeoutAbortsAndDiscardsBackend(t *testing.T) {
	opts := defaultRuntimeOpts()
	opts.queryTimeout = 80 * time.Millisecond

	h := newTimeoutHarness(t, deadBackendDialer(t), 1, opts)

	h.fe.Send(&pgproto3.Query{String: "SELECT pg_sleep(3600)"})
	if err := h.fe.Flush(); err != nil {
		t.Fatalf("send: %v", err)
	}

	msg, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "57014" {
		t.Errorf("SQLSTATE = %s, want 57014 (query_canceled)", errResp.Code)
	}

	h.waitDone(t, 2*time.Second, "query_timeout did not end the session")

	s := h.pool.Stats()
	if s.InUse != 0 {
		t.Errorf("InUse = %d, want 0: the timed-out backend still holds a slot", s.InUse)
	}
	if s.Idle != 0 {
		t.Errorf("Idle = %d, want 0: a backend still executing a statement must never "+
			"be returned to the pool", s.Idle)
	}
	if s.Discards == 0 {
		t.Error("expected the timed-out backend to be counted as a discard")
	}
}

// TestQueryTimeoutDoesNotFireOnFastQuery is the other half of the
// contract: the deadline must be cleared on ReadyForQuery, not left on
// the connection where it would travel into the pool and make the next
// client's first read fail for no visible reason.
func TestQueryTimeoutDoesNotFireOnFastQuery(t *testing.T) {
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })
	backendSide := pgproto3.NewBackend(backendServerSide, backendServerSide)

	dial := func(context.Context) (net.Conn, error) {
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}

	opts := defaultRuntimeOpts()
	opts.queryTimeout = 5 * time.Second

	h := newTimeoutHarness(t, dial, 1, opts)

	go func() {
		for {
			if _, err := backendSide.Receive(); err != nil {
				return
			}
			backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backendSide.Flush(); err != nil {
				return
			}
		}
	}()

	// Two queries: the second one only succeeds if the first cleared
	// its deadline before releasing the connection.
	for i := 0; i < 2; i++ {
		h.fe.Send(&pgproto3.Query{String: "SELECT 1"})
		if err := h.fe.Flush(); err != nil {
			t.Fatalf("send query %d: %v", i, err)
		}
		for {
			msg, err := h.fe.Receive()
			if err != nil {
				t.Fatalf("query %d: %v (a stale read deadline leaked into the pool)", i, err)
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
	}
}

// TestCircuitOpenReportsRetryableBackendError checks how an open
// breaker reaches the client: a distinct SQLSTATE (08006, the backend
// is broken — not 53300, we are full) at severity ERROR so the session
// survives and the client can retry once the backend recovers.
func TestCircuitOpenReportsRetryableBackendError(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	p := pool.New(dial, 2, nil, nil, pool.WithCircuitBreaker(1, time.Hour))

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	pid, sess := registerSession("cb-user", "cb-db")
	defer deregisterSession(pid)

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		relayImpl(proxyConn, pgproto3.NewBackend(proxyConn, proxyConn), p, sess, defaultRuntimeOpts())
	}()

	// First query trips the breaker via a real dial failure.
	codes := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		fe.Send(&pgproto3.Query{String: "SELECT 1"})
		if err := fe.Flush(); err != nil {
			t.Fatalf("send query %d: %v", i, err)
		}
		var code string
		for {
			msg, err := fe.Receive()
			if err != nil {
				t.Fatalf("query %d: session died instead of reporting a retryable error: %v", i, err)
			}
			if e, ok := msg.(*pgproto3.ErrorResponse); ok {
				code = e.Code
				if e.Severity != "ERROR" {
					t.Errorf("query %d severity = %q, want ERROR", i, e.Severity)
				}
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
		codes = append(codes, code)
	}

	if codes[0] != "53300" {
		t.Errorf("first failure code = %s, want 53300 (dial failed, breaker not yet open)", codes[0])
	}
	if codes[1] != "08006" {
		t.Errorf("second failure code = %s, want 08006 (connection_failure, breaker open)", codes[1])
	}
	if !p.CircuitOpen() {
		t.Error("breaker should be open after the dial failure")
	}

	clientConn.Close()
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay never returned")
	}
}

// TestQueryDurationHistogramRecordsCompletedQueries covers the metric
// that the audit called out as missing: without it there is no p95/p99
// on query latency, which is the first number anyone asks for when the
// proxy is blamed for a slowdown.
func TestQueryDurationHistogramRecordsCompletedQueries(t *testing.T) {
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })
	backendSide := pgproto3.NewBackend(backendServerSide, backendServerSide)

	dial := func(context.Context) (net.Conn, error) {
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}

	reg := prometheus.NewRegistry()
	opts := defaultRuntimeOpts()
	opts.metrics = newProxyMetrics(reg)

	h := newTimeoutHarness(t, dial, 1, opts)

	go func() {
		for {
			if _, err := backendSide.Receive(); err != nil {
				return
			}
			backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backendSide.Flush(); err != nil {
				return
			}
		}
	}()

	const queries = 3
	for i := 0; i < queries; i++ {
		h.fe.Send(&pgproto3.Query{String: "SELECT 1"})
		if err := h.fe.Flush(); err != nil {
			t.Fatalf("send query %d: %v", i, err)
		}
		for {
			msg, err := h.fe.Receive()
			if err != nil {
				t.Fatalf("query %d: %v", i, err)
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var found bool
	for _, f := range families {
		if f.GetName() != "pgman_query_duration_seconds" {
			continue
		}
		found = true
		if len(f.GetMetric()) != 1 {
			t.Fatalf("expected one series (one pool), got %d", len(f.GetMetric()))
		}
		m := f.GetMetric()[0]
		if got := m.GetHistogram().GetSampleCount(); got != queries {
			t.Errorf("sample count = %d, want %d", got, queries)
		}
		labels := m.GetLabel()
		if len(labels) != 1 || labels[0].GetName() != "pool" || labels[0].GetValue() != "timeout-pool" {
			t.Errorf("labels = %v, want pool=timeout-pool", labels)
		}
	}
	if !found {
		t.Fatal("pgman_query_duration_seconds was never exported")
	}
}
