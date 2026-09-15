package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// TestRelayQueryWaitTimeoutSurfacesError covers two contracts at once.
//
// The first is the original one: with the pool saturated and a
// query_wait_timeout configured, Acquire must not block forever, or
// every waiting client leaks a goroutine and an FD until the process
// dies.
//
// The second is that the failure is reported as a *query* error, not a
// connection error. Severity ERROR followed by ReadyForQuery leaves the
// session usable, so a client that hits a momentarily full pool retries
// on the connection it already has. Answering with FATAL instead makes
// every application-side pool reconnect at once, which is the last
// thing a saturated proxy needs.
func TestRelayQueryWaitTimeoutSurfacesError(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		client, _ := net.Pipe()
		return &backendConn{Conn: client, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}
	p := pool.New(dial, 1, nil, nil)

	// Saturate: acquire the one slot and never release it.
	held, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire held: %v", err)
	}
	defer held.Close()

	clientConn, proxyConn := net.Pipe()
	pid, sess := registerSession("u", "d")
	defer deregisterSession(pid)

	pg := pgproto3.NewBackend(proxyConn, proxyConn)
	fe := pgproto3.NewFrontend(clientConn, clientConn)

	opts := defaultRuntimeOpts()
	opts.queryWaitTimeout = 100 * time.Millisecond

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		relayImpl(proxyConn, pg, p, sess, opts)
	}()

	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send: %v", err)
	}

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse (pool exhausted), got %T", msg)
	}
	if errResp.Code != "53300" {
		t.Errorf("expected SQLSTATE 53300 (too_many_connections), got %s", errResp.Code)
	}
	if errResp.Severity != "ERROR" {
		t.Errorf("severity = %q, want ERROR: a full pool is a retryable "+
			"condition, and FATAL triggers a client reconnect storm", errResp.Severity)
	}
	if !strings.Contains(errResp.Message, "no backend connection available") {
		t.Errorf("unexpected message %q", errResp.Message)
	}

	// ReadyForQuery must follow, or the client is left waiting forever
	// for a response that already happened.
	msg, err = fe.Receive()
	if err != nil {
		t.Fatalf("receive after error: %v", err)
	}
	rfq, ok := msg.(*pgproto3.ReadyForQuery)
	if !ok {
		t.Fatalf("expected ReadyForQuery after the error, got %T", msg)
	}
	if rfq.TxStatus != 'I' {
		t.Errorf("TxStatus = %q, want 'I'", rfq.TxStatus)
	}

	// The session is still alive: a second query gets the same treatment
	// rather than a closed socket.
	fe.Send(&pgproto3.Query{String: "SELECT 2"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send second query on a session that should have survived: %v", err)
	}
	if _, err := fe.Receive(); err != nil {
		t.Fatalf("second query got no response — the session was killed: %v", err)
	}

	clientConn.Close()
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay never returned after query_wait_timeout fired")
	}
}

// TestRelayRunsServerResetQueryBetweenTransactions proves DISCARD ALL
// (or whatever server_reset_query is) is issued to the backend before
// the pool re-hands it to the next client. Without this, session state
// from client A leaks into client B — a correctness bug and a PII leak
// vector at once.
// TestAcceptLoopEnforcesMaxClientConn is the regression for the "no
// max_client_conn" DoS surface. Once the semaphore is full, subsequent
// dials must be rejected fast rather than growing the goroutine pool
// unboundedly.
func TestAcceptLoopEnforcesMaxClientConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	opts := defaultRuntimeOpts()
	opts.setMaxClientConn(1)
	opts.clientLoginTimeout = time.Second // ensure our long-lived probe eventually dies

	var wg sync.WaitGroup
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		// Router error keeps handleConn short — but the very first
		// accepted conn stays open long enough to keep the semaphore
		// full because we never send it a startup message.
		acceptLoopWithOpts(ln, staticRouter{err: fmt.Errorf("no pools")}, TrustAuth{}, nil, newAuthLimiter(), &wg, opts)
	}()

	// First dial fills the single slot; we deliberately don't send a
	// startup so handleConn parks on ReceiveStartupMessage until the
	// client_login_timeout deadline fires.
	first, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer first.Close()

	// Give acceptLoop a moment to hand first off to a handler.
	time.Sleep(50 * time.Millisecond)

	// Second dial must be immediately dropped by acceptLoop because
	// max_client_conn=1 is full — we detect that by the socket being
	// closed as soon as we try to read.
	second, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	defer second.Close()

	second.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := second.Read(buf)
	if err == nil && n > 0 {
		t.Errorf("expected second conn to be closed (max_client_conn=1), but read %d byte(s)", n)
	}

	ln.Close()
	first.Close()
	<-loopDone
	wg.Wait()
}

// TestHandleConnClientLoginTimeoutFires closes a client_login_timeout
// hole: without a deadline on the startup handshake, a peer that opens
// TCP and stays silent ties up a goroutine + FD forever.
func TestHandleConnClientLoginTimeoutFires(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	opts := defaultRuntimeOpts()
	opts.clientLoginTimeout = 50 * time.Millisecond

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnWithOpts(proxyConn, staticRouter{}, TrustAuth{}, nil, newAuthLimiter(), opts)
	}()

	// Never send anything. handleConn must give up at the deadline.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not honor client_login_timeout — a silent client hangs forever")
	}
}

// writeCountingConn counts Write calls on the proxy→client socket. Each
// Write is one syscall in production, so the count is a direct proxy for
// the cost of relaying a result set.
type writeCountingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *writeCountingConn) Write(b []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(b)
}

// TestRelayBatchesRowsIntoOneClientWrite pins the batching contract on
// the backend→client path: a multi-row result set must reach the client
// in a small number of writes, not one per message.
//
// The regression it guards against is a Flush() after every pgproto3
// Send. That is invisible in a correctness test — the bytes are
// identical either way — and shows up only as syscall count, which is
// exactly what makes it worth asserting explicitly.
func TestRelayBatchesRowsIntoOneClientWrite(t *testing.T) {
	const rows = 200

	clientConn, rawProxyConn := net.Pipe()
	proxyConn := &writeCountingConn{Conn: rawProxyConn}
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })

	dial := func(context.Context) (net.Conn, error) {
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}
	p := pool.New(dial, 1, nil, nil)

	pid, sess := registerSession("batch-user", "batch-db")
	t.Cleanup(func() { deregisterSession(pid) })

	pg := pgproto3.NewBackend(proxyConn, proxyConn)
	fe := pgproto3.NewFrontend(clientConn, clientConn)
	backendSide := pgproto3.NewBackend(backendServerSide, backendServerSide)

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		relay(proxyConn, pg, p, sess)
	}()

	// Fake Postgres: one small row per message, then the terminators.
	// 200 rows of ~16 bytes stays well under clientFlushThreshold, so a
	// correct relay needs exactly one write for the whole response.
	go func() {
		if _, err := backendSide.Receive(); err != nil {
			return
		}
		backendSide.Send(&pgproto3.RowDescription{
			Fields: []pgproto3.FieldDescription{{Name: []byte("n"), DataTypeOID: 23}},
		})
		for i := 0; i < rows; i++ {
			backendSide.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}})
		}
		backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 200")})
		backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = backendSide.Flush()
	}()

	fe.Send(&pgproto3.Query{String: "SELECT n FROM generate_series(1,200) n"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send query: %v", err)
	}

	// Drain until ReadyForQuery so the assertion sees the full response.
	var seenRows int
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.DataRow); ok {
			seenRows++
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if seenRows != rows {
		t.Fatalf("client got %d DataRows, want %d — batching must not drop messages", seenRows, rows)
	}

	// net.Pipe hands each Write straight to the reader, so this counts
	// relay's flushes exactly. Allow a little slack for the harness, but
	// stay far below "one per message".
	const maxWrites = 5
	if got := proxyConn.writes.Load(); got > maxWrites {
		t.Errorf("relay issued %d writes for a %d-row result set, want <= %d "+
			"(a Flush per message is the regression this guards)", got, rows, maxWrites)
	}

	fe.Send(&pgproto3.Terminate{})
	_ = fe.Flush()
	clientConn.Close()
	<-relayDone
}

// TestRelayDrainingClosesIdleSessionInsteadOfBlocking pins the shutdown
// contract for a session that holds no backend: it must be told to go
// away, promptly.
//
// The regression this guards against is pausing the pools on SIGTERM.
// A paused pool makes Acquire block until Resume or query_wait_timeout
// (120s by default), which is longer than the whole shutdown budget
// (30s by default) — so the "graceful" path was guaranteed to blow past
// its deadline and force-exit with clients still parked.
func TestRelayDrainingClosesIdleSessionInsteadOfBlocking(t *testing.T) {
	dial := func(context.Context) (net.Conn, error) {
		client, _ := net.Pipe()
		return &backendConn{Conn: client, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}
	p := pool.New(dial, 1, nil, nil)

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()
	pid, sess := registerSession("drain-user", "drain-db")
	defer deregisterSession(pid)

	pg := pgproto3.NewBackend(proxyConn, proxyConn)
	fe := pgproto3.NewFrontend(clientConn, clientConn)

	opts := defaultRuntimeOpts()
	// Long enough that a blocking Acquire would clearly fail the test
	// rather than sneak past it as a slow success.
	opts.queryWaitTimeout = 30 * time.Second
	opts.draining.Store(true)

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		relayImpl(proxyConn, pg, p, sess, opts)
	}()

	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send: %v", err)
	}

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse while draining, got %T", msg)
	}
	if errResp.Code != "57P01" {
		t.Errorf("SQLSTATE = %s, want 57P01 (admin_shutdown) — drivers key their "+
			"reconnect behaviour off this code", errResp.Code)
	}

	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay blocked instead of releasing the session during drain")
	}

	if s := p.Stats(); s.InUse != 0 {
		t.Errorf("pool InUse = %d, want 0: a draining session must not take a backend", s.InUse)
	}
}
