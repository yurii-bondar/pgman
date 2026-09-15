package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

func TestFakeAuth(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	errCh := make(chan error, 1)
	wantSecret := secretBytes(99)
	go func() { errCh <- fakeAuth(pg, 42, wantSecret) }()

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	var sawOk, sawBackendKeyData bool
	var gotPID uint32
	var gotSecret []byte
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationOk:
			sawOk = true
		case *pgproto3.BackendKeyData:
			sawBackendKeyData = true
			// v5's SecretKey is []byte; take a copy because the Frontend
			// reuses its own decode buffer between Receive calls.
			gotPID = m.ProcessID
			gotSecret = append([]byte(nil), m.SecretKey...)
		case *pgproto3.ReadyForQuery:
			if m.TxStatus != 'I' {
				t.Errorf("expected TxStatus 'I', got %q", m.TxStatus)
			}
			goto done
		}
	}
done:
	if err := <-errCh; err != nil {
		t.Fatalf("fakeAuth: %v", err)
	}
	if !sawOk {
		t.Error("expected AuthenticationOk")
	}
	if !sawBackendKeyData {
		t.Error("expected BackendKeyData")
	}
	if gotPID != 42 || !bytes.Equal(gotSecret, wantSecret) {
		t.Errorf("got BackendKeyData{%d, %x}, want {42, %x}", gotPID, gotSecret, wantSecret)
	}
}

func TestReceiveStartupMessagePlain(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	go func() {
		buf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "x"}}).Encode(nil)
		clientConn.Write(buf)
	}()
	defer clientConn.Close()

	msg, conn, out, err := receiveStartupMessage(pg, serverConn, nil, 0)
	if err != nil {
		t.Fatalf("receiveStartupMessage: %v", err)
	}
	sm, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		t.Fatalf("expected *StartupMessage, got %T", msg)
	}
	if sm.Parameters["user"] != "x" {
		t.Errorf("got user=%q, want x", sm.Parameters["user"])
	}
	if conn != serverConn {
		t.Error("conn must be unchanged when no TLS upgrade happens")
	}
	if out == nil {
		t.Error("expected a non-nil Backend")
	}
}

func TestReceiveStartupMessageCancelRequest(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	go func() {
		buf, _ := (&pgproto3.CancelRequest{ProcessID: 5, SecretKey: secretBytes(6)}).Encode(nil)
		clientConn.Write(buf)
	}()
	defer clientConn.Close()

	msg, _, _, err := receiveStartupMessage(pg, serverConn, nil, 0)
	if err != nil {
		t.Fatalf("receiveStartupMessage: %v", err)
	}
	cr, ok := msg.(*pgproto3.CancelRequest)
	if !ok || cr.ProcessID != 5 || !bytes.Equal(cr.SecretKey, secretBytes(6)) {
		t.Errorf("got %#v, want CancelRequest{5, %x}", msg, secretBytes(6))
	}
}

func TestReceiveStartupMessageRejectsSSLWithoutConfig(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	clientResult := make(chan error, 1)
	go func() {
		buf, _ := (&pgproto3.SSLRequest{}).Encode(nil)
		if _, err := clientConn.Write(buf); err != nil {
			clientResult <- err
			return
		}
		resp := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, resp); err != nil {
			clientResult <- err
			return
		}
		if resp[0] != 'N' {
			clientResult <- fmt.Errorf("expected 'N', got %q", resp)
			return
		}
		buf2, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "y"}}).Encode(nil)
		if _, err := clientConn.Write(buf2); err != nil {
			clientResult <- err
			return
		}
		clientResult <- nil
	}()
	defer clientConn.Close()

	msg, conn, _, err := receiveStartupMessage(pg, serverConn, nil, 0)
	if err != nil {
		t.Fatalf("receiveStartupMessage: %v", err)
	}
	if err := <-clientResult; err != nil {
		t.Fatalf("client side: %v", err)
	}
	sm, ok := msg.(*pgproto3.StartupMessage)
	if !ok || sm.Parameters["user"] != "y" {
		t.Errorf("got %#v, want StartupMessage with user=y", msg)
	}
	if conn != serverConn {
		t.Error("conn must stay plaintext when tlsConfig is nil")
	}
}

func TestReceiveStartupMessageUpgradesTLS(t *testing.T) {
	cert := generateTestCert(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	clientDone := make(chan error, 1)
	go func() {
		buf, _ := (&pgproto3.SSLRequest{}).Encode(nil)
		if _, err := clientConn.Write(buf); err != nil {
			clientDone <- err
			return
		}
		resp := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, resp); err != nil {
			clientDone <- err
			return
		}
		if resp[0] != 'S' {
			clientDone <- fmt.Errorf("expected 'S', got %q", resp)
			return
		}

		tlsClient := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsClient.Handshake(); err != nil {
			clientDone <- err
			return
		}
		buf2, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "z"}}).Encode(nil)
		if _, err := tlsClient.Write(buf2); err != nil {
			clientDone <- err
			return
		}
		clientDone <- nil
	}()
	defer clientConn.Close()

	msg, conn, out, err := receiveStartupMessage(pg, serverConn, tlsConfig, 0)
	if err != nil {
		t.Fatalf("receiveStartupMessage: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client side: %v", err)
	}
	if _, ok := conn.(*tls.Conn); !ok {
		t.Errorf("expected conn to be upgraded to *tls.Conn, got %T", conn)
	}
	sm, ok := msg.(*pgproto3.StartupMessage)
	if !ok || sm.Parameters["user"] != "z" {
		t.Errorf("got %#v, want StartupMessage with user=z", msg)
	}
	if out == nil {
		t.Error("expected a non-nil rebuilt Backend over the TLS connection")
	}
}

func TestReceiveStartupMessageRejectsGSS(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)

	clientResult := make(chan error, 1)
	go func() {
		buf, _ := (&pgproto3.GSSEncRequest{}).Encode(nil)
		clientConn.Write(buf)
		resp := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, resp); err != nil {
			clientResult <- err
			return
		}
		if resp[0] != 'N' {
			clientResult <- fmt.Errorf("expected 'N', got %q", resp)
			return
		}
		buf2, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "g"}}).Encode(nil)
		clientConn.Write(buf2)
		clientResult <- nil
	}()
	defer clientConn.Close()

	_, _, _, err := receiveStartupMessage(pg, serverConn, nil, 0)
	if err != nil {
		t.Fatalf("receiveStartupMessage: %v", err)
	}
	if err := <-clientResult; err != nil {
		t.Fatalf("client side: %v", err)
	}
}

// fakeBackendResponder plays "real Postgres" on one end of a pipe: it lets
// a test script exactly what backend messages come back for whatever the
// code under test sends as a pgproto3.Frontend.
func fakeBackendResponder(t *testing.T) (client net.Conn, backendSide *pgproto3.Backend) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, pgproto3.NewBackend(b, b)
}

func TestHealthCheckSuccess(t *testing.T) {
	conn, backend := fakeBackendResponder(t)

	go func() {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = backend.Flush()
	}()

	if err := healthCheck(conn); err != nil {
		t.Fatalf("expected healthy, got: %v", err)
	}
}

func TestHealthCheckBackendError(t *testing.T) {
	conn, backend := fakeBackendResponder(t)

	go func() {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "backend is unwell"})
		_ = backend.Flush()
	}()

	if err := healthCheck(conn); err == nil {
		t.Fatal("expected an error when the backend returns ErrorResponse")
	}
}

func TestHealthCheckTimesOutOnDeadConnection(t *testing.T) {
	conn, _ := net.Pipe() // nobody ever reads/responds on the other end
	if err := healthCheck(conn); err == nil {
		t.Fatal("expected healthCheck to fail once its deadline passes")
	}
}

// relayHarness wires one fake client (talking pgproto3.Backend-role, as
// relay expects) to relay(), and one fake backend connection dialed
// through a real pool.Pool — the exact same shapes handleConn wires in
// production, just without a real Postgres or real TCP listener.
type relayHarness struct {
	t           *testing.T
	clientConn  net.Conn // test drives this side as "the client"
	fe          *pgproto3.Frontend
	pool        *pool.Pool
	backendSide *pgproto3.Backend // test scripts "real Postgres" responses here
	sess        *session
	relayDone   chan struct{}
}

func newRelayHarness(t *testing.T) *relayHarness {
	t.Helper()
	clientConn, proxyConn := net.Pipe()
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })

	dialed := false
	dial := func(context.Context) (net.Conn, error) {
		if dialed {
			return nil, fmt.Errorf("relayHarness only supports a single dial")
		}
		dialed = true
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 1, secretKey: secretBytes(2)}, nil
	}
	p := pool.New(dial, 1, nil, nil)

	pid, sess := registerSession("harness-user", "harness-db")
	t.Cleanup(func() { deregisterSession(pid) })

	pg := pgproto3.NewBackend(proxyConn, proxyConn)

	h := &relayHarness{
		t:           t,
		clientConn:  clientConn,
		fe:          pgproto3.NewFrontend(clientConn, clientConn),
		pool:        p,
		backendSide: pgproto3.NewBackend(backendServerSide, backendServerSide),
		sess:        sess,
		relayDone:   make(chan struct{}),
	}
	go func() {
		defer close(h.relayDone)
		relay(proxyConn, pg, p, sess)
	}()
	return h
}

func (h *relayHarness) waitPoolStats(t *testing.T, want func(pool.Stats) bool, msg string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		if want(h.pool.Stats()) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("%s (last stats: %+v)", msg, h.pool.Stats())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRelayReleasesBackendOnIdleReadyForQuery(t *testing.T) {
	h := newRelayHarness(t)

	go func() {
		msg, err := h.backendSide.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		h.backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		h.backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = h.backendSide.Flush()
	}()

	h.fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := h.fe.Flush(); err != nil {
		t.Fatalf("send query: %v", err)
	}
	msg, err := h.fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if _, ok := msg.(*pgproto3.CommandComplete); !ok {
		t.Fatalf("expected CommandComplete, got %T", msg)
	}
	msg, err = h.fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	rfq, ok := msg.(*pgproto3.ReadyForQuery)
	if !ok || rfq.TxStatus != 'I' {
		t.Fatalf("expected ReadyForQuery{I}, got %#v", msg)
	}

	h.waitPoolStats(t, func(s pool.Stats) bool { return s.InUse == 0 && s.Idle == 1 },
		"backend was never released back to the pool after TxStatus 'I'")

	h.fe.Send(&pgproto3.Terminate{})
	_ = h.fe.Flush()
	h.clientConn.Close()
	<-h.relayDone
}

func TestRelayKeepsBackendBetweenTransactionStatements(t *testing.T) {
	h := newRelayHarness(t)

	go func() {
		// BEGIN — stays in a transaction
		msg, err := h.backendSide.Receive()
		if err != nil || func() bool { _, ok := msg.(*pgproto3.Query); return !ok }() {
			return
		}
		h.backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
		h.backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
		_ = h.backendSide.Flush()

		// COMMIT — goes idle
		msg, err = h.backendSide.Receive()
		if err != nil || func() bool { _, ok := msg.(*pgproto3.Query); return !ok }() {
			return
		}
		h.backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("COMMIT")})
		h.backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = h.backendSide.Flush()
	}()

	h.fe.Send(&pgproto3.Query{String: "BEGIN"})
	_ = h.fe.Flush()
	h.fe.Receive() // CommandComplete
	h.fe.Receive() // ReadyForQuery T

	h.waitPoolStats(t, func(s pool.Stats) bool { return s.InUse == 1 },
		"backend must stay checked out while TxStatus is 'T'")

	h.fe.Send(&pgproto3.Query{String: "COMMIT"})
	_ = h.fe.Flush()
	h.fe.Receive()
	h.fe.Receive()

	h.waitPoolStats(t, func(s pool.Stats) bool { return s.InUse == 0 && s.Idle == 1 },
		"backend must be released once TxStatus returns to 'I'")

	h.fe.Send(&pgproto3.Terminate{})
	_ = h.fe.Flush()
	h.clientConn.Close()
	<-h.relayDone
}

func TestRelayTerminateMidTransactionDiscardsBackend(t *testing.T) {
	h := newRelayHarness(t)

	go func() {
		msg, err := h.backendSide.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		h.backendSide.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
		h.backendSide.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
		_ = h.backendSide.Flush()
	}()

	h.fe.Send(&pgproto3.Query{String: "BEGIN"})
	_ = h.fe.Flush()
	h.fe.Receive()
	h.fe.Receive()

	h.waitPoolStats(t, func(s pool.Stats) bool { return s.InUse == 1 }, "backend should be held mid-transaction")

	// Client vanishes mid-transaction instead of COMMIT/ROLLBACK — relay
	// must discard, never hand an open transaction to the next session.
	h.fe.Send(&pgproto3.Terminate{})
	_ = h.fe.Flush()
	h.clientConn.Close()
	<-h.relayDone

	h.waitPoolStats(t, func(s pool.Stats) bool { return s.InUse == 0 && s.Idle == 0 },
		"a backend abandoned mid-transaction must be discarded, not idled")
}

func TestRelayClientDisconnectWithoutTerminateEndsCleanly(t *testing.T) {
	h := newRelayHarness(t)
	// No backend ever acquired — client just vanishes before sending anything.
	h.clientConn.Close()

	select {
	case <-h.relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return after the client disconnected with no messages sent")
	}
	if s := h.pool.Stats(); s.InUse != 0 {
		t.Errorf("expected no backend ever acquired, got InUse=%d", s.InUse)
	}
}

// staticRouter is a test-only Router that always returns the same pool (or
// error) regardless of what the client asked for — exactly the seam Router
// being an interface exists for: handleConn can be driven end to end
// without a real PoolRegistry or real Postgres.
type staticRouter struct {
	p   *pool.Pool
	err error
}

func (r staticRouter) Route(*pgproto3.StartupMessage) (RouteDecision, error) {
	return RouteDecision{Pool: r.p}, r.err
}

type failingAuth struct{ err error }

func (a failingAuth) Authenticate(*pgproto3.Backend, net.Conn, *pgproto3.StartupMessage) error {
	return a.err
}

func TestHandleConnFullFlow(t *testing.T) {
	backendClientSide, backendServerSide := net.Pipe()
	t.Cleanup(func() { backendClientSide.Close(); backendServerSide.Close() })
	backendPG := pgproto3.NewBackend(backendServerSide, backendServerSide)

	dialed := false
	dial := func(context.Context) (net.Conn, error) {
		if dialed {
			return nil, fmt.Errorf("this test expects exactly one dial")
		}
		dialed = true
		return &backendConn{Conn: backendClientSide, addr: "fake", pid: 9, secretKey: secretBytes(9)}, nil
	}
	p := pool.New(dial, 1, nil, nil)
	router := staticRouter{p: p}

	clientConn, proxyConn := net.Pipe()
	limiter := newAuthLimiter()

	handleConnDone := make(chan struct{})
	go func() {
		defer close(handleConnDone)
		handleConn(proxyConn, router, TrustAuth{}, nil, limiter)
	}()

	go func() {
		msg, err := backendPG.Receive()
		if err != nil {
			return
		}
		if _, ok := msg.(*pgproto3.Query); !ok {
			return
		}
		backendPG.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		backendPG.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = backendPG.Flush()
	}()

	startupBuf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "alice", "database": "db1"}}).Encode(nil)
	if _, err := clientConn.Write(startupBuf); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	sawReady := false
	for i := 0; i < 10 && !sawReady; i++ {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive during auth: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			sawReady = true
		}
	}
	if !sawReady {
		t.Fatal("never saw ReadyForQuery after fake auth")
	}

	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send query: %v", err)
	}
	msg, err := fe.Receive()
	if err != nil || func() bool { _, ok := msg.(*pgproto3.CommandComplete); return !ok }() {
		t.Fatalf("expected CommandComplete, got %#v (err=%v)", msg, err)
	}
	msg, err = fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if rfq, ok := msg.(*pgproto3.ReadyForQuery); !ok || rfq.TxStatus != 'I' {
		t.Fatalf("expected ReadyForQuery{I}, got %#v", msg)
	}

	fe.Send(&pgproto3.Terminate{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send terminate: %v", err)
	}
	clientConn.Close()

	select {
	case <-handleConnDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return after Terminate")
	}
}

func TestHandleConnCancelRequest(t *testing.T) {
	addr, received := fakePostgresListener(t)
	pid, sess := registerSession("h", "db")
	defer deregisterSession(pid)
	sess.setBackend(&backendConn{addr: addr, pid: 3, secretKey: secretBytes(4)})

	clientConn, proxyConn := net.Pipe()
	limiter := newAuthLimiter()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(proxyConn, staticRouter{}, TrustAuth{}, nil, limiter)
	}()

	buf, _ := (&pgproto3.CancelRequest{ProcessID: pid, SecretKey: sess.secret}).Encode(nil)
	clientConn.Write(buf)
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return after CancelRequest")
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the fake backend to receive a forwarded CancelRequest")
	}
}

func TestHandleConnAuthRejected(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	limiter := newAuthLimiter()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(proxyConn, staticRouter{}, failingAuth{err: fmt.Errorf("bad password")}, nil, limiter)
	}()

	startupBuf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "x", "database": "y"}}).Encode(nil)
	clientConn.Write(startupBuf)

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "28P01" {
		t.Errorf("expected SQLSTATE 28P01, got %s", errResp.Code)
	}
	if strings.Contains(errResp.Message, "bad password") {
		t.Error("the real auth error must not leak to the client — only a generic message should")
	}
	clientConn.Close()
	<-done
}

func TestHandleConnRoutingRejected(t *testing.T) {
	clientConn, proxyConn := net.Pipe()
	limiter := newAuthLimiter()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(proxyConn, staticRouter{err: fmt.Errorf("no such database")}, TrustAuth{}, nil, limiter)
	}()

	startupBuf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "x", "database": "nope"}}).Encode(nil)
	clientConn.Write(startupBuf)

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	clientConn.Close()
	<-done
}

func TestHandleConnRateLimited(t *testing.T) {
	limiter := newAuthLimiter()
	clientConn, proxyConn := net.Pipe()
	host, _, _ := net.SplitHostPort(proxyConn.LocalAddr().String())
	for i := 0; i < authLockThreshold; i++ {
		limiter.RecordFailure(host)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConn(proxyConn, staticRouter{}, TrustAuth{}, nil, limiter)
	}()

	startupBuf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "x", "database": "y"}}).Encode(nil)
	clientConn.Write(startupBuf)

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok || !strings.Contains(errResp.Message, "too many failed authentication attempts") {
		t.Fatalf("expected lockout ErrorResponse, got %#v", msg)
	}
	clientConn.Close()
	<-done
}

func TestAcceptLoopStopsOnListenerClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		acceptLoop(ln, staticRouter{}, TrustAuth{}, nil, newAuthLimiter(), &wg)
	}()

	ln.Close()

	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not return after the listener was closed")
	}
	wg.Wait()
}

func TestAcceptLoopTracksHandleConnInWaitGroup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		acceptLoop(ln, staticRouter{err: fmt.Errorf("no pools")}, TrustAuth{}, nil, newAuthLimiter(), &wg)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startupBuf, _ := (&pgproto3.StartupMessage{ProtocolVersion: 196608, Parameters: map[string]string{"user": "x", "database": "y"}}).Encode(nil)
	conn.Write(startupBuf)
	conn.Close()

	ln.Close()
	<-loopDone
	wg.Wait() // must not hang — proves handleConn's goroutine was tracked and finished
}
