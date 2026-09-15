package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// TestBackendPSCacheClearedBeforeAnotherSessionUsesIt is the regression
// for a cross-session statement mix-up.
//
// backendConn.preparedStmts is the only thing that makes
// ensureBackendHasStmt skip the lazy Parse. It used to be cleared solely
// inside the server_reset_query branch, so with that query disabled the
// record of session A's statements rode the pooled connection into
// session B. B's Bind for a colliding name — "stmtcache_1" and friends
// are picked by the driver, so collisions are the norm, not the
// exception — then found the backend "already knows" it, skipped the
// Parse, and ran A's SQL under B's identity.
//
// The clearing now happens when a different session adopts the
// connection rather than when the previous one lets go of it, so this
// asserts the guarantee at that boundary. Between the two the backend
// legitimately still carries A's statements: A owns them, and if A gets
// its own connection back the cache is still accurate.
//
// The test deliberately runs with server_reset_query disabled: that is
// the configuration the old code got wrong.
func TestBackendPSCacheClearedBeforeAnotherSessionUsesIt(t *testing.T) {
	backendClient, backendServer := net.Pipe()
	t.Cleanup(func() { backendClient.Close(); backendServer.Close() })
	backendPG := pgproto3.NewBackend(backendServer, backendServer)

	pooled := &backendConn{Conn: backendClient, addr: "fake", pid: 1, secretKey: secretBytes(2)}
	dial := func(context.Context) (net.Conn, error) { return pooled, nil }
	// limit 1: there is exactly one backend, so session B is guaranteed
	// to land on the connection session A just handed back.
	p := pool.New(dial, 1, nil, nil)

	pid, sessA := registerSession("a", "d")
	defer deregisterSession(pid)

	clientConn, proxyConn := net.Pipe()
	opts := defaultRuntimeOpts()
	opts.serverResetQuery = "" // the configuration under test

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		relayImpl(proxyConn, pgproto3.NewBackend(proxyConn, proxyConn), p, sessA, opts)
	}()

	// Script the backend: accept the Parse batch, end it with RFQ 'I'
	// so relay releases the connection back to the pool.
	go func() {
		for {
			msg, err := backendPG.Receive()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.Sync); !ok {
				continue
			}
			backendPG.Send(&pgproto3.ParseComplete{})
			backendPG.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backendPG.Flush(); err != nil {
				return
			}
		}
	}()

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	fe.Send(&pgproto3.Parse{Name: "stmtcache_1", Query: "SELECT 'session A secret'"})
	fe.Send(&pgproto3.Sync{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send parse batch: %v", err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break // the transaction is over; relay has released the backend
		}
	}

	_ = clientConn.Close()
	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not return")
	}

	// Take the recycled connection back out of the pool — this is
	// literally what session B's first Acquire does.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire the released backend: %v", err)
	}
	recycled, ok := conn.(*backendConn)
	if !ok {
		t.Fatalf("pool handed back %T, want *backendConn", conn)
	}
	if recycled.stateOwner == 0 {
		t.Fatal("the released backend is not tagged with its owner, so no handover can be detected")
	}

	// Session B adopts it, exactly as relayImpl does on acquire.
	sessB := &session{
		user: "b", database: "d", poolMode: "transaction",
		psCache: psCache{"stmtcache_1": &prepStmtInfo{SQL: "SELECT 'session B query'"}},
	}
	feB := pgproto3.NewFrontend(recycled, recycled)
	if err := adoptBackend(feB, recycled, sessB, opts); err != nil {
		t.Fatalf("adoptBackend: %v", err)
	}
	if n := len(recycled.preparedStmts); n != 0 {
		t.Fatalf("adopted backend still claims to know %d statement(s) from the previous session", n)
	}

	// The consequence that actually matters: session B, which has its
	// own "stmtcache_1" meaning something else entirely, must get its
	// own Parse prepended rather than inheriting A's.
	_, swallow := ensureBackendHasStmt(feB, recycled, sessB, "stmtcache_1",
		&pgproto3.Bind{PreparedStatement: "stmtcache_1"})
	if swallow != 1 {
		t.Error("session B's Bind was forwarded with no Parse prepended — it would have executed session A's statement")
	}
}
