package main

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// sslRequestPeer returns one end of a pipe whose far end consumes the
// 8-byte SSLRequest frame, answers with reply if there is one, and then
// hangs up. Models the three ways a backend can fail a cancel
// connection's TLS negotiation without needing a real server.
func sslRequestPeer(t *testing.T, reply []byte) net.Conn {
	t.Helper()
	near, far := net.Pipe()
	t.Cleanup(func() { _ = near.Close() })

	go func() {
		defer func() { _ = far.Close() }()
		var req [8]byte
		if _, err := io.ReadFull(far, req[:]); err != nil {
			return
		}
		if len(reply) > 0 {
			_, _ = far.Write(reply)
		}
	}()
	return near
}

// TestActiveSessionPoolKeysSeesSessionsHoldingNoConnection is the
// property the pass-through reaper depends on. A session between
// transactions owns no backend connection, so pool statistics show its
// pool as idle and eligible for eviction — but the session still holds
// the *pool.Pool and its next Acquire would fail fatally. Reading
// ownership from the session registry instead of from connection counts
// is what keeps an idle-but-live client from being killed by the
// reaper.
func TestActiveSessionPoolKeysSeesSessionsHoldingNoConnection(t *testing.T) {
	pid, sess := registerSession("alice", "shop")
	defer deregisterSession(pid)
	sess.poolName = "shop/alice"

	keys := activeSessionPoolKeys()
	if !keys["shop/alice"] {
		t.Errorf("pool %q is held by a live session but was not reported: %v", "shop/alice", keys)
	}
}

// TestActiveSessionPoolKeysSkipsUnroutedSessions: a session is in the
// registry from the moment it is created, before routing has picked a
// pool for it. Reporting its empty pool name would put "" in the set
// the reaper checks against, which matches no pool and would just be
// noise — but a reaper that ever compared the other way round would
// then spare everything.
func TestActiveSessionPoolKeysSkipsUnroutedSessions(t *testing.T) {
	pid, _ := registerSession("bob", "shop")
	defer deregisterSession(pid)

	if activeSessionPoolKeys()[""] {
		t.Error("a session with no pool name contributed an empty key")
	}
}

// TestActiveSessionPoolKeysCollapsesSharedPools: aliases and
// backend_users mean several sessions legitimately share one registry
// key, and the reaper wants the set of pools in use, not a count. Two
// sessions on one pool must not look different from one.
func TestActiveSessionPoolKeysCollapsesSharedPools(t *testing.T) {
	pid1, sess1 := registerSession("alice", "shop")
	defer deregisterSession(pid1)
	pid2, sess2 := registerSession("bob", "shop")
	defer deregisterSession(pid2)
	sess1.poolName = "shared"
	sess2.poolName = "shared"

	if !activeSessionPoolKeys()["shared"] {
		t.Error("a pool held by two sessions was not reported")
	}
}

// TestHandleCancelRequestSurvivesFailedForwarding: a CancelRequest is
// fire-and-forget by protocol, and it races the query it means to stop
// — by the time it arrives the transaction has often already committed
// and the backend gone back to the pool. That race is the normal case,
// not an error, so it must cost a log line and nothing else. Panicking
// here would let any client kill the proxy by cancelling twice.
func TestHandleCancelRequestSurvivesFailedForwarding(t *testing.T) {
	pid, sess := registerSession("carol", "shop")
	defer deregisterSession(pid)

	// Authentic secret, no backend: exactly the state a session is in
	// between transactions.
	handleCancelRequest(&pgproto3.CancelRequest{ProcessID: pid, SecretKey: sess.secret})

	if _, ok := lookupSession(pid); !ok {
		t.Error("the session was torn down by a cancel it could not serve")
	}
}

// TestStartCancelTLSFailsClosedOnEveryNegotiationFault: each of these
// is a connection the cancel can no longer safely travel on, and the
// only alternative to returning an error is sending the cancel key in
// the clear. Silently succeeding would also hand sendRealCancelRequest
// a nil stream to write to, turning a lost cancel into a crash.
func TestStartCancelTLSFailsClosedOnEveryNegotiationFault(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // no real peer to verify

	t.Run("cannot send SSLRequest", func(t *testing.T) {
		near, far := net.Pipe()
		_ = near.Close()
		_ = far.Close()

		conn, err := startCancelTLS(near, cfg)
		if err == nil {
			t.Fatal("a dead connection accepted an SSLRequest")
		}
		if conn != nil {
			t.Error("a usable stream came back with the error")
		}
	})

	t.Run("no reply to SSLRequest", func(t *testing.T) {
		conn, err := startCancelTLS(sslRequestPeer(t, nil), cfg)
		if err == nil {
			t.Fatal("a backend that hung up without answering was treated as ready")
		}
		if conn != nil {
			t.Error("a usable stream came back with the error")
		}
	})

	t.Run("handshake fails after acceptance", func(t *testing.T) {
		// Says 'S' and then goes away: the verdict byte is not proof
		// the handshake will complete, and a half-open TLS conn must
		// not be handed back as if it were.
		conn, err := startCancelTLS(sslRequestPeer(t, []byte{'S'}), cfg)
		if err == nil {
			t.Fatal("a failed handshake was reported as success")
		}
		if conn != nil {
			t.Error("a usable stream came back with the error")
		}
	})
}

// TestSendRealCancelRequestPropagatesTLSFailure ties the layer above to
// the one below: when negotiation fails the cancel has to be abandoned,
// not retried in plaintext, and the caller has to learn about it rather
// than believing the cancel went out.
func TestSendRealCancelRequestPropagatesTLSFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accepts and immediately hangs up, so the SSLRequest gets no
	// verdict byte.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	done := make(chan error, 1)
	go func() {
		done <- sendRealCancelRequest(ln.Addr().String(), 1, secretBytes(2),
			&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // no real peer to verify
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancel whose TLS negotiation failed was reported as sent")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sendRealCancelRequest never returned")
	}
}
