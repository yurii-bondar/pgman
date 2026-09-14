package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func TestRegisterDeregisterSessionLifecycle(t *testing.T) {
	pid, sess := registerSession("alice", "backoffice")
	defer deregisterSession(pid)

	if sess.user != "alice" || sess.database != "backoffice" {
		t.Errorf("got user=%s database=%s, want alice/backoffice", sess.user, sess.database)
	}
	if len(sess.secret) == 0 || bytes.Equal(sess.secret, make([]byte, len(sess.secret))) {
		t.Error("secret must not be empty or all-zero (crypto/rand should never produce that reliably, but defend against a broken generator)")
	}

	// Post-sharding: look up through the same registry API the runtime
	// uses, instead of reaching into a shard's map directly. Keeps the
	// test coupled to behavior, not internal layout.
	if _, ok := lookupSession(pid); !ok {
		t.Fatal("session must be registered under its returned pid")
	}

	deregisterSession(pid)
	if _, ok := lookupSession(pid); ok {
		t.Fatal("session must be gone after deregisterSession")
	}
}

func TestRegisterSessionPIDsAreUnique(t *testing.T) {
	pid1, _ := registerSession("a", "db")
	defer deregisterSession(pid1)
	pid2, _ := registerSession("a", "db")
	defer deregisterSession(pid2)

	if pid1 == pid2 {
		t.Fatal("two sessions must never share a fake PID")
	}
}

func TestListSessionsReflectsActiveState(t *testing.T) {
	pid, sess := registerSession("bob", "game_rgs")
	defer deregisterSession(pid)

	find := func() (SessionInfo, bool) {
		for _, info := range listSessions() {
			if info.PID == pid {
				return info, true
			}
		}
		return SessionInfo{}, false
	}

	info, ok := find()
	if !ok {
		t.Fatal("registered session must appear in listSessions")
	}
	if info.Active {
		t.Error("a freshly registered session must start idle")
	}
	if info.User != "bob" || info.Database != "game_rgs" {
		t.Errorf("got user=%s database=%s, want bob/game_rgs", info.User, info.Database)
	}

	sess.setBackend(&backendConn{})
	info, ok = find()
	if !ok || !info.Active {
		t.Fatal("session must show Active after setBackend(non-nil)")
	}
	if info.TxStartedAt.IsZero() {
		t.Error("TxStartedAt must be set once a backend is held")
	}

	sess.setBackend(nil)
	info, ok = find()
	if !ok || info.Active {
		t.Fatal("session must show idle again after setBackend(nil)")
	}
	if !info.TxStartedAt.IsZero() {
		t.Error("TxStartedAt must be cleared once the backend is released")
	}
}

func TestCancelSessionUnknownPID(t *testing.T) {
	if err := cancelSession(999999999); err == nil {
		t.Fatal("expected error cancelling a pid that was never registered")
	}
}

func TestCancelSessionNoActiveBackend(t *testing.T) {
	pid, _ := registerSession("idle-user", "db")
	defer deregisterSession(pid)

	if err := cancelSession(pid); err == nil {
		t.Fatal("expected error cancelling a session with no in-flight transaction")
	}
}

// fakePostgresListener starts a local TCP listener that plays "real
// Postgres" just far enough to receive one raw CancelRequest frame and
// decode it — enough to prove sendRealCancelRequest/cancelSession dial the
// right address and encode the right bytes, without touching any real
// Postgres instance.
func fakePostgresListener(t *testing.T) (addr string, received chan *pgproto3.CancelRequest) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	received = make(chan *pgproto3.CancelRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		pg := pgproto3.NewBackend(conn, conn)
		msg, err := pg.ReceiveStartupMessage()
		if err != nil {
			return
		}
		if cr, ok := msg.(*pgproto3.CancelRequest); ok {
			received <- cr
		}
	}()
	return ln.Addr().String(), received
}

func TestCancelSessionSendsRealCancelRequest(t *testing.T) {
	addr, received := fakePostgresListener(t)

	pid, sess := registerSession("carol", "db")
	defer deregisterSession(pid)
	sess.setBackend(&backendConn{addr: addr, pid: 4242, secretKey: secretBytes(99887766)})

	if err := cancelSession(pid); err != nil {
		t.Fatalf("cancelSession: %v", err)
	}

	select {
	case cr := <-received:
		wantSecret := secretBytes(99887766)
		if cr.ProcessID != 4242 || !bytes.Equal(cr.SecretKey, wantSecret) {
			t.Errorf("got CancelRequest{PID:%d, Secret:%x}, want {4242, %x}", cr.ProcessID, cr.SecretKey, wantSecret)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake Postgres never received a CancelRequest")
	}
}

func TestHandleCancelRequestRejectsSecretMismatch(t *testing.T) {
	addr, received := fakePostgresListener(t)

	pid, sess := registerSession("dave", "db")
	defer deregisterSession(pid)
	sess.setBackend(&backendConn{addr: addr, pid: 1, secretKey: secretBytes(1)})

	// Wrong secret — must not forward a real cancel, exactly the property
	// that stops one client from cancelling another client's query.
	wrong := make([]byte, len(sess.secret))
	copy(wrong, sess.secret)
	// Flip the low byte so the bytes.Equal check in handleCancelRequest
	// fails without shortening or lengthening the slice.
	binary.BigEndian.PutUint32(wrong, binary.BigEndian.Uint32(wrong)+1)
	handleCancelRequest(&pgproto3.CancelRequest{ProcessID: pid, SecretKey: wrong})

	select {
	case <-received:
		t.Fatal("a CancelRequest with the wrong secret must never reach the real backend")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestHandleCancelRequestForwardsOnValidSecret(t *testing.T) {
	addr, received := fakePostgresListener(t)

	pid, sess := registerSession("erin", "db")
	defer deregisterSession(pid)
	sess.setBackend(&backendConn{addr: addr, pid: 7, secretKey: secretBytes(8)})

	handleCancelRequest(&pgproto3.CancelRequest{ProcessID: pid, SecretKey: sess.secret})

	select {
	case cr := <-received:
		wantSecret := secretBytes(8)
		if cr.ProcessID != 7 || !bytes.Equal(cr.SecretKey, wantSecret) {
			t.Errorf("got CancelRequest{PID:%d, Secret:%x}, want {7, %x}", cr.ProcessID, cr.SecretKey, wantSecret)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("valid CancelRequest was not forwarded to the real backend")
	}
}

func TestHandleCancelRequestUnknownPID(t *testing.T) {
	// Must not panic and must simply be a no-op for a pid nobody registered.
	handleCancelRequest(&pgproto3.CancelRequest{ProcessID: 123456789, SecretKey: secretBytes(1)})
}
