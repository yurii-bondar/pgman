package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// copyBothRig wires relayCopyBoth between two net.Pipe pairs and hands
// back the peer ends, so a test can play either the client or the
// backend — and, crucially, can play neither and leave a direction
// silent, which is the state a replication stream sits in most of the
// time.
type copyBothRig struct {
	clientPeer  net.Conn // the client's end of the client↔proxy pipe
	backendPeer net.Conn // the backend's end of the proxy↔backend pipe
	result      chan error
}

func startCopyBoth(t *testing.T) *copyBothRig {
	t.Helper()
	clientPeer, proxyClientSide := net.Pipe()
	proxyBackendSide, backendPeer := net.Pipe()
	t.Cleanup(func() {
		clientPeer.Close()
		proxyClientSide.Close()
		proxyBackendSide.Close()
		backendPeer.Close()
	})

	rig := &copyBothRig{
		clientPeer:  clientPeer,
		backendPeer: backendPeer,
		result:      make(chan error, 1),
	}
	go func() {
		rig.result <- relayCopyBoth(
			pgproto3.NewBackend(proxyClientSide, proxyClientSide),
			pgproto3.NewFrontend(proxyBackendSide, proxyBackendSide),
			proxyClientSide, proxyBackendSide,
		)
	}()
	return rig
}

func (r *copyBothRig) wait(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-r.result:
		return err
	case <-time.After(within):
		t.Fatalf("relayCopyBoth did not return within %v — a direction is still parked "+
			"in Receive, holding the backend connection and its pool slot", within)
		return nil
	}
}

// TestCopyBothReturnsWhenClientVanishes is the leak regression.
//
// Both pumps run without read deadlines on purpose: a walsender can
// idle for minutes between WAL records. So when the client disappears,
// the backend→client goroutine is parked in Receive on a stream that
// will never produce anything, and the unconditional second <-errCh
// waited for it forever. For CDC workloads (Debezium et al.) that is a
// leak per client reconnect, accumulating for the life of the process.
func TestCopyBothReturnsWhenClientVanishes(t *testing.T) {
	rig := startCopyBoth(t)

	// The backend is a healthy but quiet replication stream: nobody
	// reads or writes backendPeer for the rest of the test.
	_ = rig.clientPeer.Close()

	if err := rig.wait(t, 2*time.Second); err == nil {
		t.Error("expected the client-side failure to be reported, got nil")
	}
}

// TestCopyBothReturnsWhenBackendVanishes is the mirror image: the
// client is idle mid-stream and the backend dies. Without the drain the
// client→backend goroutine parks in Receive on a client with nothing to
// send, and the relay never unwinds to close the session.
func TestCopyBothReturnsWhenBackendVanishes(t *testing.T) {
	rig := startCopyBoth(t)

	_ = rig.backendPeer.Close()

	if err := rig.wait(t, 2*time.Second); err == nil {
		t.Error("expected the backend-side failure to be reported, got nil")
	}
}

// TestCopyBothReturnsWhenBackendNeverAcknowledgesCopyDone covers the
// path where nothing errors at all: the client ends the copy cleanly
// and the backend — wedged, not disconnected — never sends the
// CopyDone/CommandComplete/RFQ that would release the other pump. The
// grace period has to be bounded, not infinite.
func TestCopyBothReturnsWhenBackendNeverAcknowledgesCopyDone(t *testing.T) {
	orig := copyBothDrainGrace
	copyBothDrainGrace = 150 * time.Millisecond
	t.Cleanup(func() { copyBothDrainGrace = orig })

	rig := startCopyBoth(t)

	// Drain whatever the proxy forwards so the client→backend pump
	// isn't the thing that blocks.
	go func() {
		be := pgproto3.NewBackend(rig.backendPeer, rig.backendPeer)
		for {
			if _, err := be.Receive(); err != nil {
				return
			}
		}
	}()

	fe := pgproto3.NewFrontend(rig.clientPeer, rig.clientPeer)
	fe.Send(&pgproto3.CopyDone{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send CopyDone: %v", err)
	}

	// Clean end of the copy, so the reported outcome is nil even though
	// the backend never answered.
	if err := rig.wait(t, 2*time.Second); err != nil {
		t.Errorf("expected a clean nil outcome after the client's CopyDone, got %v", err)
	}
}

// TestCopyBothCompletesNormally keeps the happy path honest: the drain
// logic must not disturb a stream that ends the way the protocol says
// it should.
func TestCopyBothCompletesNormally(t *testing.T) {
	rig := startCopyBoth(t)

	// A backend that answers CopyDone the way a real walsender does.
	go func() {
		be := pgproto3.NewBackend(rig.backendPeer, rig.backendPeer)
		for {
			msg, err := be.Receive()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.CopyDone); !ok {
				continue
			}
			be.Send(&pgproto3.CopyDone{})
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("COPY 0")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		}
	}()

	// Consume what the proxy relays back so the backend→client pump
	// reaches its RFQ exit rather than blocking on an unread pipe.
	//
	// The client reports through a channel instead of the test polling
	// a buffered one: relayCopyBoth returns as soon as it has forwarded
	// the RFQ, which is before this goroutine has necessarily read it,
	// so a `len(ch) > 0` check here raced the pump and failed roughly
	// one run in four.
	clientDone := make(chan error, 1)
	go func() {
		fe := pgproto3.NewFrontend(rig.clientPeer, rig.clientPeer)
		fe.Send(&pgproto3.CopyDone{})
		if err := fe.Flush(); err != nil {
			clientDone <- fmt.Errorf("send CopyDone: %w", err)
			return
		}
		for {
			msg, err := fe.Receive()
			if err != nil {
				clientDone <- fmt.Errorf("the stream ended before ReadyForQuery: %w", err)
				return
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				clientDone <- nil
				return
			}
		}
	}()

	if err := rig.wait(t, 2*time.Second); err != nil {
		t.Fatalf("a clean CopyBoth exchange reported %v", err)
	}

	select {
	case err := <-clientDone:
		if err != nil {
			t.Errorf("the backend's ReadyForQuery never reached the client: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("the client is still waiting for the backend's ReadyForQuery")
	}
}
