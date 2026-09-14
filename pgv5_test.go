package main

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

func goTypeString(v interface{}) string { return fmt.Sprintf("%T", v) }

// These tests guard the exact behaviors that CHANGED between pgproto3
// v2 and v5, so a future accidental revert (or a bad merge that mixes
// v2/v5 usage) surfaces here before it corrupts a real client's wire
// stream.
//
// v2 → v5 semantic differences we lock in below:
//   1. NewFrontend/NewBackend take io.Reader + io.Writer directly (no
//      external ChunkReader). Passing the same net.Conn twice is
//      idiomatic — nothing needs an external chunk-reader anymore.
//   2. Send() is BUFFERED. It returns nothing. The message does NOT
//      reach the peer until Flush() is called. A Send-without-Flush
//      pattern would silently deadlock the peer on a net.Pipe. This
//      test proves the buffered semantics AND that Flush actually
//      moves bytes.
//   3. CancelRequest.SecretKey (and BackendKeyData.SecretKey) is
//      []byte, not uint32 — because Postgres 18 lengthened the cancel
//      key. Comparisons must use bytes.Equal, not ==.

// pipeBackendFrontend wires a pgproto3 Backend (server side) to a
// Frontend (client side) over an in-memory net.Pipe — no OS sockets,
// no buffering surprises, ideal for testing exact wire behavior.
func pipeBackendFrontend(t *testing.T) (server *pgproto3.Backend, client *pgproto3.Frontend, closeAll func()) {
	t.Helper()
	sc, cc := net.Pipe()
	server = pgproto3.NewBackend(sc, sc)
	client = pgproto3.NewFrontend(cc, cc)
	return server, client, func() {
		_ = sc.Close()
		_ = cc.Close()
	}
}

// TestV5SendIsBufferedUntilFlush proves the v5 semantic change:
// Send() alone puts nothing on the wire. Verified by having the peer
// try to Receive with a very short deadline — it must fail (nothing
// arrived), then after Flush() the same Receive on a fresh deadline
// must succeed.
func TestV5SendIsBufferedUntilFlush(t *testing.T) {
	server, client, closeAll := pipeBackendFrontend(t)
	defer closeAll()

	// Server queues one message but does NOT flush. A pipe reader will
	// block indefinitely — we bound the wait with a channel-select.
	server.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	received := make(chan pgproto3.BackendMessage, 1)
	go func() {
		m, err := client.Receive()
		if err != nil {
			return
		}
		received <- m
	}()

	select {
	case m := <-received:
		t.Fatalf("Send() alone must NOT reach the peer in v5, but got: %#v", m)
	case <-time.After(80 * time.Millisecond):
		// Correct: nothing arrived. Now Flush and expect it to arrive.
	}

	if err := server.Flush(); err != nil {
		t.Fatalf("Flush after Send: %v", err)
	}
	select {
	case m := <-received:
		if _, ok := m.(*pgproto3.ReadyForQuery); !ok {
			t.Fatalf("after Flush wanted ReadyForQuery, got %#v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Flush() did not move the buffered message to the peer")
	}
}

// TestV5MultipleSendsCoalesceInOneFlush proves that Send() batching
// works the way the relay hot path relies on it: several messages
// buffered, then a single Flush drives them all to the wire in order.
// If a future refactor accidentally flushes per-Send, this test still
// passes (semantics are unchanged) — but it locks in ORDER and
// completeness, which is what actually matters for wire correctness.
func TestV5MultipleSendsCoalesceInOneFlush(t *testing.T) {
	server, client, closeAll := pipeBackendFrontend(t)
	defer closeAll()

	go func() {
		server.Send(&pgproto3.AuthenticationOk{})
		server.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
		server.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{0xDE, 0xAD, 0xBE, 0xEF}})
		server.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = server.Flush()
	}()

	// Exactly four messages, in exactly this order.
	want := []string{"*pgproto3.AuthenticationOk", "*pgproto3.ParameterStatus", "*pgproto3.BackendKeyData", "*pgproto3.ReadyForQuery"}
	for i, name := range want {
		m, err := client.Receive()
		if err != nil {
			t.Fatalf("receive #%d (%s): %v", i, name, err)
		}
		got := gotypeName(m)
		if got != name {
			t.Fatalf("message #%d: got %s, want %s", i, got, name)
		}
	}
}

// TestV5CancelRequestSecretKeyIsBytes locks in the v5 type change:
// SecretKey is []byte end-to-end (encode → decode round-trip preserves
// the exact byte sequence). A regression that reintroduces uint32 for
// the secret would either fail to compile — good — or, worse, silently
// truncate the high bytes on Postgres 18+, silently breaking cancel.
func TestV5CancelRequestSecretKeyIsBytes(t *testing.T) {
	// A 4-byte secret (pre-18 wire width) — the format libpq uses.
	original := &pgproto3.CancelRequest{
		ProcessID: 0xCAFE_BABE,
		SecretKey: []byte{0x00, 0x11, 0x22, 0x33},
	}
	encoded, err := original.Encode(nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Encoded frame has a leading 4-byte length that Decode expects
	// callers to have already stripped — do that here.
	if len(encoded) < 4 {
		t.Fatalf("encoded frame too short: %d bytes", len(encoded))
	}
	body := encoded[4:]

	var decoded pgproto3.CancelRequest
	if err := decoded.Decode(body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.ProcessID != original.ProcessID {
		t.Fatalf("ProcessID mismatch: got %08x, want %08x", decoded.ProcessID, original.ProcessID)
	}
	if !bytes.Equal(decoded.SecretKey, original.SecretKey) {
		t.Fatalf("SecretKey mismatch: got %x, want %x", decoded.SecretKey, original.SecretKey)
	}
}

// TestV5FakeAuthOnPipeAgainstFrontend end-to-ends the local fakeAuth
// function against a real v5 Frontend reading from a pipe — the same
// path a libpq client walks. Regression net: catches any accidental
// removal of the Flush inside fakeAuth (which used to be implicit in
// v2 Send() but is now mandatory), and any accidental change of
// BackendKeyData.SecretKey to a non-[]byte value.
func TestV5FakeAuthOnPipeAgainstFrontend(t *testing.T) {
	sc, cc := net.Pipe()
	defer sc.Close()
	defer cc.Close()

	server := pgproto3.NewBackend(sc, sc)
	client := pgproto3.NewFrontend(cc, cc)

	const wantPID uint32 = 0xBEEF_0000
	wantSecret := []byte{0x12, 0x34, 0x56, 0x78}

	authErr := make(chan error, 1)
	go func() { authErr <- fakeAuth(server, wantPID, wantSecret) }()

	sawBKD := false
	for i := 0; i < 20; i++ { // hard upper bound so a stuck loop can't wedge the test
		m, err := client.Receive()
		if err != nil {
			t.Fatalf("client receive #%d: %v", i, err)
		}
		if bkd, ok := m.(*pgproto3.BackendKeyData); ok {
			if bkd.ProcessID != wantPID {
				t.Fatalf("BackendKeyData.ProcessID: got %08x, want %08x", bkd.ProcessID, wantPID)
			}
			if !bytes.Equal(bkd.SecretKey, wantSecret) {
				t.Fatalf("BackendKeyData.SecretKey: got %x, want %x", bkd.SecretKey, wantSecret)
			}
			sawBKD = true
		}
		if _, done := m.(*pgproto3.ReadyForQuery); done {
			break
		}
	}
	if err := <-authErr; err != nil {
		t.Fatalf("fakeAuth: %v", err)
	}
	if !sawBKD {
		t.Fatal("fakeAuth never sent BackendKeyData")
	}
}

// gotypeName is Go's %T rendering of the concrete type — used by the
// want tables above so they read as "*pgproto3.Query" (i.e., the
// star-prefixed pointer form Go prints natively).
func gotypeName(v interface{}) string {
	return goTypeString(v)
}
