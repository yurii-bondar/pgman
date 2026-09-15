package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// tlsCancelListener plays a Postgres that has ssl turned on: it expects
// SSLRequest first and answers with sslReply, then — on 'S' — completes
// a TLS handshake before reading the CancelRequest.
//
// Anything it manages to decode lands on received, whether it arrived
// over TLS or in the clear. That is what lets the downgrade test assert
// a negative: not just "we returned an error" but "nothing reached the
// server".
func tlsCancelListener(t *testing.T, sslReply byte) (addr string, received chan *pgproto3.CancelRequest) {
	t.Helper()
	cert := generateTestCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	received = make(chan *pgproto3.CancelRequest, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		// SSLRequest is a fixed 8-byte frame: int32 length, int32 code.
		var req [8]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		if _, err := conn.Write([]byte{sslReply}); err != nil {
			return
		}

		var stream net.Conn = conn
		if sslReply == 'S' {
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			stream = tlsConn
		}

		msg, err := pgproto3.NewBackend(stream, stream).ReceiveStartupMessage()
		if err != nil {
			return
		}
		if cr, ok := msg.(*pgproto3.CancelRequest); ok {
			received <- cr
		}
	}()
	return ln.Addr().String(), received
}

// TestCancelRequestNegotiatesTLS is the regression for query
// cancellation being silently dead in the recommended production
// configuration.
//
// A cancel cannot travel on the connection it cancels — the protocol
// demands a fresh one — and that fresh connection was always dialed in
// plaintext. Against a backend with sslmode=require, which this
// project's own sample config sets, the server discarded it: Ctrl+C,
// pg_cancel_backend and the admin UI's cancel button all did nothing,
// and the only trace was a warning in the log.
func TestCancelRequestNegotiatesTLS(t *testing.T) {
	addr, received := tlsCancelListener(t, 'S')

	secret := secretBytes(0xDEADBEEF)
	err := sendRealCancelRequest(addr, 4242, secret, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("sending a cancel to a TLS-only backend: %v", err)
	}

	select {
	case cr := <-received:
		if cr.ProcessID != 4242 {
			t.Errorf("ProcessID = %d, want 4242", cr.ProcessID)
		}
		if !bytes.Equal(cr.SecretKey, secret) {
			t.Errorf("SecretKey = %v, want %v", cr.SecretKey, secret)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the TLS-only backend never received the CancelRequest")
	}
}

// TestCancelRequestRefusesPlaintextDowngrade covers the other half: if
// the backend declines TLS on a connection we know must be encrypted,
// give up rather than retry in the clear. A downgrade would put the
// cancel key on the wire unprotected, and the server that just refused
// TLS would ignore the request regardless.
func TestCancelRequestRefusesPlaintextDowngrade(t *testing.T) {
	addr, received := tlsCancelListener(t, 'N')

	err := sendRealCancelRequest(addr, 1, secretBytes(2), &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		t.Fatal("expected an error when the backend refuses TLS, got nil")
	}

	select {
	case cr := <-received:
		t.Fatalf("a CancelRequest was sent in the clear after TLS was refused: %+v", cr)
	case <-time.After(300 * time.Millisecond):
		// Nothing arrived — correct.
	}
}

// TestCancelRequestStaysPlaintextForPlaintextBackend guards the other
// direction: a nil config must not start speaking SSLRequest at a
// backend that never offered TLS.
func TestCancelRequestStaysPlaintextForPlaintextBackend(t *testing.T) {
	addr, received := fakePostgresListener(t)

	if err := sendRealCancelRequest(addr, 7, secretBytes(8), nil); err != nil {
		t.Fatalf("sending a cancel to a plaintext backend: %v", err)
	}
	select {
	case cr := <-received:
		if cr.ProcessID != 7 {
			t.Errorf("ProcessID = %d, want 7", cr.ProcessID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the plaintext backend never received the CancelRequest")
	}
}

func TestCancelTLSConfigFor(t *testing.T) {
	plain, other := net.Pipe()
	t.Cleanup(func() { plain.Close(); other.Close() })

	// A plaintext backend needs no cancel TLS, and must not be given a
	// config just because the DSN happens to carry one (sslmode=prefer
	// that fell back).
	cfg, err := cancelTLSConfigFor(plain, &pgconn.Config{TLSConfig: &tls.Config{}})
	if err != nil || cfg != nil {
		t.Errorf("plaintext conn: got (%v, %v), want (nil, nil)", cfg, err)
	}

	want := &tls.Config{ServerName: "db.example.com"}
	cfg, err = cancelTLSConfigFor(tls.Client(plain, want), &pgconn.Config{TLSConfig: want})
	if err != nil {
		t.Fatalf("tls conn: unexpected error %v", err)
	}
	if cfg != want {
		t.Errorf("tls conn: got %v, want the DSN's own TLS config", cfg)
	}

	// Encrypted but unreconstructable: fail the dial rather than hand
	// out a backend whose cancels can never work.
	if _, err := cancelTLSConfigFor(tls.Client(plain, want), &pgconn.Config{}); err == nil {
		t.Error("expected an error when the connection is TLS but no config is available")
	}
}
