// Package main — write deadlines on the client socket.
//
// Every other way a client can stall the proxy is bounded by a read
// deadline: client_login_timeout during the handshake, and
// client_idle_timeout / idle_transaction_timeout once the session is
// relaying. Writes were not bounded once the handshake's SetDeadline
// came off, and the write direction is where a client hurts the proxy
// most.
//
// The failure it closes: a peer that stops reading — SIGKILLed
// container, frozen VM, a network path that black-holes ACKs — leaves
// the proxy's send buffer full. write(2) then blocks until TCP gives up
// retransmitting, which on Linux defaults to the order of fifteen
// minutes. The relay goroutine parked in that write still holds the
// backend it acquired, so a single dead reader takes a pool slot out of
// service for the whole time. Enough of them and the pool is exhausted
// while every Postgres backend behind it sits idle.
package main

import (
	"io"
	"net"
	"time"
)

// clientWriter is the io.Writer pgproto3 writes client-bound protocol
// messages through, arming a write deadline around each write.
//
// It wraps the *writer*, not the connection, and that is load-bearing
// rather than stylistic: the auth path decides HBA `local` vs `host`
// rules and SCRAM channel binding by type-asserting the connection to
// *net.UnixConn and *tls.Conn (see hba.go and auth.go). A net.Conn
// wrapper would fail those assertions and silently downgrade METHOD=peer
// and tls-server-end-point binding. pgproto3.NewBackend takes an
// io.Reader and an io.Writer separately, so the connection itself can
// be passed through untouched.
//
// The deadline is per-write, not per-message: pgproto3 batches many
// protocol messages into one buffer and writes it in a single call, so
// what gets bounded is "the kernel accepted this buffer" — exactly the
// operation that blocks when a peer stops reading.
type clientWriter struct {
	conn    net.Conn
	timeout time.Duration
}

// newClientWriter returns the writer to hand pgproto3 for a client
// connection. A non-positive timeout returns conn itself, so the
// disabled case costs nothing — not even an interface hop per write.
func newClientWriter(conn net.Conn, timeout time.Duration) io.Writer {
	if timeout <= 0 {
		return conn
	}
	return &clientWriter{conn: conn, timeout: timeout}
}

func (w *clientWriter) Write(b []byte) (int, error) {
	if err := w.conn.SetWriteDeadline(time.Now().Add(w.timeout)); err != nil {
		return 0, err
	}
	n, err := w.conn.Write(b)
	// Clear it again: an armed deadline left behind would fire during
	// an unrelated later write, the same class of bug as a leftover
	// read deadline travelling with a pooled backend connection.
	_ = w.conn.SetWriteDeadline(time.Time{})
	return n, err
}
