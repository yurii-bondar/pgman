// Package main — the backend connector used by SCRAM pass-through.
//
// Every other pool dials through pgconn.Connect, which is more mature
// than anything written here and should stay the default. Pass-through
// cannot use it: pgconn derives its SCRAM proof from a password, and
// the whole point is that we do not have one — we have the ClientKey
// recovered from the client's own exchange, and pgconn exposes no hook
// to sign with it.
//
// So this drives the startup handshake itself. It still leans on
// pgconn for the hard, easy-to-get-wrong part: pgconn.ParseConfig turns
// sslmode, sslrootcert, sslcert and friends into a *tls.Config, and
// this file only performs the handshake that config describes.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// backendHandshakeTimeout bounds the whole connect-and-authenticate
// exchange. Without it a backend that accepts a TCP connection and then
// says nothing parks the dialing goroutine — and, because the dial
// happens under an Acquire, the pool slot with it.
var backendHandshakeTimeout = 30 * time.Second

// connectTarget is one host to try: pgconn splits a multi-host DSN into
// a primary plus fallbacks, each with its own address and TLS config
// (sslmode=prefer, for instance, becomes a TLS attempt followed by a
// plaintext one).
type connectTarget struct {
	host      string
	port      uint16
	tlsConfig *tls.Config
}

func connectTargets(cfg *pgconn.Config) []connectTarget {
	targets := []connectTarget{{host: cfg.Host, port: cfg.Port, tlsConfig: cfg.TLSConfig}}
	for _, fb := range cfg.Fallbacks {
		targets = append(targets, connectTarget{host: fb.Host, port: fb.Port, tlsConfig: fb.TLSConfig})
	}
	return targets
}

// connectPassthrough opens a backend connection authenticated as the
// user whose ClientKey is in pc, and returns it in the same
// already-authenticated, ready-for-query state pgconn.Hijack would.
func connectPassthrough(ctx context.Context, cfg *pgconn.Config, database, user string, pc passthroughCreds) (*backendConn, error) {
	var lastErr error
	for _, target := range connectTargets(cfg) {
		conn, err := dialAndHandshake(ctx, cfg, target, database, user, pc)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// A cancelled caller is not a reason to try the next host.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no connect targets in DSN")
	}
	return nil, lastErr
}

func dialAndHandshake(ctx context.Context, cfg *pgconn.Config, target connectTarget, database, user string, pc passthroughCreds) (_ *backendConn, err error) {
	addr := net.JoinHostPort(target.host, fmt.Sprintf("%d", target.port))

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// Close on every failure path below. Ownership passes to the caller
	// only once everything has succeeded.
	defer func() {
		if err != nil {
			_ = raw.Close()
		}
	}()

	deadline := time.Now().Add(backendHandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}

	// Holds either the raw socket or the TLS wrapper below; both are
	// net.Conn, which is all the rest of the handshake needs.
	conn := raw
	if target.tlsConfig != nil {
		tlsConn, tlsErr := startBackendTLS(raw, target.tlsConfig)
		if tlsErr != nil {
			return nil, tlsErr
		}
		conn = tlsConn
	}

	fe := pgproto3.NewFrontend(conn, conn)

	params := map[string]string{"user": user, "database": database}
	for k, v := range cfg.RuntimeParams {
		params[k] = v
	}
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: params})
	if err := fe.Flush(); err != nil {
		return nil, fmt.Errorf("send startup: %w", err)
	}

	pid, secret, err := completeBackendHandshake(fe, user, pc)
	if err != nil {
		return nil, err
	}

	// The handshake deadline must not follow the connection into the
	// pool: a leftover deadline makes the first query on this connection
	// fail at a time nothing explains.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}

	cancelTLS, err := cancelTLSConfigFor(conn, cfg)
	if err != nil {
		return nil, err
	}
	return &backendConn{
		Conn:      conn,
		addr:      addr,
		pid:       pid,
		secretKey: secret,
		cancelTLS: cancelTLS,
	}, nil
}

// startBackendTLS performs the client half of Postgres's TLS
// negotiation: SSLRequest, a one-byte verdict, then the handshake.
func startBackendTLS(conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	req, err := (&pgproto3.SSLRequest{}).Encode(nil)
	if err != nil {
		return nil, fmt.Errorf("encode sslrequest: %w", err)
	}
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("send sslrequest: %w", err)
	}
	var verdict [1]byte
	if _, err := io.ReadFull(conn, verdict[:]); err != nil {
		return nil, fmt.Errorf("read sslrequest reply: %w", err)
	}
	if verdict[0] != 'S' {
		// Never continue in the clear. This target's config asked for
		// TLS; a DSN that tolerates plaintext expresses that as a
		// separate fallback target, which the caller will try next.
		return nil, fmt.Errorf("backend refused TLS (replied %q)", verdict[0])
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("backend tls handshake: %w", err)
	}
	return tlsConn, nil
}

// completeBackendHandshake runs the authentication exchange and then
// consumes the backend's startup chatter up to ReadyForQuery, returning
// the cancel-key material it announced along the way.
func completeBackendHandshake(fe *pgproto3.Frontend, user string, pc passthroughCreds) (pid uint32, secret []byte, err error) {
	authenticated := false
	for {
		msg, err := fe.Receive()
		if err != nil {
			return 0, nil, fmt.Errorf("backend handshake: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.AuthenticationSASL:
			if err := scramClientAuth(fe, user, pc, m.AuthMechanisms); err != nil {
				return 0, nil, fmt.Errorf("backend scram: %w", err)
			}

		case *pgproto3.AuthenticationOk:
			authenticated = true

		case *pgproto3.BackendKeyData:
			pid = m.ProcessID
			secret = append([]byte(nil), m.SecretKey...)

		case *pgproto3.ParameterStatus, *pgproto3.NoticeResponse:
			// Startup chatter; the relay sends the client its own.

		case *pgproto3.ReadyForQuery:
			if !authenticated {
				return 0, nil, fmt.Errorf("backend reached ReadyForQuery without authenticating")
			}
			return pid, secret, nil

		case *pgproto3.ErrorResponse:
			return 0, nil, fmt.Errorf("backend refused the connection: %s (SQLSTATE %s)", m.Message, m.Code)

		case *pgproto3.AuthenticationCleartextPassword,
			*pgproto3.AuthenticationMD5Password,
			*pgproto3.AuthenticationGSS,
			*pgproto3.AuthenticationGSSContinue:
			// Pass-through has a ClientKey and nothing else. Anything
			// that wants a password, a ticket or a downgrade cannot be
			// satisfied, and saying which one was asked for is what
			// lets an operator fix their pg_hba.conf.
			return 0, nil, fmt.Errorf("backend requested %T, but SCRAM pass-through can only answer "+
				"scram-sha-256 — set that method for this user in the backend's pg_hba.conf", m)

		default:
			return 0, nil, fmt.Errorf("unexpected message during backend handshake: %T", m)
		}
	}
}

// newPassthroughDialer builds a pool.Dialer that opens connections as
// backendUser, signing with the ClientKey recovered from that user's
// own handshake with pgman.
//
// The DSN supplies everything except the credential: host, port,
// database, TLS. Any user or password in it is ignored — leaving them
// in a pass-through pool's DSN is harmless, and stripping them would
// only make the config look like it still mattered.
func newPassthroughDialer(dsn, backendUser string, store *clientKeyStore, requireTLS bool) pool.Dialer {
	// Parsed once so a broken DSN fails when the pool is built rather
	// than on some client's first query, matching newDialBackend.
	parsed, parseErr := pgconn.ParseConfig(dsn)
	if parseErr == nil && requireTLS && !dsnRequiresTLS(parsed, dsn) {
		parseErr = fmt.Errorf("require_backend_tls=true but DSN sslmode is not require/verify-ca/verify-full")
	}

	return func(ctx context.Context) (net.Conn, error) {
		if parseErr != nil {
			return nil, parseErr
		}
		pc, ok := store.lookup(backendUser)
		if !ok {
			// Only reachable if the store was cleared, since the pool
			// is created in response to this user authenticating.
			return nil, fmt.Errorf("no SCRAM credentials held for %q — it must authenticate to pgman before a backend connection can be opened as it", backendUser)
		}
		return connectPassthrough(ctx, parsed, parsed.Database, backendUser, pc)
	}
}
