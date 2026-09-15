package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// The pass-through connector is the one place pgman drives a Postgres
// startup handshake itself instead of letting pgconn do it, and the one
// place it signs with a recovered ClientKey. backend_auth_test.go proves
// the happy path against the fake server; everything here is the
// half of the code that decides what happens when the backend answers
// something other than what pass-through can satisfy.
//
// Two reasons these are wire-level rather than end-to-end: a backend
// that offers GSSAPI, closes mid-handshake or returns a nonce that does
// not extend ours cannot be expressed through the fake server's
// options, and the resulting error message is the entire product — it
// is what an operator reads before editing pg_hba.conf.

// scriptedBackend puts a pgproto3.Backend on the far end of an in-memory
// pipe and drives it from script, so a test can send byte sequences a
// real Postgres would never produce.
func scriptedBackend(t *testing.T, script func(be *pgproto3.Backend)) *pgproto3.Frontend {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	// Deadlines on both ends: a scripted exchange that desynchronises
	// should fail with a timeout naming the side that stopped talking,
	// not hang until the package timeout kills everything.
	_ = serverConn.SetDeadline(time.Now().Add(20 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-done
	})
	go func() {
		defer close(done)
		script(pgproto3.NewBackend(serverConn, serverConn))
		// Closing releases a client still waiting for a message the
		// script has decided not to send.
		_ = serverConn.Close()
	}()
	return pgproto3.NewFrontend(clientConn, clientConn)
}

// scriptedRawBackend is the same idea one layer lower, for the TLS
// negotiation that happens before any pgproto3 framing exists.
func scriptedRawBackend(t *testing.T, script func(conn net.Conn)) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	_ = serverConn.SetDeadline(time.Now().Add(20 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

	done := make(chan struct{})
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-done
	})
	go func() {
		defer close(done)
		script(serverConn)
		_ = serverConn.Close()
	}()
	return clientConn
}

// recoveredPassthroughCreds produces the credentials pass-through
// actually runs on: a ClientKey recovered from a completed SCRAM
// exchange, not one derived directly. Built the production way on
// purpose — a test that computed the key by another route would pass
// while recoverClientKey was wrong.
func recoveredPassthroughCreds(t *testing.T, password, verifier string) passthroughCreds {
	t.Helper()
	creds, err := ParseSCRAMVerifier(verifier)
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}

	server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		return creds, nil
	})
	if err != nil {
		t.Fatalf("scram server: %v", err)
	}
	sconv := server.NewConversation()
	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		t.Fatalf("scram client: %v", err)
	}
	cconv := client.NewConversation()

	clientFirst, err := cconv.Step("")
	if err != nil {
		t.Fatalf("client first: %v", err)
	}
	serverFirst, err := sconv.Step(clientFirst)
	if err != nil {
		t.Fatalf("server first: %v", err)
	}
	clientFinal, err := cconv.Step(serverFirst)
	if err != nil {
		t.Fatalf("client final: %v", err)
	}
	if _, err := sconv.Step(clientFinal); err != nil {
		t.Fatalf("server final: %v", err)
	}

	key, err := recoverClientKey(scramExchange{
		ClientFirst: clientFirst,
		ServerFirst: serverFirst,
		ClientFinal: clientFinal,
	}, creds.StoredKey)
	if err != nil {
		t.Fatalf("recover client key: %v", err)
	}
	return passthroughCreds{clientKey: key, creds: creds}
}

// readClientFirst reads the client's SASLInitialResponse and returns the
// nonce it chose. Called from inside a script goroutine, so it reports
// through t.Errorf rather than t.Fatalf.
func readClientFirst(t *testing.T, be *pgproto3.Backend) (nonce string, ok bool) {
	t.Helper()
	if err := be.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		t.Errorf("set auth type: %v", err)
		return "", false
	}
	msg, err := be.Receive()
	if err != nil {
		t.Errorf("receive sasl initial response: %v", err)
		return "", false
	}
	initial, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok {
		t.Errorf("expected SASLInitialResponse, got %T", msg)
		return "", false
	}
	for _, field := range strings.Split(string(initial.Data), ",") {
		if strings.HasPrefix(field, "r=") {
			return field[2:], true
		}
	}
	t.Errorf("client-first carries no nonce: %q", initial.Data)
	return "", false
}

// backendTLSConfigForTest is the client-side TLS config the negotiation
// tests hand to startBackendTLS. Verification is off because these
// tests never get as far as a certificate — what is under test is the
// negotiation that happens before one is presented.
func backendTLSConfigForTest() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // no certificate is ever presented in these tests
}

// TestClientKeyStoreIsNilSafe: the store is nil whenever no pool asks
// for pass-through, which is the default. Every method has to tolerate
// that, because the capture hook runs on the login path of every user
// and a panic there would take the whole listener down rather than
// degrade one feature.
func TestClientKeyStoreIsNilSafe(t *testing.T) {
	var store *clientKeyStore

	store.remember("alice", []byte("key"), scram.StoredCredentials{})
	if _, ok := store.lookup("alice"); ok {
		t.Error("a nil store returned credentials")
	}
	if store.has("alice") {
		t.Error("a nil store claims to hold a user")
	}
}

// TestClientKeyStoreOverwritesOnEachLogin is what makes a password
// rotation take effect: the entry from the user's previous login would
// otherwise keep producing proofs the backend rejects until the process
// restarts, and nothing about that failure would point at a stale key.
func TestClientKeyStoreOverwritesOnEachLogin(t *testing.T) {
	store := newClientKeyStore()
	if store.has("alice") {
		t.Fatal("a fresh store already holds a user")
	}

	store.remember("alice", []byte("first-key"), scram.StoredCredentials{})
	store.remember("alice", []byte("second-key"), scram.StoredCredentials{})

	pc, ok := store.lookup("alice")
	if !ok {
		t.Fatal("the user was not recorded")
	}
	if string(pc.clientKey) != "second-key" {
		t.Errorf("stored key = %q, want the most recent login's", pc.clientKey)
	}
}

// TestScramClientAuthRejectsABackendWithoutSCRAM covers the mechanism
// negotiation from pgman's side. A backend offering only channel-bound
// SCRAM is the realistic case — pass-through has nothing honest to bind
// with — and the error has to say what was offered, because the fix is
// in the backend's configuration and not in pgman's.
func TestScramClientAuthRejectsABackendWithoutSCRAM(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(*pgproto3.Backend) {})

	err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256-PLUS"})
	if err == nil {
		t.Fatal("a backend that cannot do SCRAM-SHA-256 was accepted")
	}
	if !strings.Contains(err.Error(), "SCRAM-SHA-256-PLUS") {
		t.Errorf("error = %v, want it to list what the backend offered", err)
	}
}

// TestScramClientAuthRejectsANonceThatDoesNotExtendOurs is SCRAM's own
// anti-relay check. A server-first whose nonce is not ours plus its own
// means something is rewriting the exchange, and continuing would let
// that something collect a proof for a nonce it chose.
func TestScramClientAuthRejectsANonceThatDoesNotExtendOurs(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		if _, ok := readClientFirst(t, be); !ok {
			return
		}
		be.Send(&pgproto3.AuthenticationSASLContinue{
			Data: []byte("r=someoneelsesnonce,s=" +
				base64.StdEncoding.EncodeToString([]byte("fakepgsalt")) + ",i=4096"),
		})
		_ = be.Flush()
	})

	err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
	if err == nil {
		t.Fatal("a server nonce unrelated to ours was accepted")
	}
	if !strings.Contains(err.Error(), "man in the middle") {
		t.Errorf("error = %v, want it to name the relay risk", err)
	}
}

// TestScramClientAuthNamesAVerifierMismatch pins the message for the
// mistake operators actually make: pgman holds a verifier generated
// locally rather than a copy of the backend's rolpassword. The
// recovered ClientKey is derived from the salt and iteration count, so
// it cannot possibly work — and without this check the backend answers
// "password authentication failed", sending someone hunting for a wrong
// password that does not exist.
func TestScramClientAuthNamesAVerifierMismatch(t *testing.T) {
	cases := []struct {
		name        string
		salt        string
		iters       int
		wantInError string
	}{
		{"different salt", "some-other-salt", 4096, "verifier"},
		{"different iteration count", "fakepgsalt", 8192, "iteration count"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
			fe := scriptedBackend(t, func(be *pgproto3.Backend) {
				nonce, ok := readClientFirst(t, be)
				if !ok {
					return
				}
				be.Send(&pgproto3.AuthenticationSASLContinue{
					Data: []byte(fmt.Sprintf("r=%sserver,s=%s,i=%d",
						nonce, base64.StdEncoding.EncodeToString([]byte(tc.salt)), tc.iters)),
				})
				_ = be.Flush()
			})

			err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
			if err == nil {
				t.Fatal("a backend with a different verifier was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantInError)
			}
			if !strings.Contains(err.Error(), "alice") {
				t.Errorf("error = %v, want it to name the user whose verifier is wrong", err)
			}
		})
	}
}

// TestScramClientAuthRejectsAWrongServerSignature is the mutual half of
// SCRAM. A backend that accepts our proof but cannot prove it holds the
// user's ServerKey is not the server we think it is, and handing it
// queries would be handing them to whatever answered on that port.
func TestScramClientAuthRejectsAWrongServerSignature(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		nonce, ok := readClientFirst(t, be)
		if !ok {
			return
		}
		be.Send(&pgproto3.AuthenticationSASLContinue{
			Data: []byte("r=" + nonce + "server,s=" +
				base64.StdEncoding.EncodeToString([]byte("fakepgsalt")) + ",i=4096"),
		})
		if err := be.Flush(); err != nil {
			return
		}
		if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
			t.Errorf("set auth type: %v", err)
			return
		}
		if _, err := be.Receive(); err != nil {
			t.Errorf("receive sasl response: %v", err)
			return
		}
		// A syntactically perfect server-final signed with nothing.
		be.Send(&pgproto3.AuthenticationSASLFinal{
			Data: []byte("v=" + base64.StdEncoding.EncodeToString(make([]byte, 32))),
		})
		_ = be.Flush()
	})

	err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
	if err == nil {
		t.Fatal("a backend that could not prove itself was accepted")
	}
	if !strings.Contains(err.Error(), "server signature") {
		t.Errorf("error = %v, want it to name the server signature", err)
	}
}

// TestScramClientAuthRejectsUnexpectedMessages: an authentication
// exchange that goes off script must end, not continue. Accepting an
// AuthenticationOk in place of the SASL continue would mean skipping
// the proof entirely, which is the one shortcut that must never exist.
func TestScramClientAuthRejectsUnexpectedMessages(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))

	t.Run("instead of the sasl continue", func(t *testing.T) {
		fe := scriptedBackend(t, func(be *pgproto3.Backend) {
			if _, ok := readClientFirst(t, be); !ok {
				return
			}
			be.Send(&pgproto3.AuthenticationOk{})
			_ = be.Flush()
		})

		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil || !strings.Contains(err.Error(), "expected AuthenticationSASLContinue") {
			t.Fatalf("error = %v, want a refusal naming AuthenticationSASLContinue", err)
		}
	})

	t.Run("instead of the sasl final", func(t *testing.T) {
		fe := scriptedBackend(t, func(be *pgproto3.Backend) {
			nonce, ok := readClientFirst(t, be)
			if !ok {
				return
			}
			be.Send(&pgproto3.AuthenticationSASLContinue{
				Data: []byte("r=" + nonce + "server,s=" +
					base64.StdEncoding.EncodeToString([]byte("fakepgsalt")) + ",i=4096"),
			})
			if err := be.Flush(); err != nil {
				return
			}
			if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
				t.Errorf("set auth type: %v", err)
				return
			}
			if _, err := be.Receive(); err != nil {
				t.Errorf("receive sasl response: %v", err)
				return
			}
			be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "nope"})
			_ = be.Flush()
		})

		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil || !strings.Contains(err.Error(), "expected AuthenticationSASLFinal") {
			t.Fatalf("error = %v, want a refusal naming AuthenticationSASLFinal", err)
		}
	})
}

// TestScramClientAuthReportsALostConnection: a backend that drops
// mid-handshake is ordinary operational traffic — a restart, a failover,
// a connection limit. Every step has to return the I/O error, because
// this runs under a pool Acquire and a blocked dial holds the slot.
func TestScramClientAuthReportsALostConnection(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))

	t.Run("before our first message lands", func(t *testing.T) {
		fe := scriptedBackend(t, func(*pgproto3.Backend) {})
		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil {
			t.Fatal("a closed connection produced a successful handshake")
		}
	})

	t.Run("after reading our first message", func(t *testing.T) {
		fe := scriptedBackend(t, func(be *pgproto3.Backend) {
			_, _ = readClientFirst(t, be)
		})
		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil || !strings.Contains(err.Error(), "receive sasl continue") {
			t.Fatalf("error = %v, want the failure attributed to the read", err)
		}
	})

	t.Run("while we are sending our proof", func(t *testing.T) {
		fe := scriptedBackend(t, func(be *pgproto3.Backend) {
			nonce, ok := readClientFirst(t, be)
			if !ok {
				return
			}
			be.Send(&pgproto3.AuthenticationSASLContinue{
				Data: []byte("r=" + nonce + "server,s=" +
					base64.StdEncoding.EncodeToString([]byte("fakepgsalt")) + ",i=4096"),
			})
			_ = be.Flush()
		})
		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil || !strings.Contains(err.Error(), "send sasl response") {
			t.Fatalf("error = %v, want the failure attributed to the write", err)
		}
	})

	t.Run("after reading our proof", func(t *testing.T) {
		fe := scriptedBackend(t, func(be *pgproto3.Backend) {
			nonce, ok := readClientFirst(t, be)
			if !ok {
				return
			}
			be.Send(&pgproto3.AuthenticationSASLContinue{
				Data: []byte("r=" + nonce + "server,s=" +
					base64.StdEncoding.EncodeToString([]byte("fakepgsalt")) + ",i=4096"),
			})
			if err := be.Flush(); err != nil {
				return
			}
			if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
				t.Errorf("set auth type: %v", err)
				return
			}
			if _, err := be.Receive(); err != nil {
				t.Errorf("receive sasl response: %v", err)
			}
		})
		err := scramClientAuth(fe, "alice", pc, []string{"SCRAM-SHA-256"})
		if err == nil || !strings.Contains(err.Error(), "receive sasl final") {
			t.Fatalf("error = %v, want the failure attributed to the read", err)
		}
	})
}

// TestVerifyServerSignatureRejectsEveryBadFinalMessage checks each
// refusal separately because they mean different things to an operator:
// "e=" is the backend's own verdict on our proof and worth quoting,
// while anything unparseable means we are not talking to Postgres at
// all. Collapsing them into one message loses that distinction.
func TestVerifyServerSignatureRejectsEveryBadFinalMessage(t *testing.T) {
	const authMessage = "n=,r=abc,r=abcdef,s=c2FsdA==,i=4096,c=biws,r=abcdef"
	serverKey := []byte("a thirty-two byte server key....")

	cases := []struct {
		name        string
		serverFinal string
		wantInError string
	}{
		{"the backend rejected us", "e=invalid-proof", "invalid-proof"},
		{"not a server-final at all", "ReadyForQuery", "malformed server-final"},
		{"signature is not base64", "v=not base64!", "not valid base64"},
		{
			name:        "signature is wrong",
			serverFinal: "v=" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
			wantInError: "does not hold this user's credentials",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyServerSignature(tc.serverFinal, serverKey, authMessage)
			if err == nil {
				t.Fatalf("%q was accepted", tc.serverFinal)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantInError)
			}
		})
	}

	t.Run("a correct signature", func(t *testing.T) {
		good := "v=" + base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, []byte(authMessage)))
		if err := verifyServerSignature(good, serverKey, authMessage); err != nil {
			t.Fatalf("a valid server signature was rejected: %v", err)
		}
	})
}

// TestParseServerFirstRejectsMalformedMessages: every field of
// server-first feeds a cryptographic derivation, so a missing or
// unparseable one has to stop the exchange. Defaulting any of them
// would produce a proof against the wrong key factors and turn a
// protocol problem into an authentication failure.
func TestParseServerFirstRejectsMalformedMessages(t *testing.T) {
	cases := []struct {
		name        string
		serverFirst string
		wantInError string
	}{
		{"salt is not base64", "r=abc,s=not base64!,i=4096", "not valid base64"},
		{"iterations are not a number", "r=abc,s=c2FsdA==,i=many", "is not a number"},
		{"no salt", "r=abc,i=4096", "incomplete server-first"},
		{"no nonce", "s=c2FsdA==,i=4096", "incomplete server-first"},
		{"non-positive iterations", "r=abc,s=c2FsdA==,i=0", "incomplete server-first"},
		{"unframed junk", "hello", "incomplete server-first"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseServerFirst(tc.serverFirst)
			if err == nil {
				t.Fatalf("%q parsed successfully", tc.serverFirst)
			}
			if !strings.Contains(err.Error(), tc.wantInError) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantInError)
			}
		})
	}

	t.Run("a well-formed message", func(t *testing.T) {
		// Unknown fields have to be skipped rather than rejected: the
		// SCRAM grammar reserves room for extensions, and a future
		// Postgres adding one must not break pass-through.
		nonce, salt, iters, err := parseServerFirst("r=abcdef,s=c2FsdA==,i=4096,x=extension")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if nonce != "abcdef" || salt != "salt" || iters != 4096 {
			t.Errorf("parsed (%q, %q, %d), want (abcdef, salt, 4096)", nonce, salt, iters)
		}
	})
}

// TestConnectTargetsIncludesEveryFallback: pgconn turns a multi-host
// DSN, and sslmode=prefer, into a primary plus fallbacks. Reading only
// the primary would silently disable every standby in the DSN — the
// connection string would keep working right up to the failover it was
// written for.
func TestConnectTargetsIncludesEveryFallback(t *testing.T) {
	cfg, err := pgconn.ParseConfig("postgres://alice@127.0.0.1:5432,127.0.0.2:5433/db1?sslmode=disable")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	targets := connectTargets(cfg)
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want one per host in the DSN", len(targets))
	}
	if targets[0].host != "127.0.0.1" || targets[0].port != 5432 {
		t.Errorf("first target = %s:%d, want 127.0.0.1:5432", targets[0].host, targets[0].port)
	}
	if targets[1].host != "127.0.0.2" || targets[1].port != 5433 {
		t.Errorf("second target = %s:%d, want 127.0.0.2:5433", targets[1].host, targets[1].port)
	}
}

// TestConnectPassthroughFallsBackToTheNextTarget is why the loop exists:
// after a failover the first host in the DSN is the one that is down, so
// a connector that gave up on the first error would keep every
// pass-through pool broken until someone edited the config.
func TestConnectPassthroughFallsBackToTheNextTarget(t *testing.T) {
	const password = "alice-password"
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password})
	_, port, err := net.SplitHostPort(backend.addr())
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}

	// Port 1 on loopback refuses immediately rather than hanging, which
	// is what a host that is down looks like from here.
	cfg, err := pgconn.ParseConfig(fmt.Sprintf(
		"postgres://alice@127.0.0.1:1,127.0.0.1:%s/db1?sslmode=disable", port))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	pc := recoveredPassthroughCreds(t, password, fakePGVerifier(t, password))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := connectPassthrough(ctx, cfg, "db1", "alice", pc)
	if err != nil {
		t.Fatalf("connect never reached the second target: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if conn.pid != 4242 {
		t.Errorf("backend pid = %d, want the cancel key the backend announced", conn.pid)
	}
	if len(conn.secretKey) == 0 {
		t.Error("no cancel secret was recorded, so this session could never be cancelled")
	}
}

// TestConnectPassthroughStopsOnACancelledCaller: the caller is a client
// that has already given up, and the remaining targets are dials nobody
// is waiting for. Walking them anyway would spend a pool slot and a
// connect timeout per host on a request that no longer exists.
func TestConnectPassthroughStopsOnACancelledCaller(t *testing.T) {
	cfg, err := pgconn.ParseConfig("postgres://alice@127.0.0.1:1,127.0.0.1:2/db1?sslmode=disable")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = connectPassthrough(ctx, cfg, "db1", "alice", pc)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want the caller's cancellation", err)
	}
}

// TestDialAndHandshakeReportsAnUnreachableBackend keeps the address in
// the error. A pass-through pool with a misspelled host otherwise fails
// with a bare "connection refused" that names neither the pool nor
// where it tried to go.
func TestDialAndHandshakeReportsAnUnreachableBackend(t *testing.T) {
	cfg, err := pgconn.ParseConfig("postgres://alice@127.0.0.1:1/db1?sslmode=disable")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))

	_, err = dialAndHandshake(context.Background(), cfg,
		connectTarget{host: "127.0.0.1", port: 1}, "db1", "alice", pc)
	if err == nil {
		t.Fatal("a dial to a closed port succeeded")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Errorf("error = %v, want it to name the address that failed", err)
	}
}

// TestConnectPassthroughAuthenticatesOverTLS is the combination a real
// deployment runs: require_backend_tls plus pass-through, so the
// ClientKey-signed proof crosses an encrypted connection. It is also
// the only test that drives pgman's own SSLRequest negotiation, since
// every other pool gets that from pgconn.
func TestConnectPassthroughAuthenticatesOverTLS(t *testing.T) {
	const password = "alice-password"
	cert := generateTestCert(t)
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password, tls: &cert})

	cfg, err := pgconn.ParseConfig(backend.dsn("app", "db1"))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.TLSConfig == nil {
		t.Fatal("the DSN did not produce a TLS config, so this test would prove nothing")
	}

	pc := recoveredPassthroughCreds(t, password, fakePGVerifier(t, password))
	// A context deadline shorter than backendHandshakeTimeout: the
	// handshake must respect the caller's budget, not its own.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := connectPassthrough(ctx, cfg, "db1", "alice", pc)
	if err != nil {
		t.Fatalf("connect over TLS: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if conn.cancelTLS == nil {
		t.Error("no TLS config was kept for cancel requests, so a cancel would go out in the clear")
	}
	params := backend.startupParams()
	if len(params) == 0 {
		t.Fatal("the backend saw no startup message")
	}
	// The DSN says user=app; pass-through must open the connection as
	// the role whose ClientKey it holds.
	if got := params[0]["user"]; got != "alice" {
		t.Errorf("connected as %q, want alice", got)
	}
}

// TestDialAndHandshakeRefusesATLSTargetItCannotReuse: a session's
// cancel request is a second connection, and it has to be opened the
// same encrypted way as the first. connectTargets can hand back a
// target with its own TLS config while the DSN's top-level one is
// empty, and returning that connection would leave every cancel on it
// either impossible or — worse — sent in plain text with the cancel key
// in it. The dial has to fail instead.
func TestDialAndHandshakeRefusesATLSTargetItCannotReuse(t *testing.T) {
	const password = "alice-password"
	cert := generateTestCert(t)
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password, tls: &cert})

	host, portStr, err := net.SplitHostPort(backend.addr())
	if err != nil {
		t.Fatalf("split backend address: %v", err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	// A config whose own TLSConfig is nil, dialled against a target that
	// carries one — the shape sslmode=prefer's fallback list produces.
	cfg, err := pgconn.ParseConfig(fmt.Sprintf("postgres://app@%s/db1?sslmode=disable", backend.addr()))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	target := connectTarget{host: host, port: port, tlsConfig: backendTLSConfigForTest()}

	pc := recoveredPassthroughCreds(t, password, fakePGVerifier(t, password))
	_, err = dialAndHandshake(context.Background(), cfg, target, "db1", "alice", pc)
	if err == nil {
		t.Fatal("a TLS connection with no reusable config for cancels was returned")
	}
	if !strings.Contains(err.Error(), "cancel requests") {
		t.Errorf("error = %v, want it to name cancel requests as the reason", err)
	}
}

// TestStartBackendTLSRefusesToContinueInTheClear is the check that makes
// sslmode=require mean something. A backend that answers 'N' has no TLS;
// falling through to a plaintext startup would put this user's SCRAM
// exchange and every subsequent statement on the wire unencrypted while
// the config claims otherwise.
func TestStartBackendTLSRefusesToContinueInTheClear(t *testing.T) {
	conn := scriptedRawBackend(t, func(server net.Conn) {
		var req [8]byte
		if _, err := io.ReadFull(server, req[:]); err != nil {
			t.Errorf("read sslrequest: %v", err)
			return
		}
		if _, err := server.Write([]byte{'N'}); err != nil {
			t.Errorf("write verdict: %v", err)
		}
	})

	_, err := startBackendTLS(conn, backendTLSConfigForTest())
	if err == nil {
		t.Fatal("a backend that refused TLS was used anyway")
	}
	if !strings.Contains(err.Error(), "refused TLS") {
		t.Errorf("error = %v, want it to name the refusal", err)
	}
}

// TestStartBackendTLSReportsAFailedHandshake covers the other half: the
// backend agreed to TLS and then the handshake itself failed. Without a
// distinct message this is indistinguishable from a certificate
// problem, which is the first thing anyone would go and check.
func TestStartBackendTLSReportsAFailedHandshake(t *testing.T) {
	conn := scriptedRawBackend(t, func(server net.Conn) {
		var req [8]byte
		if _, err := io.ReadFull(server, req[:]); err != nil {
			t.Errorf("read sslrequest: %v", err)
			return
		}
		if _, err := server.Write([]byte{'S'}); err != nil {
			t.Errorf("write verdict: %v", err)
			return
		}
		// Agreed to TLS, then spoke something else.
		if _, err := server.Write([]byte("not a ClientHello response")); err != nil {
			return
		}
	})

	_, err := startBackendTLS(conn, backendTLSConfigForTest())
	if err == nil {
		t.Fatal("a failed TLS handshake produced a usable connection")
	}
	if !strings.Contains(err.Error(), "tls handshake") {
		t.Errorf("error = %v, want it to name the handshake", err)
	}
}

// TestStartBackendTLSReportsAMissingVerdict: a backend that takes the
// SSLRequest and then closes without answering is what a connection
// limit or a crashing postmaster looks like. The single verdict byte is
// read with a blocking ReadFull, so the error has to be returned rather
// than the byte defaulted to anything.
func TestStartBackendTLSReportsAMissingVerdict(t *testing.T) {
	conn := scriptedRawBackend(t, func(server net.Conn) {
		var req [8]byte
		if _, err := io.ReadFull(server, req[:]); err != nil {
			t.Errorf("read sslrequest: %v", err)
		}
	})

	_, err := startBackendTLS(conn, backendTLSConfigForTest())
	if err == nil {
		t.Fatal("a backend that never answered the SSLRequest was used anyway")
	}
	if !strings.Contains(err.Error(), "sslrequest reply") {
		t.Errorf("error = %v, want it to name the missing reply", err)
	}
}

// TestStartBackendTLSReportsAClosedSocket: the SSLRequest is the first
// thing written to a freshly dialled socket, so a backend at its
// connection limit closes right here. The error has to surface rather
// than leave the dialler reading a socket nobody will write to.
func TestStartBackendTLSReportsAClosedSocket(t *testing.T) {
	conn := scriptedRawBackend(t, func(net.Conn) {})
	_ = conn.Close()

	if _, err := startBackendTLS(conn, backendTLSConfigForTest()); err == nil {
		t.Fatal("writing to a closed socket reported success")
	}
}

// TestCompleteBackendHandshakeRejectsUnsatisfiableAuthRequests is the
// single most useful error message in the pass-through path. pgman holds
// a ClientKey and nothing else, so any other method is unanswerable —
// and the fix is one line in the backend's pg_hba.conf, which the
// message has to point at by naming what was asked for.
func TestCompleteBackendHandshakeRejectsUnsatisfiableAuthRequests(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))

	cases := []struct {
		name string
		msg  pgproto3.BackendMessage
	}{
		{"cleartext password", &pgproto3.AuthenticationCleartextPassword{}},
		{"md5 password", &pgproto3.AuthenticationMD5Password{Salt: [4]byte{1, 2, 3, 4}}},
		{"gssapi", &pgproto3.AuthenticationGSS{}},
		{"gssapi continue", &pgproto3.AuthenticationGSSContinue{Data: []byte("token")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fe := scriptedBackend(t, func(be *pgproto3.Backend) {
				be.Send(tc.msg)
				_ = be.Flush()
			})

			_, _, err := completeBackendHandshake(fe, "alice", pc)
			if err == nil {
				t.Fatal("an unanswerable auth request did not fail the handshake")
			}
			if !strings.Contains(err.Error(), "scram-sha-256") {
				t.Errorf("error = %v, want it to name the method pg_hba.conf needs", err)
			}
		})
	}
}

// TestCompleteBackendHandshakeRequiresAuthentication guards the one
// invariant of this loop: ReadyForQuery is not proof of anything on its
// own. A backend — or something in front of it — that skips straight to
// it would otherwise hand back a pooled connection that never
// authenticated as this user at all.
func TestCompleteBackendHandshakeRequiresAuthentication(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	})

	_, _, err := completeBackendHandshake(fe, "alice", pc)
	if err == nil {
		t.Fatal("a backend that never authenticated us produced a usable connection")
	}
	if !strings.Contains(err.Error(), "without authenticating") {
		t.Errorf("error = %v, want it to say authentication never happened", err)
	}
}

// TestCompleteBackendHandshakeSurfacesAnErrorResponse keeps the
// backend's own SQLSTATE and message. "database does not exist" and
// "no pg_hba.conf entry for host" are the two most common failures here
// and they have completely different fixes, so replacing them with a
// generic connect error costs an operator the whole diagnosis.
func TestCompleteBackendHandshakeSurfacesAnErrorResponse(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "3D000",
			Message:  `database "db1" does not exist`,
		})
		_ = be.Flush()
	})

	_, _, err := completeBackendHandshake(fe, "alice", pc)
	if err == nil {
		t.Fatal("a FATAL ErrorResponse did not fail the handshake")
	}
	if !strings.Contains(err.Error(), "3D000") || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("error = %v, want the backend's own code and message", err)
	}
}

// TestCompleteBackendHandshakeRejectsAnUnexpectedMessage fails closed on
// anything the loop does not recognise. The alternative — ignoring it
// and reading on — would let a desynchronised stream be mistaken for a
// healthy connection, and the damage would surface later as corrupt
// query results rather than as a failed connect.
func TestCompleteBackendHandshakeRejectsAnUnexpectedMessage(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		_ = be.Flush()
	})

	_, _, err := completeBackendHandshake(fe, "alice", pc)
	if err == nil {
		t.Fatal("a message that has no place in a handshake was tolerated")
	}
	if !strings.Contains(err.Error(), "unexpected message") {
		t.Errorf("error = %v, want it to name the message as unexpected", err)
	}
}

// TestCompleteBackendHandshakeReportsALostConnection: a backend that
// accepts the TCP connection and then says nothing is the failure mode
// backendHandshakeTimeout exists for. The read error has to propagate,
// because this runs while holding a pool slot.
func TestCompleteBackendHandshakeReportsALostConnection(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(*pgproto3.Backend) {})

	_, _, err := completeBackendHandshake(fe, "alice", pc)
	if err == nil {
		t.Fatal("a backend that closed without a word produced a usable connection")
	}
	if !strings.Contains(err.Error(), "backend handshake") {
		t.Errorf("error = %v, want the failure attributed to the handshake read", err)
	}
}

// TestCompleteBackendHandshakeCollectsTheCancelKey covers the startup
// chatter a trust-authenticated backend sends. BackendKeyData is the
// only part of it pgman must retain: without the pid and secret, the
// admin plane's cancel and a client's own CancelRequest both silently
// do nothing.
func TestCompleteBackendHandshakeCollectsTheCancelKey(t *testing.T) {
	pc := recoveredPassthroughCreds(t, "s3cret", fakePGVerifier(t, "s3cret"))
	fe := scriptedBackend(t, func(be *pgproto3.Backend) {
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
		be.Send(&pgproto3.NoticeResponse{Severity: "NOTICE", Message: "hello"})
		be.Send(&pgproto3.BackendKeyData{ProcessID: 777, SecretKey: secretBytes(0xBEEF)})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	})

	pid, secret, err := completeBackendHandshake(fe, "alice", pc)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if pid != 777 {
		t.Errorf("pid = %d, want 777", pid)
	}
	if string(secret) != string(secretBytes(0xBEEF)) {
		t.Errorf("secret = %v, want the key the backend announced", secret)
	}
}

// TestNewPassthroughDialerFailsOnAConfigProblem: the dialer is built
// when a pool is created, and the DSN and require_backend_tls are both
// config. Both failures have to be the pool's error rather than a
// surprise on some client's first query, which is where it would
// otherwise land — as a failed statement instead of a failed reload.
func TestNewPassthroughDialerFailsOnAConfigProblem(t *testing.T) {
	store := newClientKeyStore()
	store.remember("alice", []byte("key"), scram.StoredCredentials{})

	t.Run("an unparseable DSN", func(t *testing.T) {
		dial := newPassthroughDialer("this is not a dsn", "alice", store, false)
		if _, err := dial(context.Background()); err == nil {
			t.Fatal("a broken DSN produced a working dialler")
		}
	})

	t.Run("tls required but not requested", func(t *testing.T) {
		dial := newPassthroughDialer("postgres://app@127.0.0.1:5432/db1?sslmode=disable",
			"alice", store, true)
		_, err := dial(context.Background())
		if err == nil {
			t.Fatal("require_backend_tls was satisfied by sslmode=disable")
		}
		if !strings.Contains(err.Error(), "require_backend_tls") {
			t.Errorf("error = %v, want it to name the setting that was violated", err)
		}
	})

	t.Run("no credentials held for the user", func(t *testing.T) {
		dial := newPassthroughDialer("postgres://app@127.0.0.1:5432/db1?sslmode=disable",
			"nobody", newClientKeyStore(), false)
		_, err := dial(context.Background())
		if err == nil {
			t.Fatal("a user who never authenticated got a backend connection")
		}
		if !strings.Contains(err.Error(), "nobody") {
			t.Errorf("error = %v, want it to name the user", err)
		}
	})
}
