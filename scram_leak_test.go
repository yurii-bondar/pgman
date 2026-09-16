package main

// Does any of the SCRAM material reach a place an operator can read?
//
// pgman is the one Postgres pooler in this repository that deliberately
// keeps a password-equivalent secret in memory: SCRAM pass-through
// recovers each client's ClientKey so it can authenticate to Postgres
// as that client. README calls that out as a real trade. What makes the
// trade acceptable is that the secret stays in the process — and
// "stays in the process" is a claim, not a fact, until something checks
// it.
//
// Logs are the realistic leak path. They are written at whatever level
// an operator picked, shipped to whatever aggregator the company runs,
// and kept for months. A single `slog.Warn(..., "creds", pc)` added in
// a hurry would put working credentials into Splunk, and no existing
// test would notice, because the login would still succeed.
//
// So these tests capture everything the logger emits during real
// authentication — including the failure paths, which is where
// diagnostics get added under pressure — and assert that none of the
// secret material appears, in any encoding somebody might reasonably
// have used to print it.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// captureLogs redirects the default slog logger into a buffer for the
// duration of the test, at the most verbose level.
//
// Debug level on purpose: the question is not "does the shipped log
// level leak", which changes the moment somebody debugs an incident.
// It is whether the secret is ever handed to the logging package at
// all.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// assertNoSecret fails if secret shows up in haystack under any of the
// encodings a printf-debugging line would plausibly produce.
//
// The encodings matter more than the raw comparison. Nobody writes
// `log.Print(string(clientKey))` — it is unreadable. They write %x, or
// %q, or hand the byte slice to a JSON handler, which base64s it. Each
// of those produces a different string and every one of them is a leak.
func assertNoSecret(t *testing.T, haystack []byte, secret []byte, what string) {
	t.Helper()
	if len(secret) == 0 {
		t.Fatalf("%s: empty secret, the assertion would be vacuous", what)
	}

	encodings := map[string]string{
		"raw bytes":     string(secret),
		"hex":           hex.EncodeToString(secret),
		"HEX":           strings.ToUpper(hex.EncodeToString(secret)),
		"base64":        base64.StdEncoding.EncodeToString(secret),
		"base64url":     base64.URLEncoding.EncodeToString(secret),
		"base64 raw":    base64.RawStdEncoding.EncodeToString(secret),
		"go %v of byte": fmt.Sprintf("%v", secret),
		"go %q":         fmt.Sprintf("%q", secret),
	}
	for name, encoded := range encodings {
		if bytes.Contains(haystack, []byte(encoded)) {
			t.Errorf("%s leaked into the logs as %s\n--- log ---\n%s", what, name, haystack)
		}
	}
}

// scramLeakFixture builds a SCRAMAuth with pass-through enabled, so the
// ClientKey capture path — the one that exists only because of
// pass-through — actually runs.
func scramLeakFixture(t *testing.T, password string) (*SCRAMAuth, *clientKeyStore) {
	t.Helper()
	verifier, err := GenerateSCRAMVerifier(password, 4096)
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}
	store := newClientKeyStore()
	auth.SetClientKeyStore(store)
	return auth, store
}

// runSCRAMLogin drives one full client/server exchange over a pipe and
// returns the server side's error, mirroring TestSCRAMAuthenticate.
func runSCRAMLogin(t *testing.T, auth *SCRAMAuth, user, password string) error {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	pg := pgproto3.NewBackend(serverConn, serverConn)
	startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": user}}

	serverErr := make(chan error, 1)
	go func() {
		err := auth.Authenticate(pg, serverConn, startup)
		serverErr <- err
		serverConn.Close()
	}()

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	clientErr := scramClientConversation(t, fe, user, password, nil)
	clientConn.Close()

	if err := <-serverErr; err != nil {
		return err
	}
	return clientErr
}

// TestSuccessfulLoginLogsNoCredentialMaterial is the main invariant: a
// login that works must leave no usable secret behind in the log.
func TestSuccessfulLoginLogsNoCredentialMaterial(t *testing.T) {
	const password = "correct-horse-battery-staple"
	auth, store := scramLeakFixture(t, password)

	logs := captureLogs(t)
	if err := runSCRAMLogin(t, auth, "alice", password); err != nil {
		t.Fatalf("login should have succeeded: %v", err)
	}

	pc, ok := store.lookup("alice")
	if !ok {
		t.Fatal("pass-through store holds no key for alice — the capture path did not run, so this test proves nothing")
	}

	out := logs.Bytes()
	assertNoSecret(t, out, pc.clientKey, "ClientKey")
	assertNoSecret(t, out, pc.creds.StoredKey, "StoredKey")
	assertNoSecret(t, out, pc.creds.ServerKey, "ServerKey")
	assertNoSecret(t, out, []byte(password), "the password")
	assertNoSecret(t, out, []byte(pc.creds.Salt), "the salt")
}

// TestFailedLoginLogsNoCredentialMaterial covers the paths that get
// touched when something is wrong — which is exactly when somebody
// reaches for an extra log line. A wrong password still produces a real
// client proof on the wire, so there is genuine secret material in
// scope even though the login fails.
func TestFailedLoginLogsNoCredentialMaterial(t *testing.T) {
	const password = "correct-horse-battery-staple"
	auth, _ := scramLeakFixture(t, password)

	logs := captureLogs(t)
	if err := runSCRAMLogin(t, auth, "alice", "wrong-password"); err == nil {
		t.Fatal("a wrong password was accepted")
	}

	out := logs.Bytes()
	assertNoSecret(t, out, []byte(password), "the real password")
	assertNoSecret(t, out, []byte("wrong-password"), "the attempted password")
}

// TestClientKeyRecoveryFailureLogsNoProof pins the one place that
// deliberately logs on the credential path.
//
// captureClientKey swallows a recovery failure and warns instead of
// refusing the login — the right call, since the client did
// authenticate. But it logs the error, and that error comes from code
// that has the client's proof in hand. The warning has to be useful
// enough to act on (it must name the user) without carrying the
// material that made it fail.
func TestClientKeyRecoveryFailureLogsNoProof(t *testing.T) {
	ex, creds := runSCRAM(t, "hunter2", nil)

	// A different user's verifier: the exchange is genuine, the stored
	// key it is checked against is not the one it was produced with.
	// That is the real-world case the warning exists for — pgman's
	// verifier not matching the backend's.
	_, otherCreds := runSCRAM(t, "a-different-password", nil)

	store := newClientKeyStore()
	auth := &SCRAMAuth{users: map[string]scram.StoredCredentials{}}
	auth.SetClientKeyStore(store)

	logs := captureLogs(t)
	auth.captureClientKey("alice", otherCreds, ex)

	if _, ok := store.lookup("alice"); ok {
		t.Fatal("a key that failed verification was stored anyway")
	}

	out := logs.Bytes()
	if !bytes.Contains(out, []byte("alice")) {
		t.Errorf("the warning does not name the user, so an operator cannot act on it\n--- log ---\n%s", out)
	}
	// The proof is the client-final message's p= field: the single most
	// sensitive thing in the exchange, and the value an error message
	// about a bad proof is most tempted to include.
	_, proof, err := splitClientFinal(ex.ClientFinal)
	if err != nil {
		t.Fatalf("test fixture: %v", err)
	}
	assertNoSecret(t, out, proof, "the client proof")
	assertNoSecret(t, out, creds.StoredKey, "the real StoredKey")
	assertNoSecret(t, out, []byte(ex.ClientFinal), "the client-final message")
}

// TestRecoverClientKeyErrorsCarryNoProof checks the error values
// themselves rather than the log, because an error is logged by
// whoever receives it — often with %v, often at a level nobody
// reviewed. An error that embeds the proof is a leak waiting for its
// first caller.
func TestRecoverClientKeyErrorsCarryNoProof(t *testing.T) {
	ex, creds := runSCRAM(t, "hunter2", nil)
	_, proof, err := splitClientFinal(ex.ClientFinal)
	if err != nil {
		t.Fatalf("test fixture: %v", err)
	}

	cases := map[string]scramExchange{
		"wrong verifier":     ex,
		"tampered gs2":       {ClientFirst: "no-comma", ServerFirst: ex.ServerFirst, ClientFinal: ex.ClientFinal},
		"tampered server":    {ClientFirst: ex.ClientFirst, ServerFirst: ex.ServerFirst + "x", ClientFinal: ex.ClientFinal},
		"proof not base64":   {ClientFirst: ex.ClientFirst, ServerFirst: ex.ServerFirst, ClientFinal: "c=biws,r=x,p=!!!"},
		"proof wrong size":   {ClientFirst: ex.ClientFirst, ServerFirst: ex.ServerFirst, ClientFinal: "c=biws,r=x,p=YWI="},
		"empty client-final": {ClientFirst: ex.ClientFirst, ServerFirst: ex.ServerFirst, ClientFinal: ""},
	}

	// Checked against a verifier that does not belong to this exchange,
	// so every case fails and every error message is exercised.
	_, otherCreds := runSCRAM(t, "a-different-password", nil)

	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := recoverClientKey(bad, otherCreds.StoredKey)
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := []byte(err.Error())
			assertNoSecret(t, msg, proof, "the client proof")
			assertNoSecret(t, msg, creds.StoredKey, "the StoredKey")
		})
	}
}
