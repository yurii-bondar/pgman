package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// The authentication paths on both sides of the proxy — SCRAM against
// pgman, and pgman's own handshake against Postgres — were the least
// covered code in the package at 3% and 11%, which is a poor place to
// have no tests: everything here decides who runs statements as whom.
//
// These drive the real exchanges against the fake Postgres in
// fakepg_test.go rather than asserting on intermediate values, because
// the failure mode that matters is "the other side rejected it", and
// only the other side can report that.

// scramLogin completes a SCRAM-SHA-256 exchange with the proxy as the
// client would, using the same library the proxy's server side uses.
func (c *pgClient) scramLogin(user, password string) error {
	c.t.Helper()

	msg, err := c.fe.Receive()
	if err != nil {
		return fmt.Errorf("await auth request: %w", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationSASL); !ok {
		return fmt.Errorf("expected AuthenticationSASL, got %T", msg)
	}

	client, err := scram.SHA256.NewClient(user, password, "")
	if err != nil {
		return err
	}
	conv := client.NewConversation()
	first, err := conv.Step("")
	if err != nil {
		return err
	}
	c.fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte(first)})
	if err := c.fe.Flush(); err != nil {
		return err
	}

	msg, err = c.fe.Receive()
	if err != nil {
		return fmt.Errorf("await sasl continue: %w", err)
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", msg)
	}
	final, err := conv.Step(string(cont.Data))
	if err != nil {
		return err
	}
	c.fe.Send(&pgproto3.SASLResponse{Data: []byte(final)})
	if err := c.fe.Flush(); err != nil {
		return err
	}

	msg, err = c.fe.Receive()
	if err != nil {
		return fmt.Errorf("await sasl final: %w", err)
	}
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		// The client verifies the server's signature too — a proxy that
		// accepted our proof but could not prove itself back would be
		// indistinguishable from a man in the middle.
		if _, err := conv.Step(string(m.Data)); err != nil {
			return fmt.Errorf("verify server signature: %w", err)
		}
		if !conv.Valid() {
			return fmt.Errorf("the server's signature did not verify")
		}
	case *pgproto3.ErrorResponse:
		return fmt.Errorf("%s %s: %s", m.Severity, m.Code, m.Message)
	default:
		return fmt.Errorf("expected AuthenticationSASLFinal, got %T", msg)
	}
	return nil
}

// scramConfig is testConfig with client-facing SCRAM instead of trust.
func scramConfig(t *testing.T, backend *fakePG, user, verifier string) *Config {
	t.Helper()
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.AllowInsecureTrustAuth = false
	cfg.AuthUsers = map[string]string{user: verifier}
	return cfg
}

// TestRunAuthenticatesClientWithSCRAM: the whole point of pgman holding
// verifiers rather than passwords is that this exchange works without
// either side learning the other's secret. If it breaks, no client
// authenticates at all.
func TestRunAuthenticatesClientWithSCRAM(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := scramConfig(t, backend, "alice", scramVerifierFor(t, "s3cret"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if err := client.scramLogin("alice", "s3cret"); err != nil {
		t.Fatalf("scram login: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("post-auth handshake: %v", err)
	}
	if _, err := client.query("SELECT 1"); err != nil {
		t.Fatalf("query after scram login: %v", err)
	}
}

// TestRunRejectsWrongPassword is the other half: a bad proof must end
// the connection with 28P01, the code every driver knows means "your
// credentials are wrong" rather than "retry".
func TestRunRejectsWrongPassword(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := scramConfig(t, backend, "alice", scramVerifierFor(t, "s3cret"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	err := client.scramLogin("alice", "wrong-password")
	if err == nil {
		t.Fatal("the proxy accepted a wrong password")
	}
	if !strings.Contains(err.Error(), "28P01") && !strings.Contains(err.Error(), "signature") {
		t.Errorf("error = %v, want an authentication failure", err)
	}
}

// TestRunDialsBackendOverTLS covers the backend-side SSLRequest
// negotiation, which is the only thing standing between "sslmode=require
// in the DSN" and credentials crossing the network in plain text.
func TestRunDialsBackendOverTLS(t *testing.T) {
	cert := generateTestCert(t)
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust, tls: &cert})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := client.query("SELECT 1"); err != nil {
		t.Fatalf("query over a TLS backend connection: %v", err)
	}
	if len(backend.startupParams()) == 0 {
		t.Error("the backend never completed a startup — the TLS upgrade did not happen")
	}
}

// TestRunReportsBackendAuthFailureToClient: when Postgres rejects the
// proxy's own credentials, the client must be told the backend is
// unavailable rather than left waiting. The distinction matters because
// 08006 tells a driver to retry elsewhere.
func TestRunReportsBackendAuthFailureToClient(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthReject})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("client handshake with the proxy: %v", err)
	}

	msgs, err := client.query("SELECT 1")
	// The session survives — only the query fails — so the error arrives
	// as an ErrorResponse followed by ReadyForQuery.
	if err != nil {
		t.Fatalf("the session was killed instead of the query failing: %v", err)
	}
	resp, ok := findMessage[*pgproto3.ErrorResponse](msgs)
	if !ok {
		t.Fatal("no error reported for a backend that refuses the proxy's credentials")
	}
	if resp.Code != "53300" && resp.Code != "08006" {
		t.Errorf("error code = %s, want 53300 or 08006", resp.Code)
	}
}

// TestRunPassthroughRunsStatementsAsTheClient is the property SCRAM
// pass-through exists for: the backend connection is opened as the role
// that authenticated to pgman, so GRANT, row-level security and
// pg_stat_activity all see the real user instead of one shared identity.
//
// It only works when pgman's verifier is the backend's verifier, which
// is why the fake server's salt and iteration count are used to build
// the one configured here.
func TestRunPassthroughRunsStatementsAsTheClient(t *testing.T) {
	const password = "alice-password"
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password})

	cfg := scramConfig(t, backend, "alice", fakePGVerifier(t, password))
	pc := cfg.Pools["db1"]
	pc.ScramPassthrough = true
	cfg.Pools["db1"] = pc

	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if err := client.scramLogin("alice", password); err != nil {
		t.Fatalf("scram login: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("post-auth handshake: %v", err)
	}
	msgs, err := client.query("SELECT 1")
	if err != nil {
		t.Fatalf("query through a pass-through pool: %v", err)
	}
	// Asserting on CommandComplete rather than on the startup parameters
	// alone: those are recorded before authentication, so a backend that
	// rejected the proof would still look like a successful connection.
	if resp, failed := findMessage[*pgproto3.ErrorResponse](msgs); failed {
		t.Fatalf("the query failed: %s %s", resp.Code, resp.Message)
	}
	if _, ok := findMessage[*pgproto3.CommandComplete](msgs); !ok {
		t.Fatal("no CommandComplete — the statement never ran on the backend")
	}

	params := backend.startupParams()
	if len(params) == 0 {
		t.Fatal("no backend connection was opened")
	}
	// The DSN says user=app; pass-through must override it with the
	// client's own role, having signed the backend's SCRAM challenge
	// with a ClientKey recovered from the client's exchange.
	if got := params[0]["user"]; got != "alice" {
		t.Errorf("backend connection opened as %q, want the client's role %q", got, "alice")
	}
}

// TestRunPassthroughFailsOnMismatchedVerifier pins the error an operator
// is most likely to hit: pgman's verifier for a user is not the one the
// backend holds, so the recovered ClientKey cannot produce a valid
// proof. Without a specific message this surfaces as "password
// authentication failed" and sends people hunting for a wrong password
// that does not exist.
func TestRunPassthroughFailsOnMismatchedVerifier(t *testing.T) {
	const password = "alice-password"
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password})

	// A verifier for the right password but with pgman's own random
	// salt — which is exactly what `pgman -gen-scram-verifier` produces.
	cfg := scramConfig(t, backend, "alice", scramVerifierFor(t, password))
	pc := cfg.Pools["db1"]
	pc.ScramPassthrough = true
	cfg.Pools["db1"] = pc

	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if err := client.scramLogin("alice", password); err != nil {
		t.Fatalf("scram login: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("post-auth handshake: %v", err)
	}

	msgs, err := client.query("SELECT 1")
	if err != nil {
		t.Fatalf("the session was killed instead of the query failing: %v", err)
	}
	resp, ok := findMessage[*pgproto3.ErrorResponse](msgs)
	if !ok {
		t.Fatal("a pass-through pool with the wrong verifier reported no error")
	}
	if !strings.Contains(resp.Message, "verifier") {
		t.Errorf("message = %q, want it to name the verifier mismatch", resp.Message)
	}
}

// TestRunResolvesUsersThroughAuthQuery: auth_query is how a deployment
// avoids listing every role in YAML, and it is the only path that reads
// a result set out of Postgres. A fake that answers with pg_shadow's two
// columns is enough to prove the plumbing, including the pgx round-trip.
func TestRunResolvesUsersThroughAuthQuery(t *testing.T) {
	const password = "bob-password"
	verifier := scramVerifierFor(t, password)

	backend := startFakePG(t, fakePGOptions{
		auth: fakeAuthTrust,
		rows: func(sql string) ([]string, [][]string) {
			if !strings.Contains(sql, "pg_shadow") {
				return nil, nil
			}
			return []string{"usename", "passwd"}, [][]string{{"bob", verifier}}
		},
	})

	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.AllowInsecureTrustAuth = false
	// No static users at all: bob exists only in the auth_query result.
	cfg.AuthUsers = map[string]string{}
	cfg.AuthQueryDSN = backend.dsn("authuser", "db1")
	cfg.AuthQueryCacheTTL = time.Minute
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "bob", "db1")
	if err := client.scramLogin("bob", password); err != nil {
		t.Fatalf("scram login for a user resolved through auth_query: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("post-auth handshake: %v", err)
	}

	var sawLookup bool
	for _, q := range backend.seenQueries() {
		if strings.Contains(q, "pg_shadow") {
			sawLookup = true
		}
	}
	if !sawLookup {
		t.Error("no auth_query lookup reached the backend")
	}
}

// TestAuthQueryProviderCachesAndInvalidates: the cache is what keeps a
// login storm from turning into a pg_shadow scan per connection, and
// Invalidate is what makes a password rotation take effect before the
// TTL expires.
func TestAuthQueryProviderCachesAndInvalidates(t *testing.T) {
	verifier := scramVerifierFor(t, "carol-password")
	backend := startFakePG(t, fakePGOptions{
		auth: fakeAuthTrust,
		rows: func(sql string) ([]string, [][]string) {
			if !strings.Contains(sql, "pg_shadow") {
				return nil, nil
			}
			return []string{"usename", "passwd"}, [][]string{{"carol", verifier}}
		},
	})

	provider := NewAuthQueryProvider(backend.dsn("authuser", "db1"), "", time.Minute)
	if _, err := provider.Lookup("carol"); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	first := len(backend.seenQueries())

	if _, err := provider.Lookup("carol"); err != nil {
		t.Fatalf("second lookup: %v", err)
	}
	if got := len(backend.seenQueries()); got != first {
		t.Errorf("the second lookup hit the backend again (%d → %d queries)", first, got)
	}

	provider.Invalidate("carol")
	if _, err := provider.Lookup("carol"); err != nil {
		t.Fatalf("lookup after invalidate: %v", err)
	}
	if got := len(backend.seenQueries()); got == first {
		t.Error("Invalidate did not force a fresh lookup, so a rotated password would keep failing")
	}
}

// TestAuthQueryProviderReportsAnUnknownUser: a missing row must be an
// error rather than an empty credential, or every unknown username would
// authenticate against a zero-valued verifier.
func TestAuthQueryProviderReportsAnUnknownUser(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{
		auth: fakeAuthTrust,
		rows: func(string) ([]string, [][]string) {
			// The columns exist; the user does not.
			return []string{"usename", "passwd"}, nil
		},
	})

	provider := NewAuthQueryProvider(backend.dsn("authuser", "db1"), "", time.Minute)
	if _, err := provider.Lookup("nobody"); err == nil {
		t.Fatal("an unknown user resolved successfully")
	}
}

// TestAuthQueryProviderReportsAnUnreachableBackend: auth_query is a
// network dependency of the login path, so its failure has to be
// reported rather than turned into a rejection — the difference between
// "your password is wrong" and "the auth database is down" is the
// difference between one incident and a long one.
func TestAuthQueryProviderReportsAnUnreachableBackend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ctx

	// Port 1 on loopback: nothing listens there and connecting fails
	// immediately rather than hanging.
	provider := NewAuthQueryProvider("postgres://u@127.0.0.1:1/db?sslmode=disable", "", time.Minute)
	if _, err := provider.Lookup("someone"); err == nil {
		t.Fatal("lookup against a dead backend reported success")
	}
}
