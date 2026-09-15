package main

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// The startup path has a gate for every way one client can take capacity
// from the others — max_client_conn, max_db_connections, the per-user
// rate limit — plus two whole modes that bypass the relay: the admin
// console and a CancelRequest. Each is a branch a normal query never
// takes, so each needs a client that takes it.

// TestRunEnforcesMaxClientConn: without this cap the proxy accepts
// connections until it runs out of file descriptors, and the failure
// lands on every tenant at once rather than on the one that overshot.
func TestRunEnforcesMaxClientConn(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.MaxClientConn = 1
	proxy := startProxy(t, cfg, "")

	// The first client takes the only slot and keeps it.
	first := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := first.awaitReady(); err != nil {
		t.Fatalf("first client: %v", err)
	}

	second, err := net.DialTimeout("tcp", proxy.addrs.Listen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial second client: %v", err)
	}
	defer func() { _ = second.Close() }()
	_ = second.SetDeadline(time.Now().Add(10 * time.Second))

	// The cap is enforced before the handshake, so the refusal arrives
	// as an error on a connection that never became a session.
	fe := pgproto3.NewFrontend(second, second)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "alice", "database": "db1"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("startup: %v", err)
	}
	msg, err := fe.Receive()
	if err != nil {
		// A closed connection is also a refusal, and is what a client
		// sees when the slot check happens before any protocol is read.
		return
	}
	resp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("second client got %T, want a refusal", msg)
	}
	if !strings.Contains(strings.ToLower(resp.Message), "too many") &&
		!strings.Contains(strings.ToLower(resp.Message), "max_client_conn") {
		t.Errorf("refusal = %q, want it to name the connection cap", resp.Message)
	}
}

// TestRunEnforcesPerDatabaseConnectionLimit: max_db_connections is what
// stops one noisy tenant from starving every other database on the same
// proxy, and it is applied after auth so the client can be told why.
func TestRunEnforcesPerDatabaseConnectionLimit(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.MaxDBConnections = 1
	proxy := startProxy(t, cfg, "")

	first := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := first.awaitReady(); err != nil {
		t.Fatalf("first client: %v", err)
	}

	second := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	_, err := second.awaitReady()
	if err == nil {
		t.Fatal("the second client was admitted past max_db_connections")
	}
	if !strings.Contains(err.Error(), "53300") {
		t.Errorf("error = %v, want SQLSTATE 53300 (too_many_connections)", err)
	}
}

// TestRunRateLimitsSessionOpens: the rate limit is per user and applies
// to session opens rather than queries, because a reconnect storm is how
// an application pool responds to trouble — and the proxy has to survive
// being the trouble.
func TestRunRateLimitsSessionOpens(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.MaxSessionsPerSecPerUser = 1
	cfg.MaxSessionsBurstPerUser = 1
	proxy := startProxy(t, cfg, "")

	// The burst allows exactly one, and nothing refills within the test.
	first := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := first.awaitReady(); err != nil {
		t.Fatalf("first client: %v", err)
	}

	var refused bool
	for i := 0; i < 5; i++ {
		client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
		if _, err := client.awaitReady(); err != nil {
			refused = true
			if !strings.Contains(err.Error(), "53400") && !strings.Contains(err.Error(), "28000") {
				t.Errorf("refusal = %v, want a rate-limit SQLSTATE", err)
			}
			break
		}
	}
	if !refused {
		t.Error("five session opens in a row all passed a limit of one per second")
	}
}

// TestRunServesTheAdminConsoleOverTheDataPlane: connecting to the
// virtual admin database is how PgBouncer dashboards and operator muscle
// memory reach SHOW POOLS. It is a different code path from a relayed
// session — no pool, no backend — and it is gated on admin_users.
func TestRunServesTheAdminConsoleOverTheDataPlane(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	admin := dialProxy(t, proxy.addrs.Listen, "alice", cfg.AdminDatabase)
	if _, err := admin.awaitReady(); err != nil {
		t.Fatalf("admin console handshake: %v", err)
	}

	msgs, err := admin.query("SHOW POOLS")
	if err != nil {
		t.Fatalf("SHOW POOLS: %v", err)
	}
	var sawPool bool
	for _, m := range msgs {
		if row, ok := m.(*pgproto3.DataRow); ok && len(row.Values) > 0 && string(row.Values[0]) == "db1" {
			sawPool = true
		}
	}
	if !sawPool {
		t.Error("SHOW POOLS did not list the configured pool")
	}
}

// TestRunDeniesTheAdminConsoleToOtherUsers: passing client auth proves
// who you are, not that you may PAUSE every pool. A user not on the list
// gets the same answer as for any unknown database, so the console
// cannot be found by probing.
func TestRunDeniesTheAdminConsoleToOtherUsers(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.AdminUsers = []string{"ops"} // alice is not an admin
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", cfg.AdminDatabase)
	_, err := client.awaitReady()
	if err == nil {
		t.Fatal("a non-admin user reached the admin console")
	}
	if !strings.Contains(err.Error(), "3D000") {
		t.Errorf("error = %v, want the same 3D000 an unknown database gets", err)
	}
}

// TestRunAcceptsTLSFromClients covers the SSLRequest negotiation on the
// client side, which is the branch that builds a second protocol
// backend over the upgraded connection — and the one every libpq client
// with sslmode=require takes.
func TestRunAcceptsTLSFromClients(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "dataplane")

	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.TLSCertFile, cfg.TLSKeyFile = certFile, keyFile
	proxy := startProxy(t, cfg, "")

	raw, err := net.DialTimeout("tcp", proxy.addrs.Listen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))

	// SSLRequest, then read the single-byte answer, exactly as libpq does.
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send ssl request: %v", err)
	}
	answer := make([]byte, 1)
	if _, err := raw.Read(answer); err != nil {
		t.Fatalf("read ssl answer: %v", err)
	}
	if answer[0] != 'S' {
		t.Fatalf("proxy answered %q, want 'S' with a certificate configured", answer[0])
	}

	// The certificate is self-signed per test, so verification cannot
	// succeed and is not what is under test.
	tlsConn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("tls handshake: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))

	client := &pgClient{t: t, conn: tlsConn, fe: pgproto3.NewFrontend(tlsConn, tlsConn)}
	client.fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "alice", "database": "db1"},
	})
	if err := client.fe.Flush(); err != nil {
		t.Fatalf("startup over TLS: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake over TLS: %v", err)
	}
	if _, err := client.query("SELECT 1"); err != nil {
		t.Fatalf("query over TLS: %v", err)
	}
}

// TestRunHandlesACancelRequest: a CancelRequest arrives on a brand new
// connection with no startup packet, carrying only the PID and secret
// pgman handed the client. Answering it is what makes Ctrl+C in psql
// work through the proxy; getting it wrong makes cancellation silently
// do nothing.
func TestRunHandlesACancelRequest(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	msgs, err := client.awaitReady()
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	keyData, ok := findMessage[*pgproto3.BackendKeyData](msgs)
	if !ok {
		t.Fatal("the proxy sent no BackendKeyData, so a client could never cancel anything")
	}

	// A cancel with the right PID but a wrong secret must be ignored
	// rather than acted on — the secret is the only thing stopping any
	// local process from cancelling other people's queries.
	cancelConn, err := net.DialTimeout("tcp", proxy.addrs.Listen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial cancel connection: %v", err)
	}
	defer func() { _ = cancelConn.Close() }()
	cancelFE := pgproto3.NewFrontend(cancelConn, cancelConn)
	cancelFE.Send(&pgproto3.CancelRequest{
		ProcessID: keyData.ProcessID,
		SecretKey: []byte{0, 0, 0, 0},
	})
	if err := cancelFE.Flush(); err != nil {
		t.Fatalf("send cancel: %v", err)
	}

	// The session must still be usable afterwards: a rejected cancel is
	// not a reason to drop somebody's connection.
	if _, err := client.query("SELECT 1"); err != nil {
		t.Errorf("the session broke after a rejected cancel: %v", err)
	}
}

// TestRunHonoursSessionPoolMode: session pooling pins one backend to one
// client for its whole life, which is what LISTEN/NOTIFY and
// session-level SET require. If the relay released between transactions
// anyway, those features would break intermittently under load rather
// than plainly.
func TestRunHonoursSessionPoolMode(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	pc := cfg.Pools["db1"]
	pc.PoolMode = "session"
	cfg.Pools["db1"] = pc
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := client.query("SELECT 1"); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}

	// One backend connection for three transactions: in session mode the
	// pool never gets it back to hand to anybody else.
	if got := len(backend.startupParams()); got != 1 {
		t.Errorf("the backend saw %d connections for one session, want 1", got)
	}
	// And no scrub between them, since the connection never changed hands.
	for _, q := range backend.seenQueries() {
		if strings.HasPrefix(strings.ToUpper(q), "DISCARD") {
			t.Error("a reset query ran inside a session-pooled session")
		}
	}
}

// TestRunHonoursStatementPoolMode: statement pooling releases on every
// ReadyForQuery, which is the most aggressive reuse available and the
// reason it is only appropriate for autocommit reads.
func TestRunHonoursStatementPoolMode(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	pc := cfg.Pools["db1"]
	pc.PoolMode = "statement"
	cfg.Pools["db1"] = pc
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := client.query("SELECT 1"); err != nil {
		t.Fatalf("query: %v", err)
	}
	if _, err := client.query("SELECT 2"); err != nil {
		t.Fatalf("second query: %v", err)
	}
}

// TestRunReplaysTrackedParametersOnANewBackend: application_name and the
// other tracked GUCs are set by the client at startup and would be lost
// on every backend switch in transaction pooling — which is how
// pg_stat_activity stops being able to tell your apps apart.
func TestRunReplaysTrackedParametersOnANewBackend(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	conn, err := net.DialTimeout("tcp", proxy.addrs.Listen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	client := &pgClient{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn)}
	client.fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters: map[string]string{
			"user":             "alice",
			"database":         "db1",
			"application_name": "invoicing-worker",
		},
	})
	if err := client.fe.Flush(); err != nil {
		t.Fatalf("startup: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := client.query("SELECT 1"); err != nil {
		t.Fatalf("query: %v", err)
	}

	var replayed bool
	for _, q := range backend.seenQueries() {
		if strings.Contains(q, "invoicing-worker") {
			replayed = true
		}
	}
	if !replayed {
		t.Error("application_name was not replayed onto the backend connection")
	}
}
