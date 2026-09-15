package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// The small pieces of main.go that the end-to-end tests in run_test.go
// reach only on their happy path: the pieces that exist for the failure
// cases, and the two protocol sub-relays a normal query never enters.

// TestSlogWriterBridgesStdlibLogging: dependencies still call
// log.Printf, and without this bridge those lines bypass the configured
// handler — so a deployment collecting JSON logs would silently lose
// whichever library decided to complain.
func TestSlogWriterBridgesStdlibLogging(t *testing.T) {
	n, err := slogWriter{}.Write([]byte("a message from some library\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// The contract io.Writer imposes: report the whole input as written,
	// including the newline that was trimmed before logging.
	if n != len("a message from some library\n") {
		t.Errorf("wrote %d bytes, want %d", n, len("a message from some library\n"))
	}
}

func TestFirstTokenSplitsOnTheLastSeparator(t *testing.T) {
	cases := map[string]string{
		// The point of the helper: log the host of a DSN without the
		// credentials in front of it.
		"postgres://user:pass@db.internal:5432/app": "db.internal:5432/app",
		// No separator means nothing is safe to log: returning the input
		// would print whatever the operator put in the field, which for
		// a DSN without an '@' could still be a password.
		"no-separator-here": "",
		"":                  "",
	}
	for in, want := range cases {
		if got := firstToken(in, "@"); got != want {
			t.Errorf("firstToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDsnRequiresTLSRecognisesWeakModes: require_backend_tls is enforced
// against this function, and "prefer" silently falls back to plain text
// if the server declines. Treating it as strict would make the setting a
// no-op precisely where it matters.
func TestDsnRequiresTLSRecognisesWeakModes(t *testing.T) {
	strict := []string{
		"postgres://u@h:5432/db?sslmode=require",
		"postgres://u@h:5432/db?sslmode=verify-ca",
		"postgres://u@h:5432/db?sslmode=verify-full",
	}
	weak := []string{
		"postgres://u@h:5432/db?sslmode=disable",
		"postgres://u@h:5432/db?sslmode=allow",
		"postgres://u@h:5432/db?sslmode=prefer",
		"postgres://u@h:5432/db", // unset ⇒ prefer
	}

	for _, dsn := range strict {
		if !dsnRequiresTLS(nil, dsn) {
			t.Errorf("dsnRequiresTLS(%q) = false, want true", dsn)
		}
	}
	for _, dsn := range weak {
		if dsnRequiresTLS(nil, dsn) {
			t.Errorf("dsnRequiresTLS(%q) = true — a mode that can fall back to plain text is not TLS", dsn)
		}
	}
}

// TestNewDialBackendRefusesWeakTLSWhenRequired: the check has to happen
// when the pool is built rather than at dial time, so an operator who
// sets require_backend_tls finds out from a failed startup instead of
// from a packet capture.
func TestNewDialBackendRefusesWeakTLSWhenRequired(t *testing.T) {
	dial := newDialBackend("postgres://u:p@127.0.0.1:5432/db?sslmode=disable", "127.0.0.1:5432", true)

	_, err := dial(context.Background())
	if err == nil {
		t.Fatal("a pool with sslmode=disable dialed successfully under require_backend_tls")
	}
	if !strings.Contains(err.Error(), "sslmode") {
		t.Errorf("error = %v, want it to name sslmode", err)
	}
}

// TestFailQueryDrainsAnExtendedBatchBeforeReporting is the protocol
// detail that keeps a failed Acquire from desynchronising the stream: in
// the extended protocol the client is mid-batch, and an error has to be
// followed by everything up to Sync being discarded, exactly as Postgres
// does it.
func TestFailQueryDrainsAnExtendedBatchBeforeReporting(t *testing.T) {
	clientSide, proxySide := net.Pipe()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = proxySide.Close() }()

	pg := pgproto3.NewBackend(proxySide, proxySide)
	fe := pgproto3.NewFrontend(clientSide, clientSide)

	// The client is part-way through Parse → Bind → Execute → Sync.
	go func() {
		fe.Send(&pgproto3.Bind{})
		fe.Send(&pgproto3.Execute{})
		fe.Send(&pgproto3.Sync{})
		_ = fe.Flush()
	}()

	done := make(chan error, 1)
	go func() {
		// Reported against the first message of the batch, which is not
		// terminal — so failQuery must read forward to the Sync.
		done <- failQuery(pg, &pgproto3.Parse{}, "53300", "no backend connection available")
	}()

	var sawError bool
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if resp, ok := msg.(*pgproto3.ErrorResponse); ok {
			sawError = true
			// ERROR, not FATAL: FATAL tells the driver to give up on the
			// connection, which is the reconnect storm this avoids.
			if resp.Severity != "ERROR" {
				t.Errorf("severity = %s, want ERROR", resp.Severity)
			}
			if resp.Code != "53300" {
				t.Errorf("code = %s, want 53300", resp.Code)
			}
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}
	if !sawError {
		t.Error("the client was sent ReadyForQuery with no error before it")
	}
	if err := <-done; err != nil {
		t.Errorf("failQuery: %v", err)
	}
}

// TestFailQueryReportsAClientThatHangsUpMidBatch: a client that
// disconnects while we are putting the protocol back together is not an
// error worth logging, and the caller needs to know to stop rather than
// keep writing to a dead socket.
func TestFailQueryReportsAClientThatHangsUpMidBatch(t *testing.T) {
	clientSide, proxySide := net.Pipe()
	defer func() { _ = proxySide.Close() }()

	pg := pgproto3.NewBackend(proxySide, proxySide)
	fe := pgproto3.NewFrontend(clientSide, clientSide)

	go func() {
		fe.Send(&pgproto3.Terminate{})
		_ = fe.Flush()
		_ = clientSide.Close()
	}()

	err := failQuery(pg, &pgproto3.Parse{}, "53300", "no backend connection available")
	if !errors.Is(err, errClientTerminated) {
		t.Errorf("failQuery = %v, want errClientTerminated", err)
	}
}

// TestRelayCopyInForwardsUntilTheClientEndsTheCopy: COPY IN flips the
// direction of the protocol, and the relay has to keep pumping until the
// client says it is done. Getting this wrong deadlocks the session — the
// backend waits for CopyData, the proxy waits for the backend.
func TestRelayCopyInForwardsUntilTheClientEndsTheCopy(t *testing.T) {
	clientSide, proxyClient := net.Pipe()
	proxyBackend, backendSide := net.Pipe()
	for _, c := range []net.Conn{clientSide, proxyClient, proxyBackend, backendSide} {
		defer func(c net.Conn) { _ = c.Close() }(c)
	}

	pg := pgproto3.NewBackend(proxyClient, proxyClient)
	fe := pgproto3.NewFrontend(proxyBackend, proxyBackend)

	done := make(chan error, 1)
	go func() { done <- relayCopyIn(pg, fe) }()

	client := pgproto3.NewFrontend(clientSide, clientSide)
	client.Send(&pgproto3.CopyData{Data: []byte("1,one\n")})
	client.Send(&pgproto3.CopyData{Data: []byte("2,two\n")})
	client.Send(&pgproto3.CopyDone{})
	if err := client.Flush(); err != nil {
		t.Fatalf("send copy data: %v", err)
	}

	backend := pgproto3.NewBackend(backendSide, backendSide)
	var dataFrames int
	for {
		msg, err := backend.Receive()
		if err != nil {
			t.Fatalf("backend receive: %v", err)
		}
		if _, ok := msg.(*pgproto3.CopyData); ok {
			dataFrames++
		}
		if _, ok := msg.(*pgproto3.CopyDone); ok {
			break
		}
	}
	if dataFrames != 2 {
		t.Errorf("backend saw %d CopyData frames, want 2", dataFrames)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("relayCopyIn: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("relayCopyIn did not return after CopyDone")
	}
}

// TestRelayCopyInSynthesizesCopyFailOnTerminate: a client that vanishes
// mid-copy leaves the backend expecting more data. Sending CopyFail is
// what makes it roll back instead of holding a half-finished copy open.
func TestRelayCopyInSynthesizesCopyFailOnTerminate(t *testing.T) {
	clientSide, proxyClient := net.Pipe()
	proxyBackend, backendSide := net.Pipe()
	for _, c := range []net.Conn{clientSide, proxyClient, proxyBackend, backendSide} {
		defer func(c net.Conn) { _ = c.Close() }(c)
	}

	pg := pgproto3.NewBackend(proxyClient, proxyClient)
	fe := pgproto3.NewFrontend(proxyBackend, proxyBackend)

	done := make(chan error, 1)
	go func() { done <- relayCopyIn(pg, fe) }()

	client := pgproto3.NewFrontend(clientSide, clientSide)
	client.Send(&pgproto3.Terminate{})
	if err := client.Flush(); err != nil {
		t.Fatalf("send terminate: %v", err)
	}

	backend := pgproto3.NewBackend(backendSide, backendSide)
	msg, err := backend.Receive()
	if err != nil {
		t.Fatalf("backend receive: %v", err)
	}
	if _, ok := msg.(*pgproto3.CopyFail); !ok {
		t.Errorf("backend received %T, want CopyFail", msg)
	}
	if err := <-done; err != nil {
		t.Errorf("relayCopyIn: %v", err)
	}
}

// TestReceiveStartupMessageRejectsUnsupportedFrames: GSSAPI encryption
// is refused with 'N' so the client falls back, while anything else is
// an error rather than something to guess at.
func TestReceiveStartupMessageRejectsUnsupportedFrames(t *testing.T) {
	t.Run("gss request is declined and the client continues", func(t *testing.T) {
		clientSide, proxySide := net.Pipe()
		defer func() { _ = clientSide.Close() }()
		defer func() { _ = proxySide.Close() }()

		pg := pgproto3.NewBackend(proxySide, proxySide)
		fe := pgproto3.NewFrontend(clientSide, clientSide)
		go func() {
			fe.Send(&pgproto3.GSSEncRequest{})
			_ = fe.Flush()
			// A 'N' comes back, then the client proceeds in plain text.
			buf := make([]byte, 1)
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
			fe.Send(&pgproto3.StartupMessage{
				ProtocolVersion: pgproto3.ProtocolVersionNumber,
				Parameters:      map[string]string{"user": "u", "database": "d"},
			})
			_ = fe.Flush()
		}()

		msg, _, _, err := receiveStartupMessage(pg, proxySide, nil, 0)
		if err != nil {
			t.Fatalf("receiveStartupMessage: %v", err)
		}
		if _, ok := msg.(*pgproto3.StartupMessage); !ok {
			t.Errorf("got %T, want StartupMessage after the declined GSS request", msg)
		}
	})

	t.Run("ssl request without a certificate is declined", func(t *testing.T) {
		clientSide, proxySide := net.Pipe()
		defer func() { _ = clientSide.Close() }()
		defer func() { _ = proxySide.Close() }()

		pg := pgproto3.NewBackend(proxySide, proxySide)
		fe := pgproto3.NewFrontend(clientSide, clientSide)
		go func() {
			fe.Send(&pgproto3.SSLRequest{})
			_ = fe.Flush()
			buf := make([]byte, 1)
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
			if buf[0] != 'N' {
				t.Errorf("proxy answered %q to SSLRequest with no certificate configured, want 'N'", buf[0])
			}
			fe.Send(&pgproto3.CancelRequest{ProcessID: 1, SecretKey: secretBytes(2)})
			_ = fe.Flush()
		}()

		msg, _, _, err := receiveStartupMessage(pg, proxySide, nil, 0)
		if err != nil {
			t.Fatalf("receiveStartupMessage: %v", err)
		}
		if _, ok := msg.(*pgproto3.CancelRequest); !ok {
			t.Errorf("got %T, want CancelRequest", msg)
		}
	})
}

// TestApplyRuntimeLimitsWiresTheOptionalGates: each of these is off
// unless configured, and each is the only thing standing between one
// tenant and every other tenant's capacity.
func TestApplyRuntimeLimitsWiresTheOptionalGates(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	t.Run("nothing configured leaves every gate nil", func(t *testing.T) {
		cfg := &Config{}
		opts := &runtimeOpts{}
		applyRuntimeLimits(cfg, opts, registry)

		if opts.connLimiter != nil {
			t.Error("a connection limiter was created with no limits configured")
		}
		if opts.userRateLimiter != nil {
			t.Error("a rate limiter was created with no rate configured")
		}
		if opts.adminSession != nil {
			t.Error("the admin console was wired up with no admin_database")
		}
	})

	t.Run("configured limits are wired", func(t *testing.T) {
		cfg := &Config{
			MaxDBConnections:         10,
			MaxUserConnections:       5,
			MaxSessionsPerSecPerUser: 3,
			// Burst left at zero on purpose: it must default to the rate
			// rather than to "no burst allowed", which would refuse every
			// second connection.
		}
		opts := &runtimeOpts{adminDatabase: "pgbouncer"}
		applyRuntimeLimits(cfg, opts, registry)

		if opts.connLimiter == nil {
			t.Error("max_db_connections was configured but no limiter was built")
		}
		if opts.userRateLimiter == nil {
			t.Error("max_sessions_per_sec_per_user was configured but no limiter was built")
		}
		if opts.adminSession == nil {
			t.Error("admin_database is set but no admin session handler was wired")
		}
	})
}

// TestBuildDataPlaneTLSLoadsCertificateAndClientCA covers the mTLS
// branch: the client-CA bundle turns on VerifyClientCertIfGiven, which
// is what lets HBA METHOD=cert identify a client by its certificate
// while other clients still authenticate with a password.
func TestBuildDataPlaneTLSLoadsCertificateAndClientCA(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "server")

	t.Run("no certificate configured", func(t *testing.T) {
		tlsConfig, cert, err := buildDataPlaneTLS(&Config{})
		if err != nil || tlsConfig != nil || cert != nil {
			t.Errorf("got (%v, %v, %v), want all nil — plain text is a valid setup", tlsConfig, cert, err)
		}
	})

	t.Run("certificate only", func(t *testing.T) {
		tlsConfig, cert, err := buildDataPlaneTLS(&Config{TLSCertFile: certFile, TLSKeyFile: keyFile})
		if err != nil {
			t.Fatalf("buildDataPlaneTLS: %v", err)
		}
		if cert == nil {
			t.Error("the leaf certificate was not returned — SCRAM channel binding needs it")
		}
		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %x, want TLS 1.2", tlsConfig.MinVersion)
		}
		if tlsConfig.ClientAuth != tls.NoClientCert {
			t.Errorf("ClientAuth = %v with no client CA configured, want NoClientCert", tlsConfig.ClientAuth)
		}
	})

	t.Run("certificate plus client CA", func(t *testing.T) {
		// The server certificate doubles as its own CA bundle here; what
		// is under test is the plumbing, not the trust chain.
		tlsConfig, _, err := buildDataPlaneTLS(&Config{
			TLSCertFile:     certFile,
			TLSKeyFile:      keyFile,
			TLSClientCAFile: certFile,
		})
		if err != nil {
			t.Fatalf("buildDataPlaneTLS: %v", err)
		}
		if tlsConfig.ClientAuth != tls.VerifyClientCertIfGiven {
			t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven so password clients still connect",
				tlsConfig.ClientAuth)
		}
		if tlsConfig.ClientCAs == nil {
			t.Error("the client CA pool was not populated")
		}
	})

	t.Run("client CA file that is not PEM", func(t *testing.T) {
		junk := filepath.Join(dir, "junk.crt")
		if err := os.WriteFile(junk, []byte("this is not a certificate"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, _, err := buildDataPlaneTLS(&Config{
			TLSCertFile:     certFile,
			TLSKeyFile:      keyFile,
			TLSClientCAFile: junk,
		})
		if err == nil {
			t.Fatal("a file with no certificates in it was accepted as a CA bundle")
		}
		if !strings.Contains(err.Error(), "no valid PEM") {
			t.Errorf("error = %v, want it to say the file held no certificates", err)
		}
	})
}

// TestBuildAuthBackendFallsBackToTrust: trust is what
// allow_insecure_trust_auth asks for, and it must be reachable only that
// way — a config with users must never silently end up here.
func TestBuildAuthBackendFallsBackToTrust(t *testing.T) {
	backend, err := buildAuthBackend(&Config{}, nil, nil)
	if err != nil {
		t.Fatalf("buildAuthBackend: %v", err)
	}
	if _, ok := backend.(TrustAuth); !ok {
		t.Errorf("got %T, want TrustAuth when no users are configured", backend)
	}

	withUsers, err := buildAuthBackend(&Config{
		AuthUsers: map[string]string{"alice": scramVerifierFor(t, "pw")},
	}, nil, nil)
	if err != nil {
		t.Fatalf("buildAuthBackend: %v", err)
	}
	if _, ok := withUsers.(TrustAuth); ok {
		t.Error("a config with auth_users produced trust auth")
	}
}

// TestBuildAuthBackendRejectsABrokenVerifier: a typo in a verifier has
// to stop startup. Accepting it would leave a user who can never
// authenticate and no indication why.
func TestBuildAuthBackendRejectsABrokenVerifier(t *testing.T) {
	_, err := buildAuthBackend(&Config{
		AuthUsers: map[string]string{"alice": "not-a-verifier"},
	}, nil, nil)
	if err == nil {
		t.Fatal("a malformed verifier was accepted")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Errorf("error = %v, want it to name the auth backend", err)
	}
}

// TestCLIHandlesTheModesThatNeverStartAProxy: three of pgman's four
// flags print something and exit, and two of them are how an operator
// produces the credentials the config file needs. A binary that cannot
// do that leaves them looking for a Python one-liner to hash a password.
func TestCLIHandlesTheModesThatNeverStartAProxy(t *testing.T) {
	t.Run("version", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := cli([]string{"-version"}, &out, &errOut); code != 0 {
			t.Fatalf("exit code = %d, want 0; stderr = %q", code, errOut.String())
		}
		if !strings.Contains(out.String(), version) {
			t.Errorf("output = %q, want it to contain the version %q", out.String(), version)
		}
	})

	t.Run("scram verifier", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := cli([]string{"-gen-scram-verifier", "hunter2"}, &out, &errOut); code != 0 {
			t.Fatalf("exit code = %d, want 0; stderr = %q", code, errOut.String())
		}
		// The output goes straight into auth_users, so it has to be the
		// format the parser accepts — not merely non-empty.
		if _, err := ParseSCRAMVerifier(strings.TrimSpace(out.String())); err != nil {
			t.Errorf("the printed verifier does not parse: %v", err)
		}
	})

	t.Run("admin password hash", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := cli([]string{"-gen-admin-password", "hunter2"}, &out, &errOut); code != 0 {
			t.Fatalf("exit code = %d, want 0; stderr = %q", code, errOut.String())
		}
		hash := strings.TrimSpace(out.String())
		if !strings.HasPrefix(hash, "$2") {
			t.Errorf("hash = %q, want a bcrypt hash — loadConfig rejects anything else", hash)
		}
	})

	t.Run("unknown flag", func(t *testing.T) {
		var out, errOut strings.Builder
		if code := cli([]string{"-nope"}, &out, &errOut); code != 2 {
			t.Errorf("exit code = %d, want 2 for a usage error", code)
		}
	})

	t.Run("missing config file", func(t *testing.T) {
		var out, errOut strings.Builder
		code := cli([]string{"-config", filepath.Join(t.TempDir(), "nope.yaml")}, &out, &errOut)
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if !strings.Contains(errOut.String(), "config") {
			t.Errorf("stderr = %q, want it to name the config failure", errOut.String())
		}
	})
}
