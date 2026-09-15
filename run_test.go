package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// run() is the whole proxy: pools, four listeners, the HTTP surfaces,
// signals and the ordered drain. It was untestable while it was main() —
// its failures ended in os.Exit and its ports came from a config file —
// and it was also, by a wide margin, the largest untested thing here.
//
// These tests drive the real thing against the fake Postgres in
// fakepg_test.go, on ephemeral ports, and stop it by cancelling the
// context the way a signal does.

// testConfig is a minimal working configuration: trust auth, one pool
// pointed at addr, every listener on an ephemeral loopback port.
func testConfig(t *testing.T, backendAddr, backendDSN string) *Config {
	t.Helper()
	cfg := &Config{
		ListenAddr:             "127.0.0.1:0",
		MetricsAddr:            "127.0.0.1:0",
		AdminAddr:              "127.0.0.1:0",
		AllowInsecureTrustAuth: true,
		AdminUsers:             []string{"alice"},
		Pools: map[string]PoolConfig{
			"db1": {BackendDSN: backendDSN, BackendAddr: backendAddr, Limit: 2},
		},
		// Short enough that a test does not wait on a drain, long enough
		// that it is not the thing under test.
		ShutdownTimeout: 2 * time.Second,
	}
	cfg.applyDefaults()
	// applyDefaults picks 120s, which would make a saturated-pool test
	// hang rather than fail.
	cfg.QueryWaitTimeout = 2 * time.Second
	return cfg
}

// awaitAddrs waits for run to report the addresses it bound, failing the
// test rather than the package's timeout if it never does. Every wait on
// a proxy in this file goes through this or awaitRun: an unbounded
// receive turns one stuck test into a ten-minute CI failure that names no
// test at all.
func awaitAddrs(t *testing.T, readyCh <-chan runtimeAddrs, errCh <-chan error) runtimeAddrs {
	t.Helper()
	select {
	case addrs := <-readyCh:
		return addrs
	case err := <-errCh:
		t.Fatalf("run returned before it was ready: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("run never reported ready")
	}
	return runtimeAddrs{}
}

// awaitRun waits for run to unwind after its context was cancelled.
func awaitRun(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(60 * time.Second):
		t.Fatal("run did not return after its context was cancelled")
	}
	return nil
}

type runningProxy struct {
	addrs runtimeAddrs
	errCh chan error
	stop  context.CancelFunc
	// once guards the wait on errCh: a test that shuts the proxy down
	// itself — to assert on what shutdown left behind — would otherwise
	// have the deferred cleanup wait for a second value that never comes.
	once sync.Once
}

// startProxy runs the proxy in a goroutine and waits for it to report the
// addresses it bound. The returned proxy is stopped by the test's
// cleanup, which is also what asserts run() returns.
func startProxy(t *testing.T, cfg *Config, configPath string) *runningProxy {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan runtimeAddrs, 1)
	errCh := make(chan error, 1)

	go func() {
		errCh <- run(ctx, cfg, configPath, func(a runtimeAddrs) { readyCh <- a })
	}()

	var addrs runtimeAddrs
	select {
	case addrs = <-readyCh:
	case err := <-errCh:
		cancel()
		t.Fatalf("run returned before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("run never reported ready")
	}

	p := &runningProxy{addrs: addrs, errCh: errCh, stop: cancel}
	t.Cleanup(func() { p.shutdown(t) })
	return p
}

// shutdown cancels the context and waits for run to unwind, which is the
// only way to know the drain finished rather than the test just ending.
func (p *runningProxy) shutdown(t *testing.T) {
	t.Helper()
	p.once.Do(func() {
		p.stop()
		select {
		case err := <-p.errCh:
			if err != nil && !errors.Is(err, errDrainIncomplete) {
				t.Errorf("run returned %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("run did not return after its context was cancelled")
		}
	})
}

// pgClient is a client connection to the proxy, speaking the protocol
// directly rather than through pgconn: these tests are about pgman's
// half of the exchange, and a driver would hide it.
type pgClient struct {
	t    *testing.T
	conn net.Conn
	fe   *pgproto3.Frontend
}

func dialProxy(t *testing.T, addr, user, database string) *pgClient {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	c := &pgClient{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn)}
	c.fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": user, "database": database},
	})
	if err := c.fe.Flush(); err != nil {
		t.Fatalf("send startup: %v", err)
	}
	return c
}

// awaitReady reads until ReadyForQuery, returning everything it saw so a
// test can assert on the handshake as well as on its outcome.
func (c *pgClient) awaitReady() ([]pgproto3.BackendMessage, error) {
	c.t.Helper()
	var msgs []pgproto3.BackendMessage
	for {
		msg, err := c.fe.Receive()
		if err != nil {
			return msgs, err
		}
		msgs = append(msgs, cloneBackendMessage(msg))
		switch m := msg.(type) {
		case *pgproto3.ReadyForQuery:
			return msgs, nil
		case *pgproto3.ErrorResponse:
			if m.Severity == "FATAL" {
				return msgs, fmt.Errorf("%s %s: %s", m.Severity, m.Code, m.Message)
			}
		}
	}
}

func (c *pgClient) query(sql string) ([]pgproto3.BackendMessage, error) {
	c.t.Helper()
	c.fe.Send(&pgproto3.Query{String: sql})
	if err := c.fe.Flush(); err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}
	return c.awaitReady()
}

// httpGet is the shortest way to assert an HTTP surface is actually
// answering on the port run() reported.
func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

// TestRunServesAQueryEndToEnd is the test the whole refactor was for: a
// client connects to the proxy, the proxy dials the backend, and the
// answer comes back. Everything in between — accept loop, trust auth,
// routing, Acquire, the backend handshake, the relay, the reset query —
// runs for real.
func TestRunServesAQueryEndToEnd(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("proxy handshake: %v", err)
	}

	msgs, err := client.query("SELECT 1")
	if err != nil {
		t.Fatalf("query through the proxy: %v", err)
	}
	if _, ok := findMessage[*pgproto3.CommandComplete](msgs); !ok {
		t.Errorf("no CommandComplete in %d messages", len(msgs))
	}

	// The backend must have been dialed with the DSN's user, not the
	// client's — that is the forced-user behaviour every pool has unless
	// backend_users or pass-through says otherwise.
	params := backend.startupParams()
	if len(params) == 0 {
		t.Fatal("the proxy never opened a backend connection")
	}
	if got := params[0]["user"]; got != "app" {
		t.Errorf("backend connection opened as %q, want the DSN's user %q", got, "app")
	}
	if got := params[0]["database"]; got != "db1" {
		t.Errorf("backend database = %q, want %q", got, "db1")
	}
}

// TestRunExposesProbesAndMetrics: these are the surfaces a kubelet and a
// Prometheus server talk to, and they are the ones nobody notices are
// broken until a deploy stalls.
func TestRunExposesProbesAndMetrics(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	if code, _ := httpGet(t, "http://"+proxy.addrs.Metrics+"/health"); code != http.StatusOK {
		t.Errorf("/health = %d, want 200", code)
	}
	if code, _ := httpGet(t, "http://"+proxy.addrs.Metrics+"/ready"); code != http.StatusOK {
		t.Errorf("/ready = %d, want 200 with a live pool", code)
	}

	code, body := httpGet(t, "http://"+proxy.addrs.Metrics+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d, want 200", code)
	}
	for _, want := range []string{
		"pgman_build_info",
		`pgman_pool_limit{pool="db1"}`,
		`pgbouncer_databases_pool_size{database="db1"}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics does not export %s", want)
		}
	}
}

// TestRunServesTheAdminDashboard: the admin listener binds to loopback
// and, unauthenticated, may only be reached from there — which is
// exactly where this test is.
func TestRunServesTheAdminDashboard(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	code, body := httpGet(t, "http://"+proxy.addrs.Admin+"/")
	if code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", code)
	}
	if !strings.Contains(body, "db1") {
		t.Error("the dashboard does not list the configured pool")
	}
	// The scripts have to come from the binary; a CDN reference here
	// would mean the dashboard needs public internet to work.
	if !strings.Contains(body, `src="/static/htmx.min.js"`) {
		t.Error("the dashboard does not load htmx from /static/")
	}
	if code, _ := httpGet(t, "http://"+proxy.addrs.Admin+"/static/htmx.min.js"); code != http.StatusOK {
		t.Errorf("GET /static/htmx.min.js = %d, want 200", code)
	}
}

// TestRunStopsListeningAfterShutdown: the drain has to actually release
// the port, or a restart lands on EADDRINUSE.
func TestRunStopsListeningAfterShutdown(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))

	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan runtimeAddrs, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, cfg, "", func(a runtimeAddrs) { readyCh <- a }) }()

	addrs := awaitAddrs(t, readyCh, errCh)
	// Reachable while up.
	conn, err := net.DialTimeout("tcp", addrs.Listen, 5*time.Second)
	if err != nil {
		t.Fatalf("dial while up: %v", err)
	}
	_ = conn.Close()

	cancel()
	if err := awaitRun(t, errCh); err != nil {
		t.Fatalf("run: %v", err)
	}

	if conn, err := net.DialTimeout("tcp", addrs.Listen, time.Second); err == nil {
		_ = conn.Close()
		t.Error("the data-plane port still accepts connections after shutdown")
	}
}

// TestRunFailsWhenAPortIsTaken: these listeners used to bind inside
// their own goroutines, so an address already in use logged an error
// behind a proxy that had already announced itself as up — and then ran
// without the surface an operator was relying on.
func TestRunFailsWhenAPortIsTaken(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	squatter, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = squatter.Close() }()

	cases := map[string]func(*Config){
		"data plane": func(c *Config) { c.ListenAddr = squatter.Addr().String() },
		"metrics":    func(c *Config) { c.MetricsAddr = squatter.Addr().String() },
		"admin":      func(c *Config) { c.AdminAddr = squatter.Addr().String() },
	}
	for name, taint := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
			taint(cfg)

			err := run(context.Background(), cfg, "", func(runtimeAddrs) {
				t.Error("run reported ready with a port it could not bind")
			})
			if err == nil {
				t.Fatal("run succeeded with an address already in use")
			}
			if !strings.Contains(err.Error(), "address already in use") {
				t.Errorf("error = %v, want it to name the bind failure", err)
			}
		})
	}
}

// TestRunFailsOnBrokenConfiguration walks the startup failure paths.
// Each one used to be a stdlog.Fatalf, so none of them could be
// exercised — and each is a plausible operator mistake.
func TestRunFailsOnBrokenConfiguration(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	dir := t.TempDir()

	cases := []struct {
		name  string
		taint func(*Config)
		want  string
	}{
		{
			name: "missing data-plane certificate",
			taint: func(c *Config) {
				c.TLSCertFile = filepath.Join(dir, "nope.crt")
				c.TLSKeyFile = filepath.Join(dir, "nope.key")
			},
			want: "tls:",
		},
		{
			name:  "missing client CA bundle",
			taint: func(c *Config) { c.TLSClientCAFile = filepath.Join(dir, "nope-ca.crt") },
			want:  "tls_client_ca_file",
		},
		{
			name:  "missing hba file",
			taint: func(c *Config) { c.AuthHBAFile = filepath.Join(dir, "nope.hba") },
			want:  "auth_hba_file",
		},
		{
			name:  "unwritable audit log",
			taint: func(c *Config) { c.AuditLogPath = filepath.Join(dir, "no-such-dir", "audit.log") },
			want:  "audit_log_path",
		},
		{
			name: "admin TLS certificate missing",
			taint: func(c *Config) {
				c.AdminTLSCertFile, c.AdminTLSKeyFile = filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")
			},
			want: "admin tls",
		},
		{
			// A directory that cannot be created, rather than one that
			// merely does not exist: openUnixSocket calls MkdirAll, so a
			// missing directory is created and is not a failure at all.
			// A path with a regular file in the middle of it cannot be,
			// on any platform.
			name: "unix socket dir cannot be created",
			taint: func(c *Config) {
				blocker := filepath.Join(dir, "not-a-directory")
				if err := os.WriteFile(blocker, []byte("in the way"), 0o600); err != nil {
					t.Fatalf("write blocker: %v", err)
				}
				c.UnixSocketDir = filepath.Join(blocker, "socket")
			},
			want: "unix socket",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
			// A client CA is only read when a server certificate exists,
			// so that case needs a real pair underneath it.
			if tc.name == "missing client CA bundle" {
				certFile, keyFile := writeCertPair(t, dir, "dataplane")
				cfg.TLSCertFile, cfg.TLSKeyFile = certFile, keyFile
			}
			tc.taint(cfg)

			// A cancellable context, because a case whose premise is
			// wrong must fail rather than hang: run blocks on ctx.Done
			// once it is up, so with context.Background() an expectation
			// that does not hold costs the whole package its timeout —
			// which is exactly what one of these cases did.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			err := run(ctx, cfg, "", func(runtimeAddrs) {
				t.Error("run reported ready despite a broken configuration")
				cancel()
			})
			if err == nil {
				t.Fatal("run succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestRunServesOverUnixSocket: a local client on the Unix socket is what
// HBA METHOD=peer is for, and the socket is also the one listener whose
// teardown has to remove a file.
func TestRunServesOverUnixSocket(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	// macOS caps sun_path at 104 bytes and t.TempDir() under
	// TMPDIR can be long, so keep the directory short.
	dir, err := os.MkdirTemp("", "pgm")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg.UnixSocketDir = dir

	proxy := startProxy(t, cfg, "")
	if proxy.addrs.UnixSocket == "" {
		t.Fatal("run did not report a unix socket path")
	}
	if _, err := os.Stat(proxy.addrs.UnixSocket); err != nil {
		t.Fatalf("socket file: %v", err)
	}

	conn, err := net.DialTimeout("unix", proxy.addrs.UnixSocket, 5*time.Second)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	client := &pgClient{t: t, conn: conn, fe: pgproto3.NewFrontend(conn, conn)}
	client.fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "alice", "database": "db1"},
	})
	if err := client.fe.Flush(); err != nil {
		t.Fatalf("startup over unix socket: %v", err)
	}
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake over unix socket: %v", err)
	}

	socketPath := proxy.addrs.UnixSocket
	proxy.shutdown(t)
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Errorf("socket file survived shutdown (stat err = %v) — a restart would hit EADDRINUSE", err)
	}
}

// TestRunReloadsPoolsOnSIGHUP exercises the signal path end to end: the
// file gains a pool, the process is signalled, and the new pool becomes
// visible on the metrics surface without a restart.
func TestRunReloadsPoolsOnSIGHUP(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	dsn := backend.dsn("app", "db1")

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, map[string]string{"db1": dsn}, backend.addr())

	cfg := testConfig(t, backend.addr(), dsn)
	proxy := startProxy(t, cfg, path)

	// Now the file says two pools.
	writeConfigFile(t, path, map[string]string{"db1": dsn, "db2": dsn}, backend.addr())
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := httpGet(t, "http://"+proxy.addrs.Metrics+"/metrics")
		if strings.Contains(body, `pgman_pool_limit{pool="db2"}`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the pool added to the config file never appeared after SIGHUP")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestRunReportsIncompleteDrain: a session that outstays the shutdown
// budget must make the process exit non-zero, because that is how k8s
// and systemd find out this instance did not drain in time.
func TestRunReportsIncompleteDrain(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	cfg.ShutdownTimeout = 300 * time.Millisecond
	// Otherwise the idle client below is closed by the timeout instead of
	// being the thing that holds the drain open.
	cfg.ClientIdleTimeout = -1

	ctx, cancel := context.WithCancel(context.Background())
	readyCh := make(chan runtimeAddrs, 1)
	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx, cfg, "", func(a runtimeAddrs) { readyCh <- a }) }()
	addrs := awaitAddrs(t, readyCh, errCh)

	// A client that finishes its handshake and then says nothing: its
	// goroutine is alive, so the drain cannot complete.
	client := dialProxy(t, addrs.Listen, "alice", "db1")
	if _, err := client.awaitReady(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	cancel()
	// Let the deadline expire, then let the client go so the
	// post-deadline wait finishes quickly rather than burning the full
	// grace period.
	time.Sleep(500 * time.Millisecond)
	_ = client.conn.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, errDrainIncomplete) {
			t.Errorf("run returned %v, want errDrainIncomplete", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run never returned")
	}
}

// TestRunRejectsClientsForAnUnknownDatabase: routing failures have to be
// reported as FATAL to the client rather than dropped, or a driver sees
// a reset and retries forever.
func TestRunRejectsClientsForAnUnknownDatabase(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := testConfig(t, backend.addr(), backend.dsn("app", "db1"))
	proxy := startProxy(t, cfg, "")

	client := dialProxy(t, proxy.addrs.Listen, "alice", "nosuchdb")
	_, err := client.awaitReady()
	if err == nil {
		t.Fatal("the proxy accepted a client for a database it does not serve")
	}
	if !strings.Contains(err.Error(), "3D000") {
		t.Errorf("error = %v, want SQLSTATE 3D000 (invalid_catalog_name)", err)
	}
}
