//go:build integration

// Package integration provides black-box integration tests for pgman.
//
// Instead of importing internal symbols (package main cannot be
// imported), these tests build the pgman binary, start it as a
// subprocess with a generated config, and exercise the full data path
// through pgx. This gives us true end-to-end coverage including
// config parsing, signal handling, and port binding.
//
// Prerequisites:
//
//	docker compose -f ../../docker-compose.yaml up -d postgres
//
// Run:
//
//	go test -tags integration -race -timeout 120s -v ./...
package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---- Shared state ---------------------------------------------------

var (
	// pgmanBin is the path to the compiled pgman binary, built
	// once in TestMain.
	pgmanBin string

	// pgDSN is the DSN for the real Postgres (docker-compose service).
	pgDSN string
)

const defaultPGDSN = "postgres://pgman_test:pgman_test@127.0.0.1:15432/pgman_test?sslmode=disable"

func TestMain(m *testing.M) {
	pgDSN = os.Getenv("PGMAN_TEST_PG_DSN")
	if pgDSN == "" {
		pgDSN = defaultPGDSN
	}

	// Quick PG connectivity check.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := pgx.Connect(ctx, pgDSN)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SKIP: real Postgres not reachable at %s: %v\n", pgDSN, err)
		os.Exit(0)
	}
	conn.Close(context.Background())

	// Build the pgman binary once for all tests.
	tmp, err := os.MkdirTemp("", "pgman-integ-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "tmpdir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	bin := filepath.Join(tmp, "pgman")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	// Build from the pgman package root (two dirs up from tests/integration/).
	// -race is opt-in via PGMAN_TEST_RACE=1 — otherwise we build the
	// production-style binary so soak/benchmark numbers reflect real
	// throughput, not race-detector overhead (2-10x slower).
	pkgDir, _ := filepath.Abs(filepath.Join("..", ".."))
	buildArgs := []string{"build", "-o", bin}
	if os.Getenv("PGMAN_TEST_RACE") == "1" {
		buildArgs = append(buildArgs, "-race")
	}
	buildArgs = append(buildArgs, ".")
	build := exec.Command("go", buildArgs...)
	build.Dir = pkgDir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n", err)
		os.Exit(1)
	}
	pgmanBin = bin

	os.Exit(m.Run())
}

// ---- Proxy harness --------------------------------------------------

// proxyInstance represents a running pgman subprocess.
type proxyInstance struct {
	ProxyAddr   string // host:port for PG wire connections
	MetricsAddr string // host:port for Prometheus /metrics
	AdminAddr   string // host:port for admin UI / REST API
	cmd         *exec.Cmd
	configPath  string
	cancel      context.CancelFunc
}

// startProxy launches a pgman subprocess on random ports, wired
// to the real Postgres. Registers cleanup to kill on test end.
func startProxy(t *testing.T, poolLimit int) *proxyInstance {
	t.Helper()

	// Find two free ports — one for PG wire, one for metrics.
	proxyPort := freePort(t)
	metricsPort := freePort(t)
	adminPort := freePort(t)

	cfg := configYAML(proxyPort, metricsPort, adminPort, poolLimit)

	tmpCfg, err := os.CreateTemp("", "pgman-cfg-*.yaml")
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if _, err := tmpCfg.WriteString(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	tmpCfg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := startPgmanCmd(ctx, tmpCfg.Name())

	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmpCfg.Name())
		t.Fatalf("start pgman: %v", err)
	}

	inst := &proxyInstance{
		ProxyAddr:   fmt.Sprintf("127.0.0.1:%d", proxyPort),
		MetricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort),
		AdminAddr:   fmt.Sprintf("127.0.0.1:%d", adminPort),
		cmd:         cmd,
		configPath:  tmpCfg.Name(),
		cancel:      cancel,
	}

	// Wait until proxy is accepting connections (poll up to 5s).
	if err := waitForPort(t, inst.ProxyAddr, 5*time.Second); err != nil {
		cancel()
		cmd.Wait()
		os.Remove(tmpCfg.Name())
		t.Fatalf("pgman did not start in time: %v", err)
	}

	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		os.Remove(tmpCfg.Name())
	})

	return inst
}

// proxyDSN builds a pgx connection string through the proxy.
func proxyDSN(proxyAddr string) string {
	return fmt.Sprintf(
		"postgres://pgman_test:anything@%s/pgman_test?sslmode=disable&default_query_exec_mode=simple_protocol",
		proxyAddr,
	)
}

// ---- Helpers --------------------------------------------------------

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitForPort(t *testing.T, addr string, timeout time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not ready after %s", addr, timeout)
}

func pgAddrFromDSN(t *testing.T, dsn string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Port
	if port == 0 {
		port = 5432
	}
	return fmt.Sprintf("%s:%d", host, port)
}

// pgxPool creates a pgxpool.Pool connected through the proxy.
func pgxPool(t *testing.T, proxyAddr string, maxConns int32) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(proxyDSN(proxyAddr))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

// ---- TB-generic helpers (work with *testing.T and *testing.B) -------

func freePortTB(tb testing.TB) int {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func waitForPortTB(tb testing.TB, addr string, timeout time.Duration) error {
	tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not ready after %s", addr, timeout)
}

func addrStr(port int) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}

func configYAML(proxyPort, metricsPort, adminPort, poolLimit int) string {
	return configYAMLWithMode(proxyPort, metricsPort, adminPort, poolLimit, "")
}

// configYAMLWithMode adds a pool_mode override to the pgman_test pool.
// Pass "" for the default (transaction) or "session" for session pooling.
func configYAMLWithMode(proxyPort, metricsPort, adminPort, poolLimit int, poolMode string) string {
	modeLine := ""
	// Session mode should NOT run DISCARD ALL between clients — the
	// whole point is that session state (prepared statements, temp
	// tables, GUCs) persists.
	resetQuery := `"DISCARD ALL"`
	if poolMode != "" {
		modeLine = fmt.Sprintf("    pool_mode: %q\n", poolMode)
		if poolMode == "session" {
			resetQuery = `""`
		}
	}
	return fmt.Sprintf(`listen_addr: "127.0.0.1:%d"
metrics_addr: "127.0.0.1:%d"
admin_addr: "127.0.0.1:%d"
max_client_conn: 1000
client_login_timeout: 30s
query_wait_timeout: 10s
server_reset_query: %s
server_idle_timeout: 5m
server_lifetime: 30m
min_pool_size: 1
health_check_timeout: 500ms
log_format: text
log_level: info
allow_insecure_trust_auth: true
pools:
  pgman_test:
    backend_dsn: %q
    backend_addr: %q
    limit: %d
%s`, proxyPort, metricsPort, adminPort, resetQuery, pgDSN, pgAddrFromDSN2(pgDSN), poolLimit, modeLine)
}

// startProxyWithMode is startProxy with a custom pool_mode.
func startProxyWithMode(t *testing.T, poolLimit int, poolMode string) *proxyInstance {
	t.Helper()
	proxyPort := freePort(t)
	metricsPort := freePort(t)
	adminPort := freePort(t)

	cfg := configYAMLWithMode(proxyPort, metricsPort, adminPort, poolLimit, poolMode)
	tmpCfg, err := os.CreateTemp("", "pgman-cfg-*.yaml")
	if err != nil {
		t.Fatalf("create config: %v", err)
	}
	if _, err := tmpCfg.WriteString(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	tmpCfg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := startPgmanCmd(ctx, tmpCfg.Name())
	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmpCfg.Name())
		t.Fatalf("start pgman: %v", err)
	}
	inst := &proxyInstance{
		ProxyAddr:   fmt.Sprintf("127.0.0.1:%d", proxyPort),
		MetricsAddr: fmt.Sprintf("127.0.0.1:%d", metricsPort),
		AdminAddr:   fmt.Sprintf("127.0.0.1:%d", adminPort),
		cmd:         cmd,
		configPath:  tmpCfg.Name(),
		cancel:      cancel,
	}
	waitForPort(t, inst.ProxyAddr, 5*time.Second)
	t.Cleanup(func() {
		inst.cancel()
		_ = cmd.Wait()
		os.Remove(tmpCfg.Name())
	})
	return inst
}

func startPgmanCmd(ctx context.Context, configPath string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, pgmanBin, "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd
}

// pgAddrFromDSN2 is a non-fatal version of pgAddrFromDSN for use in
// non-test contexts (config generation).
func pgAddrFromDSN2(dsn string) string {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "127.0.0.1:5432"
	}
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	port := cfg.Port
	if port == 0 {
		port = 5432
	}
	return fmt.Sprintf("%s:%d", host, port)
}
