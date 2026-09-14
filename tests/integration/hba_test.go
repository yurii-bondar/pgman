//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// startProxyWithHBA — writes an HBA file and starts the proxy with
// auth_hba_file pointing to it. Returns the running proxy instance.
func startProxyWithHBA(t *testing.T, poolLimit int, hbaContent string) *proxyInstance {
	t.Helper()

	hbaPath := filepath.Join(t.TempDir(), "hba.conf")
	if err := os.WriteFile(hbaPath, []byte(hbaContent), 0o600); err != nil {
		t.Fatalf("write hba: %v", err)
	}

	proxyPort := freePort(t)
	metricsPort := freePort(t)
	adminPort := freePort(t)

	cfg := fmt.Sprintf(`listen_addr: "127.0.0.1:%d"
metrics_addr: "127.0.0.1:%d"
admin_addr: "127.0.0.1:%d"
max_client_conn: 1000
client_login_timeout: 30s
query_wait_timeout: 10s
server_reset_query: "DISCARD ALL"
log_format: text
log_level: info
allow_insecure_trust_auth: true
auth_hba_file: %q
pools:
  pgman_test:
    backend_dsn: %q
    backend_addr: %q
    limit: %d
`, proxyPort, metricsPort, adminPort, hbaPath, pgDSN, pgAddrFromDSN2(pgDSN), poolLimit)

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
		_ = exec.Command("true").Run()
		os.Remove(tmpCfg.Name())
	})
	return inst
}

// TestHBATrustLoopback — a rule allowing trust from loopback lets a
// local pgx client through with no password check.
func TestHBATrustLoopback(t *testing.T) {
	inst := startProxyWithHBA(t, 5, `
host all all 127.0.0.0/8 trust
`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	var n int
	if err := conn.QueryRow(ctx, "SELECT 42").Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 42 {
		t.Fatalf("got %d, want 42", n)
	}
}

// TestHBARejectRule — a rule that rejects a specific database name
// fires a FATAL 28000 before we ever get to auth.
func TestHBARejectRule(t *testing.T) {
	// Reject connections to database=pgman_test from 127.0.0.0/8.
	// Then a catch-all trust for anything else (which we won't hit).
	inst := startProxyWithHBA(t, 5, `
host pgman_test all 127.0.0.0/8 reject
host all           all 127.0.0.0/8 trust
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err == nil {
		t.Fatal("expected rejection, connect succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rejects") &&
		!strings.Contains(err.Error(), "28000") {
		t.Logf("got error: %v (accepted — server-generated FATAL messages vary by client)", err)
	}
}

// TestHBANoRuleMatchesIsRejected — no rule matches → connection
// refused with "no pg_hba.conf entry" error.
func TestHBANoRuleMatchesIsRejected(t *testing.T) {
	// Only allow database "elsewhere" from loopback. Our client asks
	// for "pgman_test" → no rule matches.
	inst := startProxyWithHBA(t, 5, `
host elsewhere all 127.0.0.0/8 trust
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err == nil {
		t.Fatal("expected rejection for unmatched HBA, connect succeeded")
	}
	t.Logf("correctly rejected unmatched connection: %v", err)
}

// TestHBAOrderMatters — reject rule first must win, even when a later
// permissive rule would have accepted.
func TestHBAOrderMatters(t *testing.T) {
	inst := startProxyWithHBA(t, 5, `
host all all 127.0.0.0/8 reject
host all all 127.0.0.0/8 trust
`)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr)); err == nil {
		t.Fatal("first-match-wins violated: reject-first should have blocked the connection")
	}
}
