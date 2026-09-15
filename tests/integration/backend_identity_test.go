//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// startProxyWithBackendUsers runs pgman with per-user backend
// credentials on the pgman_test pool.
func startProxyWithBackendUsers(t *testing.T, poolLimit int, backendUsers map[string]string) *proxyInstance {
	t.Helper()

	proxyPort := freePort(t)
	metricsPort := freePort(t)
	adminPort := freePort(t)

	users := ""
	for user, dsn := range backendUsers {
		users += fmt.Sprintf("      %s: %q\n", user, dsn)
	}

	cfg := fmt.Sprintf(`listen_addr: "127.0.0.1:%d"
metrics_addr: "127.0.0.1:%d"
admin_addr: "127.0.0.1:%d"
max_client_conn: 100
client_login_timeout: 30s
query_wait_timeout: 10s
server_reset_query: "DISCARD ALL"
log_format: text
log_level: info
allow_insecure_trust_auth: true
pools:
  pgman_test:
    backend_dsn: %q
    backend_addr: %q
    limit: %d
    backend_users:
%s`, proxyPort, metricsPort, adminPort, pgDSN, pgAddrFromDSN2(pgDSN), poolLimit, users)

	tmpCfg, err := os.CreateTemp("", "pgman-identity-*.yaml")
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

// createRole makes a login role on the real Postgres and removes it
// again when the test finishes.
func createRole(t *testing.T, name, password string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer admin.Close(context.Background())

	_, _ = admin.Exec(ctx, fmt.Sprintf("DROP ROLE IF EXISTS %s", name))
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", name, password)); err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), pgDSN)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), fmt.Sprintf("DROP ROLE IF EXISTS %s", name))
	})
}

// backendRoleFor asks the proxy, as user, who Postgres thinks is running
// the statement.
func backendRoleFor(t *testing.T, inst *proxyInstance, user string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dsn := fmt.Sprintf("postgres://%s@%s/pgman_test?sslmode=disable", user, inst.ProxyAddr)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	defer conn.Close(context.Background())

	var role string
	if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("current_user as %s: %v", user, err)
	}
	return role
}

// TestBackendIdentityFollowsTheClient is the end-to-end proof that the
// (database, user) pool key does what it exists for. Before it, every
// client ran on Postgres as the backend_dsn role whatever it had
// authenticated as, so GRANT and REVOKE could not tell two clients
// apart, row-level security saw one identity, and every statement in
// pg_stat_activity was attributed to the same role.
//
// current_user is the authority here — not the config, not the pool
// name. It is what Postgres itself enforces permissions against.
func TestBackendIdentityFollowsTheClient(t *testing.T) {
	createRole(t, "pgman_alice", "alice_pw")
	createRole(t, "pgman_bob", "bob_pw")

	host := pgAddrFromDSN2(pgDSN)
	inst := startProxyWithBackendUsers(t, 5, map[string]string{
		"pgman_alice": fmt.Sprintf("postgres://pgman_alice:alice_pw@%s/pgman_test?sslmode=disable", host),
		"pgman_bob":   fmt.Sprintf("postgres://pgman_bob:bob_pw@%s/pgman_test?sslmode=disable", host),
	})

	if got := backendRoleFor(t, inst, "pgman_alice"); got != "pgman_alice" {
		t.Errorf("alice's statements run as %q on Postgres, want pgman_alice", got)
	}
	if got := backendRoleFor(t, inst, "pgman_bob"); got != "pgman_bob" {
		t.Errorf("bob's statements run as %q on Postgres, want pgman_bob", got)
	}

	// A user with no entry of its own keeps sharing the pool's DSN
	// identity, which is the pre-existing behaviour and the reason the
	// connection count does not multiply for everyone else.
	if got := backendRoleFor(t, inst, "someone_else"); got != "pgman_test" {
		t.Errorf("an unlisted user ran as %q, want the backend_dsn role pgman_test", got)
	}
}

// TestBackendIdentitySurvivesPoolReuse is the part that a single query
// cannot prove: the pools are separate, so no amount of cycling hands
// alice a connection opened as bob. With one shared pool this is exactly
// where the identities would bleed.
func TestBackendIdentitySurvivesPoolReuse(t *testing.T) {
	createRole(t, "pgman_alice", "alice_pw")
	createRole(t, "pgman_bob", "bob_pw")

	host := pgAddrFromDSN2(pgDSN)
	inst := startProxyWithBackendUsers(t, 2, map[string]string{
		"pgman_alice": fmt.Sprintf("postgres://pgman_alice:alice_pw@%s/pgman_test?sslmode=disable", host),
		"pgman_bob":   fmt.Sprintf("postgres://pgman_bob:bob_pw@%s/pgman_test?sslmode=disable", host),
	})

	for i := 0; i < 8; i++ {
		user := "pgman_alice"
		if i%2 == 1 {
			user = "pgman_bob"
		}
		if got := backendRoleFor(t, inst, user); got != user {
			t.Fatalf("round %d: %s got a connection running as %q", i, user, got)
		}
	}
}

// TestPerUserPoolsAreVisibleSeparately — an operator sizing pools has to
// be able to see that backend_users multiplied them, since each one
// carries its own limit.
func TestPerUserPoolsAreVisibleSeparately(t *testing.T) {
	createRole(t, "pgman_alice", "alice_pw")

	host := pgAddrFromDSN2(pgDSN)
	inst := startProxyWithBackendUsers(t, 3, map[string]string{
		"pgman_alice": fmt.Sprintf("postgres://pgman_alice:alice_pw@%s/pgman_test?sslmode=disable", host),
	})

	// Make sure the per-user pool has actually dialed before scraping.
	if got := backendRoleFor(t, inst, "pgman_alice"); got != "pgman_alice" {
		t.Fatalf("current_user = %q", got)
	}

	body := scrapeMetrics(t, inst.MetricsAddr)
	for _, want := range []string{`pgman_pool_limit{pool="pgman_test"}`, `pgman_pool_limit{pool="pgman_test/pgman_alice"}`} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics do not expose %s", want)
		}
	}
}

func scrapeMetrics(t *testing.T, addr string) string {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	return string(body)
}
