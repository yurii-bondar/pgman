//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// rolpasswordFor reads a role's SCRAM verifier straight out of
// pg_authid — the same string config.yaml tells operators to copy into
// auth_users. Pass-through depends on pgman's verifier being the
// backend's verifier, and this is what makes that true by construction.
func rolpasswordFor(t *testing.T, role string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	defer admin.Close(context.Background())

	var verifier string
	if err := admin.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&verifier); err != nil {
		t.Fatalf("read rolpassword for %s: %v", role, err)
	}
	if !strings.HasPrefix(verifier, "SCRAM-SHA-256$") {
		t.Fatalf("role %s is not stored with SCRAM-SHA-256: %q", role, verifier)
	}
	return verifier
}

// startProxyWithPassthrough runs pgman with scram_passthrough on and
// NO backend credentials of any kind — the DSN carries a user with no
// password, which is the whole claim being tested.
func startProxyWithPassthrough(t *testing.T, authUsers map[string]string, poolLimit int) *proxyInstance {
	t.Helper()

	proxyPort := freePort(t)
	metricsPort := freePort(t)
	adminPort := freePort(t)

	users := ""
	for user, verifier := range authUsers {
		users += fmt.Sprintf("  %s: %q\n", user, verifier)
	}

	// backend_dsn keeps a host, a port and a database, and deliberately
	// no usable credential: pass-through supplies the identity.
	backendDSN := fmt.Sprintf("postgres://unused@%s/pgman_test?sslmode=disable", pgAddrFromDSN2(pgDSN))

	cfg := fmt.Sprintf(`listen_addr: "127.0.0.1:%d"
metrics_addr: "127.0.0.1:%d"
admin_addr: "127.0.0.1:%d"
max_client_conn: 100
client_login_timeout: 30s
query_wait_timeout: 10s
server_reset_query: "DISCARD ALL"
log_format: text
log_level: info
auth_users:
%spools:
  pgman_test:
    backend_dsn: %q
    backend_addr: %q
    limit: %d
    scram_passthrough: true
`, proxyPort, metricsPort, adminPort, users, backendDSN, pgAddrFromDSN2(pgDSN), poolLimit)

	tmpCfg, err := os.CreateTemp("", "pgman-passthrough-*.yaml")
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

// queryAs connects through the proxy with a password and returns the
// single string the query produces.
func queryAs(t *testing.T, inst *proxyInstance, user, password, sql string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	dsn := fmt.Sprintf("postgres://%s:%s@%s/pgman_test?sslmode=disable", user, password, inst.ProxyAddr)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", user, err)
	}
	defer conn.Close(context.Background())

	var out string
	if err := conn.QueryRow(ctx, sql).Scan(&out); err != nil {
		t.Fatalf("%q as %s: %v", sql, user, err)
	}
	return out
}

// TestScramPassthroughAuthenticatesAsTheClient is the whole feature in
// one assertion.
//
// pgman's config holds no backend password, no passfile and no client
// certificate — only the SCRAM verifier copied from pg_authid, which is
// not enough to authenticate anywhere. The only credential that ever
// exists is the ClientKey recovered from the client's own proof, and
// current_user is Postgres itself confirming that it worked.
func TestScramPassthroughAuthenticatesAsTheClient(t *testing.T) {
	createRole(t, "pgman_pt_alice", "alice_secret")
	createRole(t, "pgman_pt_bob", "bob_secret")

	inst := startProxyWithPassthrough(t, map[string]string{
		"pgman_pt_alice": rolpasswordFor(t, "pgman_pt_alice"),
		"pgman_pt_bob":   rolpasswordFor(t, "pgman_pt_bob"),
	}, 5)

	if got := queryAs(t, inst, "pgman_pt_alice", "alice_secret", "SELECT current_user"); got != "pgman_pt_alice" {
		t.Errorf("alice's statements run as %q on Postgres, want pgman_pt_alice", got)
	}
	if got := queryAs(t, inst, "pgman_pt_bob", "bob_secret", "SELECT current_user"); got != "pgman_pt_bob" {
		t.Errorf("bob's statements run as %q on Postgres, want pgman_pt_bob", got)
	}
}

// TestScramPassthroughRejectsAWrongPassword keeps the obvious disaster
// out: recovering a credential from a proof is only sound if the proof
// was actually verified first.
func TestScramPassthroughRejectsAWrongPassword(t *testing.T) {
	createRole(t, "pgman_pt_alice", "alice_secret")

	inst := startProxyWithPassthrough(t, map[string]string{
		"pgman_pt_alice": rolpasswordFor(t, "pgman_pt_alice"),
	}, 5)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dsn := fmt.Sprintf("postgres://pgman_pt_alice:wrong@%s/pgman_test?sslmode=disable", inst.ProxyAddr)
	if conn, err := pgx.Connect(ctx, dsn); err == nil {
		conn.Close(context.Background())
		t.Fatal("a wrong password was accepted")
	}
}

// TestScramPassthroughKeepsIdentitiesApartAcrossPoolReuse cycles two
// users through a pool small enough to force reuse. Separate pools per
// identity is what stops alice's query landing on bob's connection.
func TestScramPassthroughKeepsIdentitiesApartAcrossPoolReuse(t *testing.T) {
	createRole(t, "pgman_pt_alice", "alice_secret")
	createRole(t, "pgman_pt_bob", "bob_secret")

	inst := startProxyWithPassthrough(t, map[string]string{
		"pgman_pt_alice": rolpasswordFor(t, "pgman_pt_alice"),
		"pgman_pt_bob":   rolpasswordFor(t, "pgman_pt_bob"),
	}, 1)

	for i := 0; i < 6; i++ {
		user, password := "pgman_pt_alice", "alice_secret"
		if i%2 == 1 {
			user, password = "pgman_pt_bob", "bob_secret"
		}
		if got := queryAs(t, inst, user, password, "SELECT current_user"); got != user {
			t.Fatalf("round %d: %s ran as %q", i, user, got)
		}
	}
}

// TestScramPassthroughPoolAppearsOnFirstUse — a pass-through pool
// cannot exist before its user logs in, because the credential does
// not. An operator has to be able to see it appear, since it carries
// its own limit.
func TestScramPassthroughPoolAppearsOnFirstUse(t *testing.T) {
	createRole(t, "pgman_pt_alice", "alice_secret")

	inst := startProxyWithPassthrough(t, map[string]string{
		"pgman_pt_alice": rolpasswordFor(t, "pgman_pt_alice"),
	}, 3)

	before := scrapeMetrics(t, inst.MetricsAddr)
	if strings.Contains(before, `pool="pgman_test/pgman_pt_alice"`) {
		t.Fatal("the per-user pool exists before anyone authenticated")
	}

	if got := queryAs(t, inst, "pgman_pt_alice", "alice_secret", "SELECT current_user"); got != "pgman_pt_alice" {
		t.Fatalf("current_user = %q", got)
	}

	after := scrapeMetrics(t, inst.MetricsAddr)
	if !strings.Contains(after, `pool="pgman_test/pgman_pt_alice"`) {
		t.Error("the per-user pool is not visible in metrics after first use")
	}
}

// TestScramPassthroughUnderConcurrentUsers is the case the sequential
// tests above cannot reach.
//
// TestScramPassthroughKeepsIdentitiesApartAcrossPoolReuse cycles users
// one at a time, which proves the per-user pools are keyed correctly.
// It says nothing about what happens when several users authenticate,
// route and run at the same moment — and that is the only window in
// which pgman could hand a session the wrong identity, because the
// ClientKey store is written during authentication and read during
// routing.
//
// Getting this wrong is not a dropped connection. It is one client's
// statements executing as another client's role, underneath row-level
// security and every GRANT on the database. So the assertion is exact:
// every query, from every goroutine, must see its own current_user.
func TestScramPassthroughUnderConcurrentUsers(t *testing.T) {
	const (
		users       = 6
		concurrency = 4
		rounds      = 8
	)

	authUsers := make(map[string]string, users)
	creds := make([][2]string, 0, users)
	for i := 0; i < users; i++ {
		role := fmt.Sprintf("pgman_ptc_%d", i)
		password := fmt.Sprintf("secret_%d", i)
		createRole(t, role, password)
		authUsers[role] = rolpasswordFor(t, role)
		creds = append(creds, [2]string{role, password})
	}

	// A pool limit below the number of users, so per-user pools are
	// created, evicted and recreated while other users are mid-flight.
	inst := startProxyWithPassthrough(t, authUsers, 2)

	var wg sync.WaitGroup
	errCh := make(chan string, users*concurrency*rounds)

	for _, c := range creds {
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func(role, password string) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()

				dsn := fmt.Sprintf("postgres://%s:%s@%s/pgman_test?sslmode=disable",
					role, password, inst.ProxyAddr)
				conn, err := pgx.Connect(ctx, dsn)
				if err != nil {
					errCh <- fmt.Sprintf("%s: connect: %v", role, err)
					return
				}
				defer conn.Close(context.Background())

				for r := 0; r < rounds; r++ {
					var got string
					if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&got); err != nil {
						errCh <- fmt.Sprintf("%s round %d: %v", role, r, err)
						return
					}
					if got != role {
						errCh <- fmt.Sprintf(
							"IDENTITY CROSSED: %s round %d ran as %q", role, r, got)
						return
					}
				}
			}(c[0], c[1])
		}
	}

	wg.Wait()
	close(errCh)

	var failures []string
	for msg := range errCh {
		failures = append(failures, msg)
	}
	if len(failures) > 0 {
		for _, f := range failures {
			t.Error(f)
		}
		t.Fatalf("%d of %d concurrent sessions failed", len(failures), users*concurrency)
	}
	t.Logf("%d users × %d connections × %d queries all ran as themselves",
		users, concurrency, rounds)
}
