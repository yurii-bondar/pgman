//go:build integration

// Failure and recovery: what pgman does when the database goes away,
// and whether it comes back on its own.
//
// Everything else in this package tests the happy path against a
// Postgres that is always there. The interesting questions are the
// other ones — does a dead backend produce a clean error or a hang,
// does the breaker open, does /ready tell the orchestrator the truth,
// and does the pool recover without a restart once the database is
// back. A pooler that needs a bounce after every database blip is worse
// than no pooler at all, because it turns a thirty-second outage into a
// deploy.
//
// The database itself is shared with every other test here, so it is
// never touched. Instead pgman is pointed at a TCP forwarder that this
// file can break and heal at will, which is both safer and a closer
// model of what actually fails in production: the network between the
// pooler and the database, not the database process.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---- Controllable TCP forwarder -------------------------------------

// faultProxy forwards TCP to an upstream and can be told to stop.
//
// Break() both refuses new connections and drops existing ones, which
// is what a failover, a pod eviction or a firewall change looks like
// from the client side. Heal() restores service on the same address, so
// the pool gets its backend back without anything else changing.
type faultProxy struct {
	addr     string
	upstream string

	mu       sync.Mutex
	broken   bool
	live     map[net.Conn]struct{}
	accepted atomic.Int64

	ln   net.Listener
	done chan struct{}
	wg   sync.WaitGroup
}

func newFaultProxy(t *testing.T, upstream string) *faultProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fault proxy listen: %v", err)
	}
	fp := &faultProxy{
		addr:     ln.Addr().String(),
		upstream: upstream,
		live:     make(map[net.Conn]struct{}),
		ln:       ln,
		done:     make(chan struct{}),
	}
	fp.wg.Add(1)
	go fp.serve()
	t.Cleanup(fp.close)
	return fp
}

func (f *faultProxy) serve() {
	defer f.wg.Done()
	for {
		client, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.accepted.Add(1)

		f.mu.Lock()
		broken := f.broken
		f.mu.Unlock()
		if broken {
			_ = client.Close()
			continue
		}

		upstream, err := net.DialTimeout("tcp", f.upstream, 5*time.Second)
		if err != nil {
			_ = client.Close()
			continue
		}

		f.mu.Lock()
		f.live[client] = struct{}{}
		f.live[upstream] = struct{}{}
		f.mu.Unlock()

		f.wg.Add(2)
		go f.pipe(client, upstream)
		go f.pipe(upstream, client)
	}
}

func (f *faultProxy) pipe(dst, src net.Conn) {
	defer f.wg.Done()
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
	f.mu.Lock()
	delete(f.live, dst)
	delete(f.live, src)
	f.mu.Unlock()
}

// Break drops every live connection and refuses new ones.
func (f *faultProxy) Break() {
	f.mu.Lock()
	f.broken = true
	for c := range f.live {
		_ = c.Close()
	}
	f.live = make(map[net.Conn]struct{})
	f.mu.Unlock()
}

// Heal resumes forwarding on the same address.
func (f *faultProxy) Heal() {
	f.mu.Lock()
	f.broken = false
	f.mu.Unlock()
}

func (f *faultProxy) close() {
	close(f.done)
	_ = f.ln.Close()
	f.Break()
	f.wg.Wait()
}

// withBackendVia points the shared harness at addr for one test.
//
// pgDSN is what configYAML builds every pool from, so swapping it is
// the whole of "start pgman against a different backend" — no second
// copy of the config template, which would drift. Tests in this package
// do not run in parallel, and the value is restored on cleanup.
func withBackendVia(t *testing.T, addr string) {
	t.Helper()
	cfg, err := pgx.ParseConfig(pgDSN)
	if err != nil {
		t.Fatalf("parse pgDSN: %v", err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	prev := pgDSN
	pgDSN = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.User, cfg.Password, host, port, cfg.Database)
	t.Cleanup(func() { pgDSN = prev })
}

// readyStatus asks the health endpoint what it currently believes.
func readyStatus(t *testing.T, metricsAddr string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+metricsAddr+"/ready", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /ready: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// ---- Tests -----------------------------------------------------------

// TestBackendOutageFailsCleanlyAndRecovers is the headline scenario: the
// database becomes unreachable and then comes back.
//
// What is asserted is not that queries keep working — they cannot — but
// that the failure is *clean and temporary*. Clients get errors rather
// than hangs, the readiness probe stops claiming the proxy is usable so
// an orchestrator can route around it, and once the backend returns the
// pool serves traffic again with no intervention.
func TestBackendOutageFailsCleanlyAndRecovers(t *testing.T) {
	fp := newFaultProxy(t, pgAddrFromDSN(t, pgDSN))
	withBackendVia(t, fp.addr)

	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pool := pgxPool(t, inst.ProxyAddr, 8)

	var n int
	if err := pool.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil {
		t.Fatalf("baseline query before any fault: %v", err)
	}

	// ---- the outage ----
	fp.Break()

	// Every query must now fail, and fail promptly. A hang here is the
	// bug this test exists for: a client blocked forever on a dead
	// backend holds a slot that nothing will ever free.
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	failed := 0
	for time.Now().Before(deadline) && failed < 12 {
		qCtx, qCancel := context.WithTimeout(ctx, 5*time.Second)
		err := pool.QueryRow(qCtx, "SELECT 1").Scan(&n)
		qCancel()
		if err == nil {
			// A connection dialled before the break can still be idle
			// in pgx's own pool; keep going until the proxy has noticed.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		lastErr = err
		failed++
	}
	if failed == 0 {
		t.Fatal("queries kept succeeding after the backend was cut off")
	}
	t.Logf("outage error (expected): %v", lastErr)

	// The breaker exists so that N clients do not each pay a full dial
	// timeout against a backend that is known to be down. Its visible
	// effect is /ready turning 503, which is what stops a load balancer
	// sending more work to an instance that cannot serve it.
	breakerOpen := false
	for i := 0; i < 40 && !breakerOpen; i++ {
		code, body := readyStatus(t, inst.MetricsAddr)
		if code == http.StatusServiceUnavailable {
			breakerOpen = true
			t.Logf("/ready reported 503 during the outage: %s", strings.TrimSpace(body))
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !breakerOpen {
		t.Error("/ready never reported 503 while the backend was unreachable — " +
			"an orchestrator would keep routing traffic here")
	}

	// ---- the recovery ----
	fp.Heal()

	recovered := false
	recoverDeadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(recoverDeadline) {
		qCtx, qCancel := context.WithTimeout(ctx, 5*time.Second)
		err := pool.QueryRow(qCtx, "SELECT 1").Scan(&n)
		qCancel()
		if err == nil {
			recovered = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !recovered {
		t.Fatal("the pool never recovered after the backend came back — a restart would be required")
	}

	code, body := readyStatus(t, inst.MetricsAddr)
	if code != http.StatusOK {
		t.Errorf("/ready is still %d after recovery: %s", code, strings.TrimSpace(body))
	}

	// And it must be genuinely healthy, not one lucky query.
	for i := 0; i < 50; i++ {
		if err := pool.QueryRow(ctx, "SELECT $1::int", i).Scan(&n); err != nil {
			t.Fatalf("query %d after recovery: %v", i, err)
		}
	}
	t.Logf("recovered; forwarder accepted %d connections in total", fp.accepted.Load())
}

// TestCancellationStorm fires cancellations at a busy pool from many
// clients at once.
//
// One cancel is already covered. The reason to do a thousand is that
// cancellation is the only path in a Postgres proxy that touches a
// session from *outside* it: a second connection, opened by another
// goroutine, carrying a key that has to still refer to a live backend.
// Racing that against normal traffic, pool churn and each other is
// where use-after-release and cross-session cancels would show up —
// and a cancel delivered to the wrong session is a query killed at
// random in someone else's transaction.
//
// The assertion is deliberately about survival rather than about how
// many cancels landed: whether a given cancel wins the race with its
// own query finishing is genuinely nondeterministic. What must not
// happen is the proxy wedging, leaking backends, or killing work that
// nobody cancelled.
func TestCancellationStorm(t *testing.T) {
	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	const (
		cancellers = 24
		rounds     = 12
	)

	cfg, err := pgxpool.ParseConfig(proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	cfg.MaxConns = cancellers
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var (
		cancelled  atomic.Int64
		completed  atomic.Int64
		unexpected atomic.Int64
	)

	var wg sync.WaitGroup
	wg.Add(cancellers)
	for i := 0; i < cancellers; i++ {
		go func(id int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				qCtx, qCancel := context.WithCancel(ctx)
				// Cancel at a random-ish point inside the sleep, so
				// some cancels arrive while the query is running, some
				// as it finishes, and some after it is already gone.
				go func() {
					time.Sleep(time.Duration(20+((id*7+r*13)%80)) * time.Millisecond)
					qCancel()
				}()
				_, err := pool.Exec(qCtx, "SELECT pg_sleep(0.05)")
				qCancel()
				switch {
				case err == nil:
					completed.Add(1)
				case isCancellation(err):
					cancelled.Add(1)
				default:
					unexpected.Add(1)
					t.Logf("unexpected error: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	t.Logf("cancellation storm: %d cancelled, %d completed, %d unexpected",
		cancelled.Load(), completed.Load(), unexpected.Load())

	if unexpected.Load() > 0 {
		t.Errorf("%d queries failed with something other than a cancellation", unexpected.Load())
	}
	if cancelled.Load() == 0 {
		t.Error("no query was ever actually cancelled — the storm did not test cancellation")
	}

	// The proxy must still be fully usable afterwards. A cancellation
	// path that discards a backend it should have kept, or keeps one it
	// should have discarded, shows up here as a pool that can no longer
	// serve its limit.
	var wg2 sync.WaitGroup
	errs := make([]error, 10)
	wg2.Add(10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer wg2.Done()
			var n int
			errs[id] = pool.QueryRow(ctx, "SELECT $1::int", id).Scan(&n)
		}(i)
	}
	wg2.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("post-storm query %d failed, the pool did not fully recover: %v", i, err)
		}
	}
}

// isCancellation reports whether err is the expected outcome of
// cancelling a query, in any of the shapes it legitimately arrives in.
func isCancellation(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := err.Error()
	for _, want := range []string{
		"57014",                // query_canceled
		"canceling statement",  // the backend's own wording
		"conn closed",          // pgx tearing down a cancelled conn
		"context canceled",     // wrapped rather than joined
		"failed to deallocate", // cleanup on a conn already going away
		"unexpected EOF",       // cancel raced the response
	} {
		if strings.Contains(msg, want) {
			return true
		}
	}
	return false
}

// TestBackendSwitchoverKeepsInFlightWork is the Kubernetes shape:
// the address behind the pool starts serving a different backend, and
// pgman is told to move.
//
// This is what the DNS watcher triggers when a Service's endpoints
// change — it calls pool.Reconnect(), which is exercised here through
// the admin API so the whole path is real rather than mocked. The unit
// tests in dns_watcher_test.go already prove the watcher *decides*
// correctly; what they cannot show is whether acting on that decision
// disturbs traffic.
//
// The contract being checked: a transaction already in flight finishes
// on its old connection, and everything afterwards runs on new ones.
// Killing live transactions on a pod rotation would make rolling
// deploys visible to users, which is the whole thing a pooler is
// supposed to hide.
func TestBackendSwitchoverKeepsInFlightWork(t *testing.T) {
	fp := newFaultProxy(t, pgAddrFromDSN(t, pgDSN))
	withBackendVia(t, fp.addr)

	inst := startProxy(t, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pool := pgxPool(t, inst.ProxyAddr, 8)

	// Warm several backends so there is idle state for RECONNECT to drop.
	var warmWG sync.WaitGroup
	warmWG.Add(4)
	for i := 0; i < 4; i++ {
		go func() {
			defer warmWG.Done()
			var n int
			_ = pool.QueryRow(ctx, "SELECT pg_sleep(0.1)").Scan(&n)
		}()
	}
	warmWG.Wait()
	before := fp.accepted.Load()

	// Start a transaction and hold it open across the switchover.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	var inTx int
	if err := tx.QueryRow(ctx, "SELECT 41").Scan(&inTx); err != nil {
		t.Fatalf("first statement in tx: %v", err)
	}

	// The switchover itself.
	resp, err := http.Post(
		fmt.Sprintf("http://%s/pools/pgman_test/reconnect", inst.AdminAddr),
		"application/x-www-form-urlencoded", strings.NewReader(""))
	if err != nil {
		t.Fatalf("admin reconnect: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin reconnect returned %d", resp.StatusCode)
	}

	// The open transaction must be unharmed: same backend, same
	// snapshot, commit succeeds.
	if err := tx.QueryRow(ctx, "SELECT $1::int + 1", inTx).Scan(&inTx); err != nil {
		t.Fatalf("a RECONNECT killed an in-flight transaction: %v", err)
	}
	if inTx != 42 {
		t.Fatalf("in-flight transaction returned %d, want 42", inTx)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit after RECONNECT: %v", err)
	}

	// New work must go over freshly dialled connections.
	for i := 0; i < 8; i++ {
		var n int
		if err := pool.QueryRow(ctx, "SELECT $1::int", i).Scan(&n); err != nil {
			t.Fatalf("query %d after switchover: %v", i, err)
		}
	}
	after := fp.accepted.Load()
	if after <= before {
		t.Errorf("no new backend connections after RECONNECT (%d before, %d after) — "+
			"a DNS flip would leave clients pinned to the old endpoint", before, after)
	}
	t.Logf("switchover: %d backend connections before, %d after", before, after)
}

// TestReadyReportsPoolDetail checks that the readiness body is worth
// reading, not just its status code.
//
// An orchestrator only needs the code. A human paged at 3am needs to
// know which pool is broken, and /ready is the first thing they will
// curl.
func TestReadyReportsPoolDetail(t *testing.T) {
	inst := startProxy(t, 5)

	code, body := readyStatus(t, inst.MetricsAddr)
	if code != http.StatusOK {
		t.Fatalf("/ready = %d on a healthy proxy: %s", code, body)
	}

	var payload struct {
		Pools []struct {
			Name        string `json:"name"`
			CircuitOpen bool   `json:"circuit_open"`
		} `json:"pools"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("/ready body is not the documented JSON: %v\nbody: %s", err, body)
	}
	if len(payload.Pools) == 0 {
		t.Fatalf("/ready lists no pools, so it cannot say which one is unhealthy: %s", body)
	}
	for _, p := range payload.Pools {
		if p.Name == "" {
			t.Errorf("/ready lists a pool with no name: %s", body)
		}
	}
}
