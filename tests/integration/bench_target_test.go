//go:build integration

// Package integration — the measurement half of the pooler comparison.
//
// This file deliberately knows nothing about pgman. It points pgx at a
// DSN and reports what came back; starting the poolers, matching their
// configuration and walking the matrix is scripts/bench-vs-pgbouncer.sh's
// job. Keeping the two apart is the whole reason the numbers are
// comparable: one client, one query, one timing path, three targets.
//
// Driven by env vars in the style TestPgbenchStyleMix already
// established, and skipped when PGMAN_BENCH_DSN is unset so that a
// plain `go test -tags integration ./...` is unaffected.
package integration

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// benchResultPrefix tags the single line the driver script parses out
// of the log. Everything else this test prints is for a human reading
// a run that went wrong.
const benchResultPrefix = "BENCHRESULT"

// benchErrPrefix tags the companion line describing why a cell failed,
// when it did.
const benchErrPrefix = "BENCHERR"

// benchQuery is the statement every cell of the matrix runs. Same one
// TestPgbenchStyleMix uses, and for the same reason: multiple columns,
// a little arithmetic and a text function give the backend real work,
// so the pooler's overhead is measured as a fraction of a realistic
// query rather than of a SELECT 1 that flatters whichever pooler has
// the shorter code path.
const benchQuery = "SELECT $1::int, $1::int * 2, upper($2::text), current_timestamp"

// execModes maps the protocol names the matrix uses onto pgx's
// query-execution modes. These three are the axis that actually
// separates poolers: a transaction pooler has to do nothing special for
// the simple protocol, some work for the extended one, and real
// bookkeeping for named prepared statements.
var execModes = map[string]string{
	"simple":   "simple_protocol", // one Query message, no Parse/Bind
	"extended": "exec",            // Parse/Bind/Execute, unnamed, no cache
	"prepared": "cache_statement", // named statements, client-side cache
}

func TestBenchTarget(t *testing.T) {
	dsn := os.Getenv("PGMAN_BENCH_DSN")
	if dsn == "" {
		t.Skip("PGMAN_BENCH_DSN is unset — this test is driven by scripts/bench-vs-pgbouncer.sh")
	}

	label := os.Getenv("PGMAN_BENCH_LABEL")
	if label == "" {
		label = "unlabelled"
	}
	protocol := os.Getenv("PGMAN_BENCH_PROTOCOL")
	if protocol == "" {
		protocol = "simple"
	}
	mode, ok := execModes[protocol]
	if !ok {
		t.Fatalf("PGMAN_BENCH_PROTOCOL=%q is not one of simple/extended/prepared", protocol)
	}

	clients := envInt("PGMAN_BENCH_CLIENTS", 10)
	dur := envDuration("PGMAN_BENCH_DURATION", 15*time.Second)
	warmup := envDuration("PGMAN_BENCH_WARMUP", 3*time.Second)

	pool := benchPool(t, dsn, mode, clients)

	// Each worker gets a connection of its own, held for the whole run.
	//
	// This is the difference between measuring a pooler and measuring
	// pgx. Letting N goroutines share a pgxpool means pgx opens only as
	// many connections as it needs to keep them busy — so a run labelled
	// "1000 clients" can be 1000 goroutines over a few dozen sockets,
	// and the number in the table would be a claim about the load
	// generator rather than about the thing under test. Client-
	// connection count is precisely what a pooler exists to absorb, so
	// it has to be real.
	conns := establishClients(t, pool, clients)
	defer releaseClients(conns)

	// Warm-up is not politeness, it is correctness: the first queries
	// of a run pay for the pooler filling its backend pool, for the
	// backend parsing the statement for the first time, and — in the
	// prepared case — for every client's first Parse. Folding that into
	// the sample makes a short run measure startup, not steady state.
	runBench(t, conns, warmup, false)

	res := runBench(t, conns, dur, true)

	qps := float64(res.ops) / dur.Seconds()
	t.Logf("%s %s, %s protocol, %d of %d clients connected", label, dur, protocol, len(conns), clients)
	t.Logf("  ops %d, failed %d, %.0f QPS", res.ops, res.fails, qps)
	t.Logf("  p50 %s  p95 %s  p99 %s  max %s",
		res.pct(50), res.pct(95), res.pct(99), res.pct(100))

	// One machine-readable line. Deliberately flat key=value rather
	// than JSON: the consumer is a shell script, and `grep | cut` beats
	// a jq dependency for six numbers.
	//
	// conns is reported separately from clients so a row where the two
	// disagree is visible as such instead of quietly overstating the
	// load.
	t.Logf("%s target=%s protocol=%s clients=%d conns=%d qps=%.0f p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f max_ms=%.3f ops=%d fails=%d",
		benchResultPrefix, label, protocol, clients, len(conns), qps,
		ms(res.pct(50)), ms(res.pct(95)), ms(res.pct(99)), ms(res.pct(100)),
		res.ops, res.fails)

	// Emitted on its own line because the reason is free text and the
	// result line above is parsed as flat key=value pairs.
	if msg, n := res.topError(); n > 0 {
		t.Logf("%s %d of %d failures: %s", benchErrPrefix, n, res.fails, msg)
	}
}

// establishClients opens `clients` connections and keeps them.
//
// It returns however many it managed rather than failing, because
// "fewer than asked for" is a result. A session-mode pooler with fifty
// backends cannot give a thousand clients a working connection, and the
// honest way to show that is a row that says how many it did give —
// not a harness that reports a thousand and quietly measures fifty.
func establishClients(t *testing.T, pool *pgxpool.Pool, clients int) []*pgxpool.Conn {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	conns := make([]*pgxpool.Conn, 0, clients)
	for i := 0; i < clients; i++ {
		// Per-connection deadline: the first refusal is the interesting
		// one, and without a bound a saturated pooler would hold the
		// harness for the full two minutes per remaining client.
		acquireCtx, acquireCancel := context.WithTimeout(ctx, 20*time.Second)
		c, err := pool.Acquire(acquireCtx)
		acquireCancel()
		if err != nil {
			t.Logf("stopped at %d of %d connections: %v", len(conns), clients, err)
			break
		}
		conns = append(conns, c)
	}
	if len(conns) == 0 {
		t.Fatal("not a single client connection could be established")
	}
	return conns
}

func releaseClients(conns []*pgxpool.Conn) {
	for _, c := range conns {
		c.Release()
	}
}

// benchPool builds the client-side pool. MinConns equals MaxConns on
// purpose: "1000 concurrent clients" has to mean 1000 established
// connections against the pooler, not 1000 goroutines sharing whatever
// pgx felt like opening.
func benchPool(t *testing.T, dsn, execMode string, clients int) *pgxpool.Pool {
	t.Helper()

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	cfg, err := pgxpool.ParseConfig(dsn + sep + "default_query_exec_mode=" + execMode)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = int32(clients)
	cfg.MinConns = int32(clients)
	// Long enough that nothing churns mid-run: a reconnect during the
	// measurement window would show up as a latency spike belonging to
	// pgx rather than to the pooler under test.
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = time.Hour
	cfg.HealthCheckPeriod = time.Hour

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// benchResult holds one run's outcome. Latencies are kept as a sorted
// slice so percentiles are exact — an approximation would be the wrong
// trade here, since the whole point of the exercise is to publish p99.
type benchResult struct {
	latencies []time.Duration
	ops       int64
	fails     int64
	// errs counts failures by message. A failure count on its own is
	// not a result: "700k failures" reads as a catastrophe when it may
	// be a saturated pool politely refusing work, and reads as normal
	// back-pressure when it is actually connections being reset. The
	// row is only interpretable with the reason attached.
	errs map[string]int64
}

// topError returns the most common failure and how many there were.
func (r benchResult) topError() (string, int64) {
	var msg string
	var n int64
	for m, c := range r.errs {
		if c > n {
			msg, n = m, c
		}
	}
	return msg, n
}

// pct returns the p-th percentile, with p=100 meaning the maximum.
func (r benchResult) pct(p int) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	idx := len(r.latencies) * p / 100
	if idx >= len(r.latencies) {
		idx = len(r.latencies) - 1
	}
	return r.latencies[idx]
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

// runBench drives one goroutine per held connection for `dur`, and
// collects per-op latencies when record is set.
//
// Each worker appends to its own slice with no synchronisation at all.
// That is the difference between measuring the pooler and measuring the
// measurement: a shared atomic counter on a path this hot becomes a
// contended cache line across every worker, and at 1000 goroutines it
// is the harness that shows up in the p99, not the thing under test.
// The slices are merged once, after the clock has stopped.
func runBench(t *testing.T, conns []*pgxpool.Conn, dur time.Duration, record bool) benchResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), dur+30*time.Second)
	defer cancel()

	type workerOut struct {
		lat   []time.Duration
		ops   int64
		fails int64
		errs  map[string]int64
	}
	clients := len(conns)
	out := make([]workerOut, clients)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(clients)

	for i := 0; i < clients; i++ {
		go func(id int) {
			defer wg.Done()
			w := &out[id]
			if record {
				// A rough guess at the per-worker op count. Wrong in
				// either direction only costs a reallocation or a few
				// unused slots, and it keeps append off the allocator
				// in the common case.
				w.lat = make([]time.Duration, 0, int(dur.Seconds())*500)
			}
			conn := conns[id]
			arg := fmt.Sprintf("worker-%d", id)
			var (
				a, b int
				s    string
				ts   time.Time
			)
			for {
				select {
				case <-stop:
					return
				default:
				}
				start := time.Now()
				err := conn.QueryRow(ctx, benchQuery, id, arg).Scan(&a, &b, &s, &ts)
				elapsed := time.Since(start)
				if err != nil {
					w.fails++
					if w.errs == nil {
						w.errs = make(map[string]int64, 2)
					}
					w.errs[normaliseBenchError(err)]++
					// A saturated pool answers every client with the
					// same error as fast as it can accept them, which
					// would spin this loop at the speed of the CPU and
					// distort the run for everyone else.
					select {
					case <-stop:
						return
					case <-time.After(time.Millisecond):
					}
					continue
				}
				w.ops++
				if record {
					w.lat = append(w.lat, elapsed)
				}
			}
		}(i)
	}

	time.Sleep(dur)
	close(stop)
	wg.Wait()

	var res benchResult
	res.errs = make(map[string]int64)
	total := 0
	for i := range out {
		total += len(out[i].lat)
	}
	res.latencies = make([]time.Duration, 0, total)
	for i := range out {
		res.ops += out[i].ops
		res.fails += out[i].fails
		res.latencies = append(res.latencies, out[i].lat...)
		for msg, n := range out[i].errs {
			res.errs[msg] += n
		}
	}
	sort.Slice(res.latencies, func(a, b int) bool { return res.latencies[a] < res.latencies[b] })
	return res
}

// normaliseBenchError strips the parts of an error that differ per
// occurrence — addresses, ports, statement names — so that a million
// instances of one problem collapse into one tally entry instead of a
// million singletons.
func normaliseBenchError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, " (SQLSTATE "); i >= 0 {
		// Keep the SQLSTATE, drop nothing else: it is the part an
		// operator would grep for.
		msg = msg[:i] + msg[i:]
	}
	for _, noisy := range []string{"127.0.0.1:", "[::1]:", "stmtcache_"} {
		if i := strings.Index(msg, noisy); i >= 0 {
			msg = msg[:i] + noisy + "…"
		}
	}
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return msg
}
