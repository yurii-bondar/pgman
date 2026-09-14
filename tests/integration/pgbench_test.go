//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestPgbenchStyleMix — realistic workload mix on pgman. Not a
// literal pgbench replay (no accounts/tellers tables), but the same
// spirit: multi-column read, small arithmetic on the backend, no toy
// SELECT-1. Reveals what real apps see: proxy overhead amortized into
// meaningful work.
//
// Override env vars:
//
//	PGBENCH_DURATION       — soak duration (default 15s)
//	PGBENCH_CONCURRENCY    — parallel clients (default 100)
//	PGBENCH_POOL_LIMIT     — proxy pool limit (default 50)
//
// Expected on a modern laptop w/ docker-desktop Postgres:
//
//	~30K QPS (up from ~16K for the SELECT-1 microbench, because the
//	proxy overhead becomes a smaller fraction of total latency).
func TestPgbenchStyleMix(t *testing.T) {
	dur := envDuration("PGBENCH_DURATION", 15*time.Second)
	conc := envInt("PGBENCH_CONCURRENCY", 100)
	poolLimit := envInt("PGBENCH_POOL_LIMIT", 50)

	inst := startProxy(t, poolLimit)
	ctx, stop := context.WithTimeout(context.Background(), dur+10*time.Second)
	defer stop()

	pool := pgxPool(t, inst.ProxyAddr, int32(conc))

	// Warm.
	var warm int
	_ = pool.QueryRow(ctx, "SELECT 1").Scan(&warm)

	var (
		totalOps  atomic.Int64
		totalFail atomic.Int64
		latNs     atomic.Int64
		maxLatNs  atomic.Int64
	)

	// Query the client rotates through — a slightly interesting one
	// (multiple columns, an arithmetic expression, a text function).
	// Enough backend work that the proxy is decisively NOT the
	// bottleneck, but not so much that PG becomes the bottleneck.
	const q = "SELECT $1::int, $1::int * 2, upper($2::text), current_timestamp"

	done := make(chan struct{})
	deadline := time.After(dur)
	for i := 0; i < conc; i++ {
		go func(id int) {
			var (
				a, b int
				s    string
				ts   time.Time
			)
			for {
				select {
				case <-done:
					return
				default:
				}
				start := time.Now()
				err := pool.QueryRow(ctx, q, id, fmt.Sprintf("worker-%d", id)).Scan(&a, &b, &s, &ts)
				el := time.Since(start).Nanoseconds()
				if err != nil {
					totalFail.Add(1)
					continue
				}
				totalOps.Add(1)
				latNs.Add(el)
				for {
					cur := maxLatNs.Load()
					if el <= cur || maxLatNs.CompareAndSwap(cur, el) {
						break
					}
				}
			}
		}(i)
	}

	<-deadline
	close(done)
	time.Sleep(500 * time.Millisecond)

	ops := totalOps.Load()
	fails := totalFail.Load()
	var avg time.Duration
	if ops > 0 {
		avg = time.Duration(latNs.Load() / ops)
	}
	maxL := time.Duration(maxLatNs.Load())
	qps := float64(ops) / dur.Seconds()

	t.Logf("═══ pgbench-style mix (%s, %d workers, pool=%d) ═══", dur, conc, poolLimit)
	t.Logf("  Total ops:    %d", ops)
	t.Logf("  Failed:       %d", fails)
	t.Logf("  Avg latency:  %s", avg)
	t.Logf("  Max latency:  %s", maxL)
	t.Logf("  Throughput:   %.0f QPS", qps)

	if ops == 0 {
		t.Fatal("no successful ops")
	}
	if fails > 0 {
		rate := float64(fails) / float64(ops+fails) * 100
		t.Logf("  Failure rate: %.2f%%", rate)
		if rate > 1.0 {
			t.Fatalf("failure rate too high: %.2f%%", rate)
		}
	}
}

func envDuration(key string, dflt time.Duration) time.Duration {
	if s := os.Getenv(key); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			return d
		}
	}
	return dflt
}

func envInt(key string, dflt int) int {
	if s := os.Getenv(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return dflt
}
