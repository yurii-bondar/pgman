//go:build integration

package integration

import (
	"context"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// BenchmarkProxySelectOne — raw query-through-proxy latency (single conn).
func BenchmarkProxySelectOne(b *testing.B) {
	inst := benchProxy(b)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		b.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var dummy int
	_ = pool.QueryRow(ctx, "SELECT 1").Scan(&dummy) // warm

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := pool.QueryRow(ctx, "SELECT 1").Scan(&dummy); err != nil {
			b.Fatalf("query: %v", err)
		}
	}
}

// BenchmarkProxyConcurrent — throughput under GOMAXPROCS parallel load.
func BenchmarkProxyConcurrent(b *testing.B) {
	inst := benchProxy(b)
	ctx := context.Background()

	cfg, _ := pgxpool.ParseConfig(proxyDSN(inst.ProxyAddr))
	cfg.MaxConns = 16
	cfg.MinConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		b.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var dummy int
	_ = pool.QueryRow(ctx, "SELECT 1").Scan(&dummy) // warm

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var n int
		for pb.Next() {
			if err := pool.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil {
				b.Fatalf("query: %v", err)
			}
		}
	})
}

// TestSoakSustained — time-boxed soak test: 30 goroutines for N seconds.
// Reports ops/sec, latency, failure rate. Catches leaks and degradation.
//
// Default: 10s. Override: PGMAN_SOAK_DURATION=30s
func TestSoakSustained(t *testing.T) {
	poolLimit := 20
	if s := os.Getenv("PGMAN_SOAK_POOL_LIMIT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			poolLimit = n
		}
	}
	inst := startProxy(t, poolLimit)

	soakDur := 10 * time.Second
	if s := os.Getenv("PGMAN_SOAK_DURATION"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			soakDur = d
		}
	}

	// Concurrency overrideable so we can find the real throughput
	// ceiling (with just 30 goroutines the test is latency-bound:
	// 30 / avg_latency_sec = max ops/sec, hiding proxy headroom).
	concurrency := 30
	if s := os.Getenv("PGMAN_SOAK_CONCURRENCY"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			concurrency = n
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), soakDur+10*time.Second)
	defer stop()

	pool := pgxPool(t, inst.ProxyAddr, int32(concurrency))

	// Warm.
	var d int
	_ = pool.QueryRow(ctx, "SELECT 1").Scan(&d)

	var (
		totalOps  atomic.Int64
		totalFail atomic.Int64
		latencyNs atomic.Int64
		maxLatNs  atomic.Int64
	)

	deadline := time.After(soakDur)
	done := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		go func(id int) {
			for {
				select {
				case <-done:
					return
				default:
				}

				start := time.Now()
				var n int
				err := pool.QueryRow(ctx, "SELECT $1::int", id).Scan(&n)
				elapsed := time.Since(start).Nanoseconds()

				if err != nil {
					totalFail.Add(1)
					continue
				}
				totalOps.Add(1)
				latencyNs.Add(elapsed)

				for {
					cur := maxLatNs.Load()
					if elapsed <= cur || maxLatNs.CompareAndSwap(cur, elapsed) {
						break
					}
				}
			}
		}(i)
	}

	<-deadline
	close(done)
	// Give goroutines a moment to finish in-flight queries.
	time.Sleep(500 * time.Millisecond)

	ops := totalOps.Load()
	fails := totalFail.Load()
	avgLat := time.Duration(0)
	if ops > 0 {
		avgLat = time.Duration(latencyNs.Load() / ops)
	}
	maxLat := time.Duration(maxLatNs.Load())

	t.Logf("═══ Soak test results (%s, %d goroutines) ═══", soakDur, concurrency)
	t.Logf("  Total ops:     %d", ops)
	t.Logf("  Failed ops:    %d", fails)
	t.Logf("  Avg latency:   %s", avgLat)
	t.Logf("  Max latency:   %s", maxLat)
	t.Logf("  Ops/sec:       %.0f", float64(ops)/soakDur.Seconds())

	if fails > 0 {
		failRate := float64(fails) / float64(ops+fails) * 100
		t.Logf("  Failure rate:  %.2f%%", failRate)
		if failRate > 1.0 {
			t.Fatalf("failure rate %.2f%% exceeds 1%% threshold", failRate)
		}
	}
	if ops == 0 {
		t.Fatal("zero successful operations")
	}
}

// ---- Bench harness --------------------------------------------------

// benchProxy is startProxy adapted for *testing.B (uses b.Cleanup).
func benchProxy(b *testing.B) *proxyInstance {
	b.Helper()
	// Re-use the same startProxy logic but adapted for benchmarks.
	// We can't call startProxy directly because it expects *testing.T.
	// Use a thin wrapper.
	return startProxyForBench(b, 20)
}

// startProxyForBench mirrors startProxy but accepts testing.TB.
func startProxyForBench(tb testing.TB, poolLimit int) *proxyInstance {
	tb.Helper()

	proxyPort := freePortTB(tb)
	metricsPort := freePortTB(tb)
	adminPort := freePortTB(tb)

	cfg := configYAML(proxyPort, metricsPort, adminPort, poolLimit)

	tmpCfg, err := os.CreateTemp("", "pgman-bench-*.yaml")
	if err != nil {
		tb.Fatalf("create config: %v", err)
	}
	tmpCfg.WriteString(cfg)
	tmpCfg.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := startPgmanCmd(ctx, tmpCfg.Name())
	if err := cmd.Start(); err != nil {
		cancel()
		os.Remove(tmpCfg.Name())
		tb.Fatalf("start pgman: %v", err)
	}

	addr := addrStr(proxyPort)
	if err := waitForPortTB(tb, addr, 5*time.Second); err != nil {
		cancel()
		cmd.Wait()
		os.Remove(tmpCfg.Name())
		tb.Fatalf("pgman did not start: %v", err)
	}

	tb.Cleanup(func() {
		cancel()
		cmd.Wait()
		os.Remove(tmpCfg.Name())
	})

	return &proxyInstance{
		ProxyAddr:   addr,
		MetricsAddr: addrStr(metricsPort),
		AdminAddr:   addrStr(adminPort),
		cmd:         cmd,
		configPath:  tmpCfg.Name(),
		cancel:      cancel,
	}
}
