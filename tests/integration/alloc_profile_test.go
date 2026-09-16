//go:build integration

// Allocation accounting for the proxy process itself.
//
// The micro-benchmarks in this package report allocs/op, but those are
// the *client's* allocations: pgman runs as a subprocess, so Go's
// -memprofile sees pgx and nothing else. For a proxy whose hot path is
// "parse a small message, copy it, write it out", the number that
// matters is how much garbage the proxy makes per query — and the only
// place that can be read is the proxy's own runtime.
//
// pgman already exposes net/http/pprof on the admin listener behind
// enable_pprof, so no new machinery is needed: take a reading, apply a
// known number of queries, take another, divide.
//
// This is a measurement, not a pass/fail gate. It prints a number and
// keeps the profile as an artifact; a threshold would either be so
// loose it never fires or so tight it fails on runner noise. The point
// is that a change which doubles allocation per query shows up in a CI
// log instead of a support ticket.
package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"
)

// allocHeaderRe matches the summary line of pprof's debug=1 heap
// output:
//
//	heap profile: 42: 6784 [98765: 12345678] @ heap/1048576
//
// The bracketed pair is cumulative since process start — total objects
// and total bytes ever allocated — which is exactly what a rate needs.
// The unbracketed pair is live heap, which is not: a GC between the two
// readings would make it meaningless.
var allocHeaderRe = regexp.MustCompile(`^heap profile: \d+: \d+ \[(\d+): (\d+)\]`)

type allocTotals struct {
	objects uint64
	bytes   uint64
}

func readAllocTotals(t *testing.T, adminAddr string) allocTotals {
	t.Helper()

	url := fmt.Sprintf("http://%s/debug/pprof/allocs?debug=1", adminAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build pprof request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetch %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s returned %s — is enable_pprof set?", url, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read pprof body: %v", err)
	}
	m := allocHeaderRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("could not find the totals line in the profile; first 200 bytes:\n%.200s", body)
	}
	objects, _ := strconv.ParseUint(string(m[1]), 10, 64)
	bytes, _ := strconv.ParseUint(string(m[2]), 10, 64)
	return allocTotals{objects: objects, bytes: bytes}
}

func TestAllocationRatePerQuery(t *testing.T) {
	// enable_pprof is off by default and deliberately so — it is a
	// live-heap dump gun. The harness forwards this verbatim into the
	// generated config.
	t.Setenv("PGMAN_TEST_EXTRA_CONFIG", "enable_pprof: true\n")

	// Exact allocation accounting, not sampled.
	//
	// Go's default MemProfileRate samples one allocation per 512 KiB.
	// Over a run that allocates a few megabytes that is a handful of
	// samples, and the scaled-up totals it reports are noise dressed as
	// numbers — the first version of this test confidently printed
	// "0.0 allocs/query". memprofilerate=1 records every allocation.
	//
	// The cost is throughput: the QPS logged below is therefore NOT a
	// performance measurement, and the benchmark suite is where that
	// question belongs. This test answers "how much garbage per query",
	// and for that the answer has to be exact.
	//
	// The subprocess inherits this because startPgmanCmd leaves
	// cmd.Env nil.
	t.Setenv("GODEBUG", "memprofilerate=1")

	inst := startProxy(t, 20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	pool := pgxPool(t, inst.ProxyAddr, 16)

	// Warm: fill the backend pool and let every one-off allocation the
	// first queries cause land before the first reading.
	for i := 0; i < 2000; i++ {
		var n int
		if err := pool.QueryRow(ctx, "SELECT $1::int", i).Scan(&n); err != nil {
			t.Fatalf("warm query: %v", err)
		}
	}

	const queries = 60000
	const workers = 16

	before := readAllocTotals(t, inst.AdminAddr)
	start := time.Now()

	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			var (
				a, b int
				s    string
				ts   time.Time
			)
			for i := 0; i < queries/workers; i++ {
				err := pool.QueryRow(ctx,
					"SELECT $1::int, $1::int * 2, upper($2::text), current_timestamp",
					id, "worker").Scan(&a, &b, &s, &ts)
				if err != nil {
					errs[id] = err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for _, err := range errs {
		if err != nil {
			t.Fatalf("load query: %v", err)
		}
	}

	after := readAllocTotals(t, inst.AdminAddr)

	ran := int64(queries/workers) * workers
	deltaBytes := after.bytes - before.bytes
	deltaObjects := after.objects - before.objects

	t.Logf("═══ pgman allocation rate ═══")
	t.Logf("  queries:            %d in %s (%.0f QPS)", ran, elapsed.Round(time.Millisecond),
		float64(ran)/elapsed.Seconds())
	t.Logf("  bytes allocated:    %d (%.0f B/query)", deltaBytes, float64(deltaBytes)/float64(ran))
	t.Logf("  objects allocated:  %d (%.1f allocs/query)", deltaObjects, float64(deltaObjects)/float64(ran))
	t.Logf("  allocation rate:    %.1f MiB/s", float64(deltaBytes)/elapsed.Seconds()/(1<<20))

	if deltaBytes == 0 {
		t.Fatal("the proxy allocated nothing across 60k queries — the reading is not working")
	}

	// Keep the profiles so a regression can be investigated rather than
	// just noticed. CI uploads the directory as an artifact.
	saveProfile(t, inst.AdminAddr, "allocs", "allocs.pb.gz")
	saveProfile(t, inst.AdminAddr, "heap", "heap.pb.gz")
}

// saveProfile downloads one pprof profile into testdata-adjacent output
// so `go tool pprof -top <file>` works on it directly.
func saveProfile(t *testing.T, adminAddr, name, filename string) {
	t.Helper()

	dir := os.Getenv("PGMAN_PROFILE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create profile dir: %v", err)
	}

	url := fmt.Sprintf("http://%s/debug/pprof/%s", adminAddr, name)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Logf("could not fetch %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	t.Logf("  %s profile: %s", name, path)
}
