//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestAdminPauseResume — PAUSE via admin API parks new queries; RESUME
// wakes them. In-flight transactions are not disturbed.
func TestAdminPauseResume(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// One in-flight conn before pause — should keep working during pause.
	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	// Pause the pool.
	if err := adminPost(inst.AdminAddr, "/pools/pgman_test/pause"); err != nil {
		t.Fatalf("pause: %v", err)
	}

	// Fire off a new client whose FIRST query must block until Resume.
	// We give it 3s; if it succeeds before Resume, pause was ineffective.
	newQueryDone := make(chan error, 1)
	go func() {
		c2, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
		if err != nil {
			newQueryDone <- fmt.Errorf("connect: %w", err)
			return
		}
		defer c2.Close(ctx)
		var n int
		newQueryDone <- c2.QueryRow(ctx, "SELECT 1").Scan(&n)
	}()

	select {
	case err := <-newQueryDone:
		t.Fatalf("query completed during pause: err=%v", err)
	case <-time.After(1 * time.Second):
		// Good — still blocked.
	}

	// Resume.
	if err := adminPost(inst.AdminAddr, "/pools/pgman_test/resume"); err != nil {
		t.Fatalf("resume: %v", err)
	}

	select {
	case err := <-newQueryDone:
		if err != nil {
			t.Fatalf("query after resume: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("query did not complete within 5s after Resume")
	}
}

// TestAdminReconnect — RECONNECT drops idle backends immediately;
// subsequent Acquire dials fresh. In-flight is not killed.
func TestAdminReconnect(t *testing.T) {
	inst := startProxy(t, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Warm up idle: 3 concurrent clients then release.
	warm := func() {
		var wg sync.WaitGroup
		conns := make([]*pgx.Conn, 3)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
				if err != nil {
					t.Errorf("warm connect %d: %v", i, err)
					return
				}
				var n int
				c.QueryRow(ctx, "SELECT 1").Scan(&n)
				conns[i] = c
			}(i)
		}
		wg.Wait()
		for _, c := range conns {
			if c != nil {
				c.Close(ctx)
			}
		}
	}
	warm()

	// Sanity: pool should have some idle now.
	// (No admin endpoint returns pool stats, so we just verify RECONNECT
	//  is accepted and subsequent queries still work.)
	if err := adminPost(inst.AdminAddr, "/pools/pgman_test/reconnect"); err != nil {
		t.Fatalf("reconnect: %v", err)
	}

	// A fresh query must still succeed — dial happens on demand.
	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("post-reconnect connect: %v", err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, "SELECT 42").Scan(&n); err != nil {
		t.Fatalf("post-reconnect query: %v", err)
	}
	if n != 42 {
		t.Fatalf("got %d, want 42", n)
	}
}

// TestAdminPauseRespectsClientTimeout — a paused pool must honor the
// client's query_wait_timeout / context deadline.
func TestAdminPauseRespectsClientTimeout(t *testing.T) {
	inst := startProxy(t, 3)

	// Pause immediately.
	if err := adminPost(inst.AdminAddr, "/pools/pgman_test/pause"); err != nil {
		t.Fatalf("pause: %v", err)
	}
	t.Cleanup(func() {
		_ = adminPost(inst.AdminAddr, "/pools/pgman_test/resume")
	})

	// Short-deadline client — must fail with a deadline error, not hang.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err == nil {
		// Connect succeeded (auth happens before route), the query
		// will be what hits the pause gate.
		var n int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&n)
		conn.Close(context.Background())
	}
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected deadline/pause error, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took %s — should have failed near the 2s deadline", elapsed)
	}
	t.Logf("paused-pool query correctly failed after %s: %v", elapsed, err)
}

// TestCopyFromStdin — the classic bulk-load path. Client sends
// COPY foo FROM STDIN followed by CopyData/CopyDone. Verifies the
// proxy correctly switches into COPY IN mode and doesn't deadlock.
//
// Uses a regular (non-TEMP) table because transaction pooling routes
// each transaction to a potentially different backend — TEMP tables
// are session-local and would vanish between CREATE and COPY.
func TestCopyFromStdin(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	tableName := fmt.Sprintf("copy_in_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (id int, val text)`, tableName)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP TABLE "+tableName)
	})

	// Build a payload: 1000 rows.
	var payload bytes.Buffer
	const rows = 1000
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&payload, "%d\thello-%d\n", i, i)
	}

	n, err := conn.PgConn().CopyFrom(ctx, &payload, "COPY "+tableName+" FROM STDIN")
	if err != nil {
		t.Fatalf("CopyFrom: %v", err)
	}
	if n.RowsAffected() != rows {
		t.Fatalf("copied %d, want %d", n.RowsAffected(), rows)
	}

	// Verify.
	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM "+tableName).Scan(&count); err != nil {
		t.Fatalf("select count: %v", err)
	}
	if count != rows {
		t.Fatalf("row count %d, want %d", count, rows)
	}
}

// TestCopyToStdout — the reverse direction. Backend streams CopyData
// rows to the client. Existing relay loop already handles this without
// special casing (CopyData → CopyDone → CommandComplete → RFQ).
func TestCopyToStdout(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)

	tableName := fmt.Sprintf("copy_out_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (id int, val text)`, tableName)); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(context.Background(), "DROP TABLE "+tableName)
	})
	if _, err := conn.Exec(ctx, fmt.Sprintf(`INSERT INTO %s SELECT g, 'row-'||g FROM generate_series(1, 500) g`, tableName)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	var out bytes.Buffer
	tag, err := conn.PgConn().CopyTo(ctx, &out, "COPY "+tableName+" TO STDOUT")
	if err != nil {
		t.Fatalf("CopyTo: %v", err)
	}
	if tag.RowsAffected() != 500 {
		t.Fatalf("streamed %d rows, want 500", tag.RowsAffected())
	}
	if !bytes.Contains(out.Bytes(), []byte("500\trow-500")) {
		t.Fatal("expected row 500 in COPY output")
	}
}

// TestCopyFromStdinWithConcurrentTraffic — while one client streams a
// COPY IN, other clients query normally through the same pool. Guards
// against COPY relay accidentally holding the whole pool hostage.
func TestCopyFromStdinWithConcurrentTraffic(t *testing.T) {
	inst := startProxy(t, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	setupConn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("setup connect: %v", err)
	}
	// Real table (not temp) — temp is per-session and not visible from other clients.
	tableName := fmt.Sprintf("copy_concurrent_%d", time.Now().UnixNano())
	if _, err := setupConn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s (id int)`, tableName)); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		setupConn.Exec(context.Background(), "DROP TABLE "+tableName)
		setupConn.Close(context.Background())
	})

	// Background traffic: 4 goroutines running SELECT 1 in a loop.
	stop := make(chan struct{})
	var bgOps atomic.Int64
	var bgErrs atomic.Int64
	var bgWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			c, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
			if err != nil {
				bgErrs.Add(1)
				return
			}
			defer c.Close(context.Background())
			for {
				select {
				case <-stop:
					return
				default:
				}
				var n int
				if err := c.QueryRow(ctx, "SELECT 1").Scan(&n); err != nil {
					bgErrs.Add(1)
					return
				}
				bgOps.Add(1)
			}
		}()
	}

	// Copy while background is running.
	copyConn, err := pgx.Connect(ctx, proxyDSN(inst.ProxyAddr))
	if err != nil {
		t.Fatalf("copy connect: %v", err)
	}
	defer copyConn.Close(ctx)

	var payload bytes.Buffer
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&payload, "%d\n", i)
	}
	tag, err := copyConn.PgConn().CopyFrom(ctx, &payload, "COPY "+tableName+" FROM STDIN")
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if tag.RowsAffected() != 5000 {
		t.Fatalf("copied %d, want 5000", tag.RowsAffected())
	}

	close(stop)
	bgWg.Wait()

	if bgErrs.Load() > 0 {
		t.Fatalf("%d background errors during COPY", bgErrs.Load())
	}
	if bgOps.Load() == 0 {
		t.Fatal("background traffic saw zero ops — pool was starved")
	}
	t.Logf("copy completed with %d concurrent SELECT 1 ops running", bgOps.Load())
}

// ---- Helpers --------------------------------------------------------

// adminPost fires a POST at the pgman admin endpoint. The admin
// server is loopback-only trust-auth in test config, so no auth headers
// needed.
func adminPost(adminAddr, path string) error {
	url := "http://" + adminAddr + path
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin POST %s: %d — %s", path, resp.StatusCode, body)
	}
	return nil
}
