package main

// The handshake's two deadlines — the one that must fire, and the one
// that must be gone by the time anyone could notice it existed — plus
// dial retry on the pass-through path.
//
// dialAndHandshake puts a deadline on the socket while authenticating,
// because a backend that completes the TCP handshake and then says
// nothing would otherwise hold the dialling goroutine, and the pool
// slot behind it, indefinitely. That is what the deadline is for, and
// it had no test.
//
// It then clears the deadline before handing the connection to the
// pool. That line carries a comment saying a leftover deadline makes
// the first query fail "at a time nothing explains" — a precise
// description of a bug that is close to undiagnosable from a support
// ticket, because a deadline is absolute: one left behind does not fail
// the next query, it fails whichever query happens to run once the wall
// clock passes it, on a connection reused many times since. Also no
// test.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yurii-bondar/pgman/pool"
)

// silentBackend accepts TCP connections and then never speaks. It is
// the shape of a backend that is up, reachable and wedged — a database
// mid-failover, or a firewall that allows SYN and drops the rest. The
// connections are held rather than closed on purpose: closing would
// make this the already-covered "connection reset" case.
func silentBackend(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted = &atomic.Int32{}

	var mu sync.Mutex
	var held []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return ln.Addr().String(), accepted
}

func splitHostPortForTest(t *testing.T, addr string) (string, uint16) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, uint16(port)
}

// TestHandshakeTimesOutAgainstASilentBackend is the deadline doing its
// job: a backend that accepts and then says nothing must produce an
// error, not a goroutine parked forever.
//
// The caller's context supplies the bound, because
// backendHandshakeTimeout is measured in seconds and a unit test should
// not be. dialAndHandshake takes whichever of the two is sooner, so a
// short context exercises the same code.
func TestHandshakeTimesOutAgainstASilentBackend(t *testing.T) {
	addr, accepted := silentBackend(t)

	cfg, err := pgconn.ParseConfig("postgres://alice@" + addr + "/db?sslmode=disable")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	host, port := splitHostPortForTest(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := dialAndHandshake(ctx, cfg,
			connectTarget{host: host, port: port},
			"db", "alice", passthroughCreds{})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a backend that never answered produced a working connection")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("handshake took %s to give up — the deadline is not bounding it", elapsed)
		}
		t.Logf("gave up after %s: %v", time.Since(start).Round(time.Millisecond), err)
	case <-time.After(15 * time.Second):
		t.Fatal("dialAndHandshake never returned against a silent backend — " +
			"in production that pins a pool slot for the life of the process")
	}

	if accepted.Load() == 0 {
		t.Error("the backend never accepted a connection, so nothing was tested")
	}
}

// TestHandshakeClearsTheDeadlineOnSuccess is the other half, and the
// subtler one.
//
// After a successful handshake the returned connection must carry no
// deadline. The check is behavioural rather than structural — net.Conn
// exposes no way to read a deadline back — so the test does what a real
// first query does: a read. With a stale handshake deadline (already in
// the past by then) the read returns immediately; with the deadline
// properly cleared it blocks until the short one this test sets. The
// difference between those two outcomes is the assertion.
func TestHandshakeClearsTheDeadlineOnSuccess(t *testing.T) {
	const password = "alice-password"
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password})

	// Pass-through only works when pgman's verifier is byte-identical
	// to the backend's, so the verifier is built from the fake server's
	// own salt and iteration count.
	pc := recoveredPassthroughCreds(t, password, fakePGVerifier(t, password))

	cfg, err := pgconn.ParseConfig(backend.dsn("alice", "db1"))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	host, port := splitHostPortForTest(t, backend.addr())

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	bc, err := dialAndHandshake(ctx, cfg,
		connectTarget{host: host, port: port}, "db1", "alice", pc)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer bc.Close()

	// The handshake ends at ReadyForQuery and the fake server then waits
	// for a query, so there is nothing further to read. Any read that
	// returns quickly is returning because of a deadline, and the only
	// question is whose.
	const window = 200 * time.Millisecond
	if err := bc.SetReadDeadline(time.Now().Add(window)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 1)
	_, readErr := bc.Read(buf)
	waited := time.Since(start)

	if readErr == nil {
		t.Fatal("unexpected data on a connection whose handshake had finished")
	}
	if !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("read failed with %v, want the deadline this test set", readErr)
	}
	// Half the window is a generous margin: a stale absolute deadline
	// trips with no wait at all, while the deadline set above cannot
	// fire early.
	if waited < window/2 {
		t.Errorf("the read gave up after %s of a %s window — an old handshake "+
			"deadline is still on the socket, and it would fail some "+
			"unrelated client's query later", waited, window)
	}
}

// flakyForwarder refuses the first `failures` connections and forwards
// everything after that to upstream.
//
// It exists so the retry test measures the real composition — the
// pass-through dialer underneath the pool's retry loop — rather than a
// synthetic dialler, which pool_extra_test.go already covers.
func flakyForwarder(t *testing.T, upstream string, failures int32) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var seen atomic.Int32

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			if seen.Add(1) <= failures {
				_ = client.Close()
				continue
			}
			up, err := net.DialTimeout("tcp", upstream, 5*time.Second)
			if err != nil {
				_ = client.Close()
				continue
			}
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = io.Copy(up, client); _ = up.Close(); _ = client.Close() }()
			go func() { defer wg.Done(); _, _ = io.Copy(client, up); _ = up.Close(); _ = client.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	return ln.Addr().String()
}

// TestPassthroughDialerRetriesThroughThePool closes the last item on
// the review's SCRAM list: server_login_retry on the pass-through path.
//
// Retry is implemented once, in the pool, and is tested there with a
// synthetic dialler. What was never checked is that the pass-through
// dialler composes with it — that a transient failure on a connection
// authenticated with a recovered ClientKey is retried rather than
// surfaced. That is the difference between a failover being invisible
// and being an incident.
func TestPassthroughDialerRetriesThroughThePool(t *testing.T) {
	const password = "alice-password"
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthSCRAM, password: password})

	// Two failures, so a pool configured with a single retry would
	// still fail: the test has to distinguish "retries" from "retries
	// enough".
	front := flakyForwarder(t, backend.addr(), 2)

	store := newClientKeyStore()
	creds, err := ParseSCRAMVerifier(fakePGVerifier(t, password))
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}
	pc := recoveredPassthroughCreds(t, password, fakePGVerifier(t, password))
	store.remember("alice", pc.clientKey, creds)

	host, port, _ := net.SplitHostPort(front)
	dsn := "postgres://alice@" + host + ":" + port + "/db1?sslmode=disable"

	dial := newPassthroughDialer(dsn, "alice", store, false)
	p := pool.New(dial, 2, nil, nil, pool.WithDialRetry(3, 5*time.Millisecond))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire gave up, so a transient backend failure reaches the "+
			"client instead of being retried: %v", err)
	}
	p.Release(conn)

	// And the connection that did come back must be a real
	// pass-through one: authenticated as alice, not something the
	// forwarder let through half-formed.
	bc, ok := conn.(*backendConn)
	if !ok {
		t.Fatalf("pool returned %T, want *backendConn", conn)
	}
	if bc.pid == 0 {
		t.Error("the retried connection carries no backend PID, so the handshake did not complete")
	}
	params := backend.startupParams()
	if len(params) == 0 {
		t.Fatal("the backend saw no startup message")
	}
	if got := params[len(params)-1]["user"]; got != "alice" {
		t.Errorf("the backend was told user=%q, want alice", got)
	}
}

// TestPassthroughRetryIsBounded is the other side of the same setting.
// Unbounded retry against a backend that is down turns every client
// into a slow error instead of a fast one, and starves the circuit
// breaker of the failures it opens on.
func TestPassthroughRetryIsBounded(t *testing.T) {
	var attempts atomic.Int32
	dial := func(ctx context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, errors.New("backend is down")
	}

	p := pool.New(dial, 2, nil, nil, pool.WithDialRetry(2, time.Millisecond))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Close(ctx)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := p.Acquire(ctx)
	if err == nil {
		t.Fatal("Acquire succeeded against a backend that always fails")
	}
	if !strings.Contains(err.Error(), "backend is down") {
		t.Errorf("error %v does not carry the dialler's own cause", err)
	}
	// One initial attempt plus two retries.
	if got := attempts.Load(); got != 3 {
		t.Errorf("dialled %d times, want 3 — retry is not bounded by the setting", got)
	}
}
