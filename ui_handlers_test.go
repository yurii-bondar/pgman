package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// The admin endpoints that act on a pool rather than just describing it.
// Each is one HTTP request away from taking a database offline, so the
// wiring between the URL, the pool it names and the panel that reports
// what happened is worth pinning: a handler that silently addressed the
// wrong pool, or reported success on a pool it never found, would be
// discovered during an incident.

// managePost drives one admin POST with a {name} path value, the way
// http.ServeMux would.
func managePost(t *testing.T, h http.HandlerFunc, path, name string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.SetPathValue("name", name)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestPausePoolHandlerParksAndReports(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	rec := managePost(t, pausePoolHandler(registry), "/pools/db1/pause", "db1")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST pause = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "paused") {
		t.Error("the management panel does not say the pool was paused")
	}

	p, _ := registry.Get("db1")
	if !p.IsPaused() {
		t.Error("the pool is not actually paused — the panel reported something that did not happen")
	}

	// And back again: resume has to reach the same pool, or PAUSE
	// becomes a one-way door that needs a restart to undo.
	rec = managePost(t, resumePoolHandler(registry), "/pools/db1/resume", "db1")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST resume = %d, want 200", rec.Code)
	}
	if p.IsPaused() {
		t.Error("the pool is still paused after resume")
	}
}

// TestReconnectPoolHandlerReportsHowManyWereDropped: the count is the
// only feedback an operator gets that the reconnect did anything, which
// after an RDS failover is the difference between "done" and "try again".
func TestReconnectPoolHandlerReportsHowManyWereDropped(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	cfg := dummyPoolConfig(2)
	cfg.BackendDSN = backend.dsn("app", "db1")
	cfg.BackendAddr = backend.addr()
	registry := NewPoolRegistryWithDefaults(map[string]PoolConfig{"db1": cfg}, NewEventLog(10), &Config{}, nil)

	// Put one connection in the idle pool so there is something to drop.
	p, _ := registry.Get("db1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.Release(conn)

	rec := managePost(t, reconnectPoolHandler(registry), "/pools/db1/reconnect", "db1")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST reconnect = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "1 idle dropped") {
		t.Errorf("panel = %q, want it to report one dropped connection", rec.Body.String())
	}
}

// TestPoolActionHandlersRejectUnknownPools: naming a pool that does not
// exist must be an error in the panel rather than a silent no-op, since
// the operator's next move depends on believing the action happened.
func TestPoolActionHandlersRejectUnknownPools(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	for name, h := range map[string]http.HandlerFunc{
		"pause":     pausePoolHandler(registry),
		"resume":    resumePoolHandler(registry),
		"reconnect": reconnectPoolHandler(registry),
	} {
		t.Run(name, func(t *testing.T) {
			rec := managePost(t, h, "/pools/ghost/"+name, "ghost")
			body := rec.Body.String()
			if !strings.Contains(body, "not found") {
				t.Errorf("panel = %q, want it to say the pool was not found", body)
			}
		})
	}
}

// TestResizePoolHandlerRejectsAnUnparsableLimit: the limit arrives from
// a form field, so "abc" and "-1" are both things a browser can send. A
// pool resized to zero would refuse every connection.
func TestResizePoolHandlerRejectsAnUnparsableLimit(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	h := resizePoolHandler(registry)

	for _, limit := range []string{"", "abc", "0", "-3"} {
		req := httptest.NewRequest(http.MethodPost, "/pools/db1/resize",
			strings.NewReader("limit="+limit))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("name", "db1")
		rec := httptest.NewRecorder()
		h(rec, req)

		if !strings.Contains(rec.Body.String(), "limit") {
			t.Errorf("limit=%q: panel = %q, want it to complain about the limit", limit, rec.Body.String())
		}
		if cfg, _ := registry.PoolConfig("db1"); cfg.Limit != 2 {
			t.Fatalf("limit=%q: the pool was resized to %d anyway", limit, cfg.Limit)
		}
	}
}

// TestAdminSessionHandlerAnswersBothProtocols: psql uses simple queries
// and pgx uses the extended protocol by default, so an admin console
// that only answers one of them looks broken to half its users — and the
// half it looks broken to just hangs.
func TestAdminSessionHandlerAnswersBothProtocols(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	handler := adminSessionHandler(registry)

	clientSide, proxySide := net.Pipe()
	t.Cleanup(func() { _ = clientSide.Close(); _ = proxySide.Close() })
	pg := pgproto3.NewBackend(proxySide, proxySide)
	fe := pgproto3.NewFrontend(clientSide, clientSide)

	done := make(chan struct{})
	go func() {
		handler(pg)
		close(done)
	}()

	// Simple protocol.
	fe.Send(&pgproto3.Query{String: "SHOW POOLS"})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send query: %v", err)
	}
	if !awaitReadyForQuery(t, fe) {
		t.Fatal("SHOW POOLS never produced ReadyForQuery")
	}

	// Extended protocol: a Parse/Bind/Execute/Sync batch has to be
	// acknowledged too, or a pgx client waits forever on the Sync.
	fe.Send(&pgproto3.Parse{Query: "SHOW POOLS"})
	fe.Send(&pgproto3.Bind{})
	fe.Send(&pgproto3.Execute{})
	fe.Send(&pgproto3.Sync{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send extended batch: %v", err)
	}
	if !awaitReadyForQuery(t, fe) {
		t.Fatal("the extended-protocol batch never produced ReadyForQuery")
	}

	fe.Send(&pgproto3.Terminate{})
	_ = fe.Flush()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("the admin session did not end on Terminate")
	}
}

// awaitReadyForQuery reads until RFQ, reporting whether it arrived.
func awaitReadyForQuery(t *testing.T, fe *pgproto3.Frontend) bool {
	t.Helper()
	for {
		msg, err := fe.Receive()
		if err != nil {
			return false
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return true
		}
	}
}

// TestAdminSQLReconnectAndResumeAcrossAllPools: the bare forms of these
// commands act on every pool at once, which is what an operator reaches
// for after a failover — and is also the most destructive thing the
// console can do by accident.
func TestAdminSQLReconnectAndResumeAcrossAllPools(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"db1": dummyPoolConfig(2),
		"db2": dummyPoolConfig(2),
	}, NewEventLog(10))

	p1, _ := registry.Get("db1")
	p2, _ := registry.Get("db2")
	p1.Pause()
	p2.Pause()

	msgs := adminExchange(t, registry, "RESUME")
	if _, ok := findMessage[*pgproto3.CommandComplete](msgs); !ok {
		t.Fatal("RESUME produced no CommandComplete")
	}
	if p1.IsPaused() || p2.IsPaused() {
		t.Error("a bare RESUME left a pool paused")
	}

	msgs = adminExchange(t, registry, "RECONNECT")
	if _, ok := findMessage[*pgproto3.CommandComplete](msgs); !ok {
		t.Error("RECONNECT produced no CommandComplete")
	}
}

// TestAdminSQLReportsUnknownPools: a typo in a pool name has to come
// back as an error, not as a successful command that did nothing.
func TestAdminSQLReportsUnknownPools(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	for _, cmd := range []string{"PAUSE ghost", "RESUME ghost", "RECONNECT ghost"} {
		msgs := adminExchange(t, registry, cmd)
		resp, ok := findMessage[*pgproto3.ErrorResponse](msgs)
		if !ok {
			t.Errorf("%q reported no error for a pool that does not exist", cmd)
			continue
		}
		if resp.Code != "3D000" {
			t.Errorf("%q error code = %s, want 3D000", cmd, resp.Code)
		}
	}
}

// TestShowClientsListsRegisteredSessions: SHOW CLIENTS is how an
// operator finds the session holding a lock, so it has to read the live
// registry rather than a snapshot taken at startup.
func TestShowClientsListsRegisteredSessions(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	pid, sess := registerSession("alice", "db1")
	sess.poolName = "db1"
	t.Cleanup(func() { deregisterSession(pid) })

	msgs := adminExchange(t, registry, "SHOW CLIENTS")
	var found bool
	for _, m := range msgs {
		row, ok := m.(*pgproto3.DataRow)
		if !ok {
			continue
		}
		if len(row.Values) >= 3 && string(row.Values[1]) == "alice" && string(row.Values[2]) == "db1" {
			found = true
		}
	}
	if !found {
		t.Error("SHOW CLIENTS did not list the registered session")
	}
}

// TestSplitAddrHandlesAddressesWithoutAPort: SHOW DATABASES reports host
// and port separately, and backend_addr is operator-supplied text — a
// value without a colon must degrade to an empty port rather than
// producing a row with the whole address in the port column.
func TestSplitAddrHandlesAddressesWithoutAPort(t *testing.T) {
	cases := map[string][2]string{
		"db.internal:5432": {"db.internal", "5432"},
		"db.internal":      {"db.internal", ""},
		"":                 {"", ""},
	}
	for in, want := range cases {
		host, port := splitAddr(in)
		if host != want[0] || port != want[1] {
			t.Errorf("splitAddr(%q) = (%q, %q), want (%q, %q)", in, host, port, want[0], want[1])
		}
	}
}

// plainWriter is an http.ResponseWriter that is deliberately not an
// http.Flusher, which is what a middleware wrapping the response can
// accidentally produce. The SSE handler has to refuse rather than stream
// into something it cannot flush, or every dashboard behind that
// middleware shows a page that never updates.
type plainWriter struct {
	header http.Header
	code   int
	body   strings.Builder
	// failAfter makes Write fail once this many bytes have been
	// accepted, standing in for a browser tab that was closed
	// mid-stream: the write error is how the server finds out.
	failAfter int
	written   int
}

func (w *plainWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *plainWriter) WriteHeader(code int) { w.code = code }

func (w *plainWriter) Write(p []byte) (int, error) {
	if w.failAfter > 0 && w.written >= w.failAfter {
		return 0, errors.New("client went away")
	}
	w.written += len(p)
	return w.body.Write(p)
}

// TestSSEHandlerRefusesAResponseItCannotFlush: without a flush every
// event sits in a buffer, so the dashboard would render once and then
// appear frozen — which is indistinguishable from a hung proxy at
// exactly the moment somebody is checking whether the proxy is hung.
func TestSSEHandlerRefusesAResponseItCannotFlush(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	w := &plainWriter{}
	sseHandler(registry, NewEventLog(10))(w, httptest.NewRequest(http.MethodGet, "/events", nil))

	if w.code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 when the response cannot be flushed", w.code)
	}
}

// TestSSEHandlerStopsWhenTheClientGoesAway: the stream runs in a
// goroutine per open tab, and a write error is the only signal that the
// tab is gone. Ignoring it leaves a goroutine rendering the pool table
// into a dead socket every 500ms, forever.
func TestSSEHandlerStopsWhenTheClientGoesAway(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	// A recorder is a Flusher, so wrap one that fails partway through
	// the first event instead.
	w := &flushableWriter{plainWriter: plainWriter{failAfter: 16}}

	done := make(chan struct{})
	go func() {
		sseHandler(registry, NewEventLog(10))(w, httptest.NewRequest(http.MethodGet, "/events", nil))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the SSE handler kept streaming to a client that had gone away")
	}
}

// flushableWriter is a plainWriter that does implement http.Flusher, for
// the case where streaming starts and then the client disappears.
type flushableWriter struct {
	plainWriter
}

func (w *flushableWriter) Flush() {}
