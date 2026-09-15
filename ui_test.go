package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yurii-bondar/pgman/pool"
)

func TestPoolRows(t *testing.T) {
	pools := map[string]*pool.Pool{
		"zebra": pool.New(nil, 3, nil, nil),
		"alpha": pool.New(nil, 5, nil, nil),
	}
	rows := poolRows(pools)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0].Name != "alpha" || rows[1].Name != "zebra" {
		t.Errorf("expected alphabetical order, got %s, %s", rows[0].Name, rows[1].Name)
	}
	if rows[0].Limit != 5 || rows[1].Limit != 3 {
		t.Errorf("limits not reflected: %+v %+v", rows[0], rows[1])
	}
}

func TestSessionRowsReflectsRegisteredSessions(t *testing.T) {
	pid, sess := registerSession("frank", "shop")
	defer deregisterSession(pid)

	rows := sessionRows()
	var found *struct{}
	for _, r := range rows {
		if r.PID == pid {
			found = &struct{}{}
			if r.User != "frank" || r.Database != "shop" {
				t.Errorf("got user=%s db=%s, want frank/shop", r.User, r.Database)
			}
			if r.Active {
				t.Error("expected idle session to show Active=false")
			}
		}
	}
	if found == nil {
		t.Fatal("expected registered session to appear in sessionRows()")
	}

	sess.setBackend(&backendConn{})
	rows = sessionRows()
	for _, r := range rows {
		if r.PID == pid && (!r.Active || r.TxFor == "") {
			t.Errorf("expected active session with non-empty TxFor, got %+v", r)
		}
	}
}

func TestEventRowsFormatsTimestamps(t *testing.T) {
	l := NewEventLog(5)
	l.Record("mypool", "discard", nil)

	rows := eventRows(l)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Pool != "mypool" || rows[0].Kind != "discard" {
		t.Errorf("unexpected row: %+v", rows[0])
	}
	if _, err := time.Parse("15:04:05", rows[0].Time); err != nil {
		t.Errorf("expected HH:MM:SS formatted time, got %q", rows[0].Time)
	}
}

func TestManageRowsReflectsRegistry(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"b": dummyPoolConfig(2),
		"a": dummyPoolConfig(9),
	}, NewEventLog(10))

	rows := manageRows(registry)
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
	if rows[0].Name != "a" || rows[1].Name != "b" {
		t.Errorf("expected sorted order, got %s, %s", rows[0].Name, rows[1].Name)
	}
	if rows[1].Limit != 2 {
		t.Errorf("expected limit 2 for pool b, got %d", rows[1].Limit)
	}
}

func TestIndexHandlerRendersPage(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	handler := indexHandler(registry, NewEventLog(10))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "db1") {
		t.Error("expected the page to mention the configured pool")
	}
	if !strings.Contains(body, "Live status") {
		t.Error("expected the tab bar in the rendered page")
	}
}

func TestSSEHandlerStreamsNamedEvents(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	srv := httptest.NewServer(sseHandler(registry, NewEventLog(10)))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %q", ct)
	}

	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	for _, want := range []string{"event: pools", "event: sessions", "event: events"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected stream to contain %q, got:\n%s", want, got)
		}
	}
}

func TestAddPoolHandler(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	handler := addPoolHandler(registry)

	form := url.Values{
		"name":         {"newpool"},
		"backend_dsn":  {"postgres://u:p@localhost:1/db"},
		"backend_addr": {"localhost:1"},
		"limit":        {"3"},
	}
	req := httptest.NewRequest(http.MethodPost, "/pools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "newpool") {
		t.Error("expected success response to mention the new pool")
	}
	p, ok := registry.Get("newpool")
	if !ok || p.Stats().Limit != 3 {
		t.Fatal("pool was not actually added to the registry")
	}
}

func TestAddPoolHandlerRejectsInvalidLimit(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	handler := addPoolHandler(registry)

	form := url.Values{"name": {"x"}, "backend_dsn": {"y"}, "backend_addr": {"z"}, "limit": {"not-a-number"}}
	req := httptest.NewRequest(http.MethodPost, "/pools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !strings.Contains(rec.Body.String(), "invalid limit") {
		t.Errorf("expected an invalid-limit error message, got: %s", rec.Body.String())
	}
	if _, ok := registry.Get("x"); ok {
		t.Error("pool must not be added when the form is invalid")
	}
}

func TestAddPoolHandlerRejectsDuplicateName(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"dup": dummyPoolConfig(1)}, NewEventLog(10))
	handler := addPoolHandler(registry)

	// backend_addr has to be a valid host:port or validateBackendAddr
	// rejects it first and this test stops testing duplicate names.
	form := url.Values{
		"name":         {"dup"},
		"backend_dsn":  {"postgres://u:p@db:5432/x"},
		"backend_addr": {"db:5432"},
		"limit":        {"1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/pools", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !strings.Contains(rec.Body.String(), "already exists") {
		t.Errorf("expected duplicate-name error, got: %s", rec.Body.String())
	}
}

func TestResizePoolHandler(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pools/{name}/resize", resizePoolHandler(registry))

	form := url.Values{"limit": {"7"}}
	req := httptest.NewRequest(http.MethodPost, "/pools/db1/resize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	p, _ := registry.Get("db1")
	// Give the background drain goroutine a moment; the resize itself is
	// synchronous, but we only assert on registry state, which is already
	// updated before resizePoolHandler even returns.
	if p.Stats().Limit != 7 {
		t.Errorf("expected new limit 7, got %d", p.Stats().Limit)
	}
}

func TestResizePoolHandlerUnknownPool(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pools/{name}/resize", resizePoolHandler(registry))

	form := url.Values{"limit": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/pools/nope/resize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("expected not-found error, got: %s", rec.Body.String())
	}
}

func TestRemovePoolHandler(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pools/{name}/remove", removePoolHandler(registry))

	req := httptest.NewRequest(http.MethodPost, "/pools/db1/remove", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := registry.Get("db1"); ok {
		t.Error("pool must be gone from the registry immediately")
	}
}

func TestRemovePoolHandlerUnknownPool(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	mux := http.NewServeMux()
	mux.HandleFunc("POST /pools/{name}/remove", removePoolHandler(registry))

	req := httptest.NewRequest(http.MethodPost, "/pools/nope/remove", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "not found") {
		t.Errorf("expected not-found error, got: %s", rec.Body.String())
	}
}

func TestCancelSessionHandler(t *testing.T) {
	addr, received := fakePostgresListener(t)
	pid, sess := registerSession("greg", "db")
	defer deregisterSession(pid)
	sess.setBackend(&backendConn{addr: addr, pid: 1, secretKey: secretBytes(1)})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions/{pid}/cancel", cancelSessionHandler)

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+strconv.FormatUint(uint64(pid), 10)+"/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the fake backend to receive a CancelRequest")
	}
}

func TestCancelSessionHandlerInvalidPID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions/{pid}/cancel", cancelSessionHandler)

	req := httptest.NewRequest(http.MethodPost, "/sessions/not-a-number/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a non-numeric pid, got %d", rec.Code)
	}
}

func TestCancelSessionHandlerUnknownPID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions/{pid}/cancel", cancelSessionHandler)

	req := httptest.NewRequest(http.MethodPost, "/sessions/999999999/cancel", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for an unknown pid, got %d", rec.Code)
	}
}

func TestReloadHandlerReportsDiff(t *testing.T) {
	path := writeConfig(t, `
allow_insecure_trust_auth: true
pools:
  onlyinfile:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 1
`)
	registry := NewPoolRegistry(map[string]PoolConfig{"onlyrunning": dummyPoolConfig(1)}, NewEventLog(10))
	handler := reloadHandler(path, registry)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "onlyinfile") {
		t.Error("expected diff to mention the pool present only in the file")
	}
	if !strings.Contains(body, "onlyrunning") {
		t.Error("expected diff to mention the pool present only in the running registry")
	}
}

func TestReloadHandlerInvalidConfig(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	handler := reloadHandler("/does/not/exist.yaml", registry)

	req := httptest.NewRequest(http.MethodPost, "/reload", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if !strings.Contains(rec.Body.String(), "invalid") {
		t.Errorf("expected an invalid-config message, got: %s", rec.Body.String())
	}
}
