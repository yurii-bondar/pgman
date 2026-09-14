package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yurii-bondar/pgman/pool"
)

func decodeHealth(t *testing.T, rec *httptest.ResponseRecorder) healthResponse {
	t.Helper()
	var body healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestHealthStaysOKWhileDraining is the whole reason liveness and
// readiness are separate handlers. A failing liveness probe means
// "restart this container", and restarting a proxy that is deliberately
// draining turns a clean rolling deploy into dropped transactions.
func TestHealthStaysOKWhileDraining(t *testing.T) {
	h := healthHandler()

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := decodeHealth(t, rec).Status; got != "ok" {
		t.Errorf("status = %q, want ok", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store: a cached probe response "+
			"would keep reporting healthy after the fact", got)
	}
}

// TestReadyTurnsUnreadyWhileDraining covers the case that matters on
// every single deploy: readiness must flip *before* the listener closes,
// so the Service stops sending new connections to a pod that is on its
// way out.
func TestReadyTurnsUnreadyWhileDraining(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	var draining atomic.Bool
	h := readyHandler(registry, &draining)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status before drain = %d, want 200", rec.Code)
	}

	draining.Store(true)

	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status while draining = %d, want 503", rec.Code)
	}
	body := decodeHealth(t, rec)
	if body.Status != "draining" || !body.Draining {
		t.Errorf("body = %+v, want status=draining", body)
	}
}

// TestReadyReportsPerPoolDetail: a probe endpoint that only explains
// itself on failure is useless during the incident that follows.
func TestReadyReportsPerPoolDetail(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"db1": dummyPoolConfig(2),
		"db2": dummyPoolConfig(3),
	}, NewEventLog(10))
	var draining atomic.Bool

	rec := httptest.NewRecorder()
	readyHandler(registry, &draining)(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	body := decodeHealth(t, rec)
	if len(body.Pools) != 2 {
		t.Fatalf("got %d pools in the response, want 2", len(body.Pools))
	}
	// Names() sorts, so the order is stable and worth asserting.
	if body.Pools[0].Name != "db1" || body.Pools[1].Name != "db2" {
		t.Errorf("pool names = %q/%q, want db1/db2 in sorted order",
			body.Pools[0].Name, body.Pools[1].Name)
	}
}

// unreachableRegistry builds a registry whose pools can never dial, with
// a breaker that trips on the first failure.
func unreachableRegistry(t *testing.T, names ...string) *PoolRegistry {
	t.Helper()
	registry := NewPoolRegistry(nil, NewEventLog(10))
	for _, name := range names {
		p := pool.New(
			func(context.Context) (net.Conn, error) { return nil, errors.New("refused") },
			2, nil, nil, pool.WithCircuitBreaker(1, time.Hour))
		// Trip it.
		if _, err := p.Acquire(context.Background()); err == nil {
			t.Fatalf("%s: expected the dial to fail", name)
		}
		if !p.CircuitOpen() {
			t.Fatalf("%s: breaker did not open", name)
		}
		registry.mu.Lock()
		registry.entries[name] = &registryEntry{config: dummyPoolConfig(2), pool: p, dnsStop: func() {}}
		registry.mu.Unlock()
	}
	return registry
}

// TestReadyUnreadyOnlyWhenEveryBackendIsGone pins a deliberate policy
// choice, which is exactly the kind of decision worth a test.
//
// One degraded backend affects every replica identically, so failing
// readiness there would pull the whole deployment out of rotation and
// turn a partial outage into a total one. Only total backend loss —
// which can genuinely be local to one instance — makes this pod worth
// removing.
func TestReadyUnreadyOnlyWhenEveryBackendIsGone(t *testing.T) {
	var draining atomic.Bool

	t.Run("one of two pools down stays ready", func(t *testing.T) {
		registry := unreachableRegistry(t, "broken")
		// A second, healthy pool.
		registry.mu.Lock()
		registry.entries["healthy"] = &registryEntry{
			config:  dummyPoolConfig(2),
			pool:    pool.New(func(context.Context) (net.Conn, error) { return nil, errors.New("unused") }, 2, nil, nil),
			dnsStop: func() {},
		}
		registry.mu.Unlock()

		rec := httptest.NewRecorder()
		readyHandler(registry, &draining)(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: one broken backend must not remove the "+
				"instance from rotation", rec.Code)
		}
	})

	t.Run("every pool down is unready", func(t *testing.T) {
		registry := unreachableRegistry(t, "a", "b")

		rec := httptest.NewRecorder()
		readyHandler(registry, &draining)(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503 when no backend is reachable at all", rec.Code)
		}
		body := decodeHealth(t, rec)
		if body.Status != "unready" {
			t.Errorf("status = %q, want unready", body.Status)
		}
		for _, p := range body.Pools {
			if !p.CircuitOpen {
				t.Errorf("pool %s should report circuit_open", p.Name)
			}
		}
	})
}

// TestReadyWithNoPoolsIsReady: zero pools is a misconfiguration, not a
// backend outage. Reporting unready would leave the operator staring at
// a pod that never becomes ready instead of at the config error in the
// logs.
func TestReadyWithNoPoolsIsReady(t *testing.T) {
	var draining atomic.Bool
	rec := httptest.NewRecorder()
	readyHandler(NewPoolRegistry(nil, NewEventLog(10)), &draining)(
		rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
