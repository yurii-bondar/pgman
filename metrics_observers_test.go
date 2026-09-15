package main

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/prometheus/client_golang/prometheus"
)

// Three mechanisms act on their own, with no client or operator asking:
// the prepared-statement cap closes statements on a backend, the reaper
// closes idle pass-through pools, and SIGHUP applies a config file. Each
// was observable only as a log line, which answers "did it happen" and
// not the question an operator actually has — how often, next to a graph
// of the thing that changed at the same time.

// counterValue reads one labelled counter out of a registry, failing the
// test when the series is absent: a metric that is never emitted looks
// identical to one that is zero on a dashboard, and only one of those is
// a bug.
func counterValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families := gatherByName(t, reg)
	f, ok := families[name]
	if !ok {
		t.Fatalf("%s was never emitted", name)
	}
	for _, m := range f.GetMetric() {
		matches := true
		for _, l := range m.GetLabel() {
			if want, ok := labels[l.GetName()]; ok && want != l.GetValue() {
				matches = false
			}
		}
		if matches {
			return m.GetCounter().GetValue()
		}
	}
	t.Fatalf("%s has no series with labels %v", name, labels)
	return 0
}

// TestPreparedStmtEvictionsAreCounted: a rising rate here is the signal
// that max_prepared_statements is below what the workload uses, and every
// eviction costs the next Bind an extra Parse round trip — latency that
// is otherwise unattributable.
func TestPreparedStmtEvictionsAreCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := newProxyMetrics(reg)

	f := newPSFixture(t)
	f.sess.psLimit = 1
	f.sess.poolName = "shop"
	f.sess.metrics = metrics

	f.process(&pgproto3.Parse{Name: "first", Query: "SELECT 1"})
	f.process(&pgproto3.Parse{Name: "second", Query: "SELECT 2"}) // evicts "first"

	if got := counterValue(t, reg, "pgman_prepared_stmt_evictions_total", map[string]string{"pool": "shop"}); got != 1 {
		t.Errorf("evictions = %v, want 1", got)
	}
}

// TestPreparedStmtEvictionsSurviveASessionWithoutMetrics keeps the hot
// path safe for the sessions tests build by hand: the counter is reached
// through the session, and a nil metric set must not be a panic inside a
// relay.
func TestPreparedStmtEvictionsSurviveASessionWithoutMetrics(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psLimit = 1
	f.sess.metrics = nil

	f.process(&pgproto3.Parse{Name: "first", Query: "SELECT 1"})
	f.process(&pgproto3.Parse{Name: "second", Query: "SELECT 2"})
}

// TestPassthroughEvictionsAreCounted: these pools appear on demand and
// are reclaimed in the background, so the count is the only way to tell
// a deployment whose roles churn from one whose pools are being closed
// and rebuilt under steady traffic.
func TestPassthroughEvictionsAreCounted(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := newProxyMetrics(reg)

	r := passthroughRegistry(t, "alice")
	idle(t, r, "db/alice", time.Hour)
	reapPassthroughPools(r, 30*time.Minute, metrics)

	if got := counterValue(t, reg, "pgman_passthrough_pools_evicted_total", nil); got != 1 {
		t.Errorf("evicted = %v, want 1", got)
	}
}

// TestConfigReloadsAreCountedByOutcome: a configmap that keeps failing to
// parse is invisible otherwise — the proxy goes on serving the last good
// configuration, which is the right behaviour and also the reason nobody
// notices for a week.
func TestConfigReloadsAreCountedByOutcome(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := newProxyMetrics(reg)

	metrics.observeConfigReload(ReloadResult{
		Added:        []string{"analytics"},
		Removed:      []string{"legacy"},
		Reconfigured: []string{"shop", "reports"},
		Unchanged:    []string{"billing"},
	}, nil)
	metrics.observeConfigReload(ReloadResult{}, errors.New("yaml: line 4: could not find expected ':'"))

	if got := counterValue(t, reg, "pgman_config_reloads_total", map[string]string{"result": "applied"}); got != 1 {
		t.Errorf("applied = %v, want 1", got)
	}
	if got := counterValue(t, reg, "pgman_config_reloads_total", map[string]string{"result": "failed"}); got != 1 {
		t.Errorf("failed = %v, want 1", got)
	}

	for action, want := range map[string]float64{"added": 1, "removed": 1, "reconfigured": 2} {
		if got := counterValue(t, reg, "pgman_config_reload_pools_total", map[string]string{"action": action}); got != want {
			t.Errorf("%s = %v, want %v", action, got, want)
		}
	}

	// Unchanged pools are deliberately not counted: they are the normal
	// case, and counting them would bury the actions that matter.
	families := gatherByName(t, reg)
	for _, m := range families["pgman_config_reload_pools_total"].GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetValue() == "unchanged" {
				t.Error("unchanged pools were counted as a reload action")
			}
		}
	}
}

// TestShowPoolsCountsClients: cl_active used to be hardcoded to zero, so
// every PgBouncer dashboard built on that column showed a proxy with no
// clients on it — which is the first number somebody checks when deciding
// whether traffic is reaching the right place.
func TestShowPoolsCountsClients(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"shop":    dummyPoolConfig(2),
		"reports": dummyPoolConfig(2),
	}, NewEventLog(10))

	// Two sessions on one pool, none on the other.
	for i := 0; i < 2; i++ {
		pid, sess := registerSession("alice", "shop")
		sess.poolName = "shop"
		t.Cleanup(func() { deregisterSession(pid) })
	}

	const clActiveColumn = 1 // database, cl_active, cl_waiting, ...
	rows := rowsByName(adminExchange(t, registry, "SHOW POOLS"))

	if got := string(rows["shop"][clActiveColumn]); got != "2" {
		t.Errorf("shop cl_active = %s, want 2", got)
	}
	if got := string(rows["reports"][clActiveColumn]); got != "0" {
		t.Errorf("reports cl_active = %s, want 0 — no session was routed there", got)
	}
}

// TestShowPoolsCountsSessionsHoldingNoBackend: a session between
// transactions holds no backend connection but is very much a connected
// client, and it is the one an operator is looking for when in_use reads
// low and the application insists it is busy.
func TestShowPoolsCountsSessionsHoldingNoBackend(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"shop": dummyPoolConfig(2)}, NewEventLog(10))

	pid, sess := registerSession("alice", "shop")
	sess.poolName = "shop"
	t.Cleanup(func() { deregisterSession(pid) })
	// A freshly registered session holds nothing: setBackend has not run,
	// which is exactly the state between two transactions.

	rows := rowsByName(adminExchange(t, registry, "SHOW POOLS"))
	if got := string(rows["shop"][1]); got != "1" {
		t.Errorf("cl_active = %s, want 1: a session between transactions is still a client", got)
	}
	// And the pool itself reports nothing in use, which is the pair of
	// numbers that tells the operator where the time is going.
	const svActiveColumn = 3
	if got := string(rows["shop"][svActiveColumn]); got != "0" {
		t.Errorf("sv_active = %s, want 0", got)
	}
}

// TestCancelDialTimeoutIsConfigurable: the cancel path is a side channel
// — the session it belongs to is busy running the query being cancelled —
// so the goroutine delivering it has nothing else bounding it. It was a
// hardcoded constant with a comment saying it should be a setting.
func TestCancelDialTimeoutIsConfigurable(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()
	if cfg.CancelDialTimeout != defaultCancelDialTimeout {
		t.Errorf("default = %v, want %v", cfg.CancelDialTimeout, defaultCancelDialTimeout)
	}

	explicit := Config{CancelDialTimeout: 250 * time.Millisecond}
	explicit.applyDefaults()
	if explicit.CancelDialTimeout != 250*time.Millisecond {
		t.Errorf("an explicit value became %v", explicit.CancelDialTimeout)
	}
}
