package main

import (
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// This collector is a compatibility contract, not an internal detail:
// its whole purpose is that community PgBouncer dashboards and alert
// rules keep working against pgman without a panel being rewritten.
// Which means a rename, a dropped series or a changed label is a
// breaking change for people outside this repository — and until this
// file existed, nothing would have failed if one happened.

// gatherByName collects everything the registry holds and indexes the
// metric families by name.
func gatherByName(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		out[f.GetName()] = f
	}
	return out
}

// pgbouncerFixture registers the compat collector over one pool with a
// known limit. Nothing dials, so the stats are the ones a freshly
// created pool reports.
func pgbouncerFixture(t *testing.T, limit int) *prometheus.Registry {
	t.Helper()
	registry := NewPoolRegistry(map[string]PoolConfig{"shop": dummyPoolConfig(limit)}, NewEventLog(10))
	reg := prometheus.NewRegistry()
	reg.MustRegister(newPgbouncerCollector(registry))
	return reg
}

// TestPgbouncerCompatMetricNames pins the exact series names. The list
// is not "whatever the code emits today" — it is what
// prometheus-community/pgbouncer_exporter calls these numbers, which is
// what the dashboards query for.
func TestPgbouncerCompatMetricNames(t *testing.T) {
	want := []string{
		"pgbouncer_databases_current_connections",
		"pgbouncer_databases_pool_size",
		"pgbouncer_pools_client_waiting_connections",
		"pgbouncer_pools_server_active_connections",
		"pgbouncer_pools_server_idle_connections",
		"pgbouncer_stats_queries_pooled_total",
	}

	families := gatherByName(t, pgbouncerFixture(t, 7))
	got := make([]string, 0, len(families))
	for name := range families {
		got = append(got, name)
	}
	sort.Strings(got)

	if len(got) != len(want) {
		t.Fatalf("exported series:\n  got  %v\n  want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("series %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPgbouncerCompatLabelsAndTypes: dashboards group by `database` and
// alerting rules apply rate() to the counter. A gauge published where a
// counter is expected produces a panel that silently reads zero.
func TestPgbouncerCompatLabelsAndTypes(t *testing.T) {
	families := gatherByName(t, pgbouncerFixture(t, 7))

	wantType := map[string]dto.MetricType{
		"pgbouncer_databases_current_connections":    dto.MetricType_GAUGE,
		"pgbouncer_databases_pool_size":              dto.MetricType_GAUGE,
		"pgbouncer_pools_client_waiting_connections": dto.MetricType_GAUGE,
		"pgbouncer_pools_server_active_connections":  dto.MetricType_GAUGE,
		"pgbouncer_pools_server_idle_connections":    dto.MetricType_GAUGE,
		"pgbouncer_stats_queries_pooled_total":       dto.MetricType_COUNTER,
	}

	for name, want := range wantType {
		f, ok := families[name]
		if !ok {
			t.Errorf("%s is not exported", name)
			continue
		}
		if f.GetType() != want {
			t.Errorf("%s is a %s, want %s", name, f.GetType(), want)
		}
		for _, m := range f.GetMetric() {
			labels := m.GetLabel()
			if len(labels) != 1 || labels[0].GetName() != "database" {
				t.Errorf("%s labels = %v, want exactly one label named database", name, labels)
				continue
			}
			// The pool's registry key, which is what every other pgman
			// series is labelled by too — a dashboard joining the two
			// sets needs them to agree.
			if labels[0].GetValue() != "shop" {
				t.Errorf("%s database label = %q, want the pool key %q",
					name, labels[0].GetValue(), "shop")
			}
		}
	}
}

// TestPgbouncerCompatValuesTrackPoolStats: the collector must be a thin
// alias over pool.Stats, so if it ever starts keeping state of its own,
// the two metric surfaces can disagree — and an operator comparing the
// pgman_* and pgbouncer_* panels would have no way to tell which lies.
func TestPgbouncerCompatValuesTrackPoolStats(t *testing.T) {
	const limit = 7
	families := gatherByName(t, pgbouncerFixture(t, limit))

	value := func(name string) float64 {
		t.Helper()
		f, ok := families[name]
		if !ok || len(f.GetMetric()) == 0 {
			t.Fatalf("%s was not exported", name)
		}
		m := f.GetMetric()[0]
		if g := m.GetGauge(); g != nil {
			return g.GetValue()
		}
		return m.GetCounter().GetValue()
	}

	if got := value("pgbouncer_databases_pool_size"); got != limit {
		t.Errorf("pool_size = %v, want the configured limit %d", got, limit)
	}
	// A pool that has never been acquired from holds no connections, so
	// everything derived from live state has to read zero rather than,
	// say, the limit.
	for _, name := range []string{
		"pgbouncer_pools_server_active_connections",
		"pgbouncer_pools_server_idle_connections",
		"pgbouncer_pools_client_waiting_connections",
		"pgbouncer_databases_current_connections",
		"pgbouncer_stats_queries_pooled_total",
	} {
		if got := value(name); got != 0 {
			t.Errorf("%s = %v on an untouched pool, want 0", name, got)
		}
	}
}

// TestPgbouncerCompatDescribeMatchesCollect: a Collector whose Describe
// omits a Desc it later emits is rejected at registration time in
// strict mode and, worse, can collide with another collector's series.
func TestPgbouncerCompatDescribeMatchesCollect(t *testing.T) {
	c := newPgbouncerCollector(NewPoolRegistry(
		map[string]PoolConfig{"shop": dummyPoolConfig(2)}, NewEventLog(10)))

	descs := make(chan *prometheus.Desc, 16)
	c.Describe(descs)
	close(descs)
	described := 0
	for range descs {
		described++
	}

	metrics := make(chan prometheus.Metric, 32)
	c.Collect(metrics)
	close(metrics)
	collected := 0
	for range metrics {
		collected++
	}

	if described != collected {
		t.Errorf("Describe announced %d series but Collect emitted %d for one pool",
			described, collected)
	}
}
