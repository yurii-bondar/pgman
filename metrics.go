package main

import (
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// poolsCollector adapts every configured pool's Stats() to Prometheus,
// one series per pool distinguished by the "pool" label. Single
// Collector for all pools — the registry rejects two Collector
// instances that Describe the same metric name+label set, since at
// registration time it can't yet know their label *values* will differ.
type poolsCollector struct {
	registry *PoolRegistry

	limit           *prometheus.Desc
	inUse           *prometheus.Desc
	idle            *prometheus.Desc
	waiting         *prometheus.Desc
	acquireTotal    *prometheus.Desc
	acquireSeconds  *prometheus.Desc
	discardsTotal   *prometheus.Desc
	dialErrorsTotal *prometheus.Desc
	reapedTotal     *prometheus.Desc
	circuitOpen     *prometheus.Desc
}

func newPoolsCollector(registry *PoolRegistry) *poolsCollector {
	labels := []string{"pool"}
	return &poolsCollector{
		registry: registry,
		limit: prometheus.NewDesc(
			"pgman_pool_limit", "Configured maximum outstanding backend connections.", labels, nil),
		inUse: prometheus.NewDesc(
			"pgman_pool_in_use", "Backend connections currently acquired by a session.", labels, nil),
		idle: prometheus.NewDesc(
			"pgman_pool_idle", "Backend connections currently idle, ready for reuse.", labels, nil),
		waiting: prometheus.NewDesc(
			"pgman_pool_waiting", "Goroutines currently parked in Acquire waiting for a slot.", labels, nil),
		acquireTotal: prometheus.NewDesc(
			"pgman_pool_acquire_total", "Total Acquire calls.", labels, nil),
		acquireSeconds: prometheus.NewDesc(
			"pgman_pool_acquire_seconds_total", "Cumulative time spent inside Acquire (slot wait + health-check + dial).", labels, nil),
		discardsTotal: prometheus.NewDesc(
			"pgman_pool_discards_total", "Connections discarded as unhealthy or broken.", labels, nil),
		dialErrorsTotal: prometheus.NewDesc(
			"pgman_pool_dial_errors_total", "Failed dials to the real backend.", labels, nil),
		reapedTotal: prometheus.NewDesc(
			"pgman_pool_reaped_total", "Connections closed by the idle/lifetime reaper.", labels, nil),
		circuitOpen: prometheus.NewDesc(
			"pgman_pool_circuit_open", "1 while the pool's circuit breaker is rejecting dials, 0 otherwise.", labels, nil),
	}
}

func (c *poolsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.limit
	ch <- c.inUse
	ch <- c.idle
	ch <- c.waiting
	ch <- c.acquireTotal
	ch <- c.acquireSeconds
	ch <- c.discardsTotal
	ch <- c.dialErrorsTotal
	ch <- c.reapedTotal
	ch <- c.circuitOpen
}

func (c *poolsCollector) Collect(ch chan<- prometheus.Metric) {
	for name, p := range c.registry.Pools() {
		s := p.Stats()
		ch <- prometheus.MustNewConstMetric(c.limit, prometheus.GaugeValue, float64(s.Limit), name)
		ch <- prometheus.MustNewConstMetric(c.inUse, prometheus.GaugeValue, float64(s.InUse), name)
		ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.Idle), name)
		ch <- prometheus.MustNewConstMetric(c.waiting, prometheus.GaugeValue, float64(s.Waiting), name)
		ch <- prometheus.MustNewConstMetric(c.acquireTotal, prometheus.CounterValue, float64(s.WaitCount), name)
		ch <- prometheus.MustNewConstMetric(c.acquireSeconds, prometheus.CounterValue, s.WaitTime.Seconds(), name)
		ch <- prometheus.MustNewConstMetric(c.discardsTotal, prometheus.CounterValue, float64(s.Discards), name)
		ch <- prometheus.MustNewConstMetric(c.dialErrorsTotal, prometheus.CounterValue, float64(s.DialErrors), name)
		ch <- prometheus.MustNewConstMetric(c.reapedTotal, prometheus.CounterValue, float64(s.Reaped), name)
		circuit := 0.0
		if s.CircuitOpen {
			circuit = 1
		}
		ch <- prometheus.MustNewConstMetric(c.circuitOpen, prometheus.GaugeValue, circuit, name)
	}
}

// proxyMetrics is the non-pool metric set — client connection counts,
// login failures, acquire wait-time histogram (for p50/p95/p99). Kept
// separate from poolsCollector because these are pushed by hot-path code
// paths, not pulled per-scrape.
type proxyMetrics struct {
	AcquireWait      *prometheus.HistogramVec
	QueryDuration    *prometheus.HistogramVec
	ClientConnActive prometheus.Gauge
	ClientConnTotal  prometheus.Counter
	ClientLoginFail  *prometheus.CounterVec
	ClientLoginOK    prometheus.Counter
	MaxConnRejected  prometheus.Counter

	// The three mechanisms below act on their own, without a client or
	// an operator asking. Each was observable only as a log line, which
	// is the wrong shape for the question they raise: not "did it
	// happen" but "how often", against a graph of something else that
	// changed at the same time.
	PreparedStmtEvictions *prometheus.CounterVec
	PassthroughEvictions  prometheus.Counter
	ConfigReloads         *prometheus.CounterVec
	ConfigReloadPools     *prometheus.CounterVec
}

func newProxyMetrics(reg prometheus.Registerer) *proxyMetrics {
	m := &proxyMetrics{
		AcquireWait: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pgman_pool_acquire_wait_seconds",
			Help: "Histogram of Acquire wait time (slot wait + healthcheck + dial), labelled by pool.",
			// Buckets chosen for typical proxy latency: sub-ms fast
			// path all the way to a query_wait_timeout-ish tail.
			Buckets: []float64{
				0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05,
				0.1, 0.5, 1, 5, 10, 30, 120,
			},
		}, []string{"pool"}),
		QueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "pgman_query_duration_seconds",
			Help: "Histogram of query round-trip time through the proxy: from " +
				"forwarding the terminal message (Query/Sync) to the backend " +
				"until its ReadyForQuery arrives. Labelled by pool.",
			// Wider at the bottom than AcquireWait — a pooled query is
			// dominated by real backend work, so sub-100µs buckets are
			// wasted resolution while the p99 tail is what matters.
			Buckets: []float64{
				0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
				0.25, 0.5, 1, 2.5, 5, 10, 30, 60,
			},
		}, []string{"pool"}),
		ClientConnActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "pgman_client_conn_active",
			Help: "Number of client connections currently held by the proxy.",
		}),
		ClientConnTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pgman_client_conn_total",
			Help: "Total client connections accepted (regardless of outcome).",
		}),
		ClientLoginFail: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgman_client_login_failures_total",
			Help: "Total client startup/auth failures, labelled by reason.",
		}, []string{"reason"}),
		ClientLoginOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pgman_client_login_ok_total",
			Help: "Total successful client logins.",
		}),
		MaxConnRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pgman_max_client_conn_rejected_total",
			Help: "Total client connections rejected because max_client_conn was reached.",
		}),
		// A rising rate here is the signal that max_prepared_statements
		// is below what the workload actually uses: every eviction costs
		// the next Bind an extra Parse round trip, which shows up as
		// latency nobody can otherwise explain.
		PreparedStmtEvictions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgman_prepared_stmt_evictions_total",
			Help: "Named prepared statements closed on a backend to stay within max_prepared_statements, by pool.",
		}, []string{"pool"}),
		PassthroughEvictions: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "pgman_passthrough_pools_evicted_total",
			Help: "SCRAM pass-through pools closed after scram_passthrough_idle_timeout.",
		}),
		// Labelled by outcome rather than counted separately, so an
		// alert can be written on the ratio: a configmap that keeps
		// failing to parse is invisible otherwise, since the proxy goes
		// on serving the last good configuration.
		ConfigReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgman_config_reloads_total",
			Help: "Config reloads attempted, by result (applied / failed).",
		}, []string{"result"}),
		ConfigReloadPools: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "pgman_config_reload_pools_total",
			Help: "Pools affected by config reloads, by action (added / removed / reconfigured).",
		}, []string{"action"}),
	}
	reg.MustRegister(m.AcquireWait, m.QueryDuration, m.ClientConnActive, m.ClientConnTotal, m.ClientLoginFail, m.ClientLoginOK, m.MaxConnRejected)
	reg.MustRegister(m.PreparedStmtEvictions, m.PassthroughEvictions, m.ConfigReloads, m.ConfigReloadPools)
	reg.MustRegister(newBuildInfoCollector())
	return m
}

// newBuildInfoCollector exports the release this process was built from,
// as the constant-1 gauge with everything in labels that Prometheus
// projects use for the purpose (node_exporter, and Go's own
// promhttp/collectors, all spell it this way).
//
// It matters more than it looks: images are published automatically and
// tagged `latest` alongside their version, so "which build is that pod
// running" is otherwise answered by digging out a digest and mapping it
// back to a tag by hand. With this, a dashboard can annotate a latency
// change with the version it started at.
func newBuildInfoCollector() prometheus.Collector {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pgman_build_info",
		Help: "Build information. Always 1; the labels are the payload.",
	}, []string{"version", "go_version"})
	g.WithLabelValues(version, runtime.Version()).Set(1)
	return g
}

// observeQuery records one completed query round-trip. Safe on a nil
// *proxyMetrics so the hot path doesn't need a guard at every call site
// (tests build runtimeOpts without metrics).
func (m *proxyMetrics) observeQuery(pool string, d time.Duration) {
	if m == nil {
		return
	}
	m.QueryDuration.WithLabelValues(pool).Observe(d.Seconds())
}

// observePreparedStmtEviction counts one statement closed on a backend
// to stay within the cap. Nil-safe like observeQuery: the relay reaches
// it from a session, and tests build sessions without metrics.
func (m *proxyMetrics) observePreparedStmtEviction(pool string) {
	if m == nil {
		return
	}
	m.PreparedStmtEvictions.WithLabelValues(pool).Inc()
}

// observePassthroughEvictions counts pools the reaper reclaimed.
func (m *proxyMetrics) observePassthroughEvictions(n int) {
	if m == nil || n == 0 {
		return
	}
	m.PassthroughEvictions.Add(float64(n))
}

// observeConfigReload records one reload and what it did. A failed
// reload reports no pool actions, because it applied none: the proxy
// keeps serving the configuration it already had.
func (m *proxyMetrics) observeConfigReload(result ReloadResult, err error) {
	if m == nil {
		return
	}
	if err != nil {
		m.ConfigReloads.WithLabelValues("failed").Inc()
		return
	}
	m.ConfigReloads.WithLabelValues("applied").Inc()
	for action, names := range map[string][]string{
		"added":        result.Added,
		"removed":      result.Removed,
		"reconfigured": result.Reconfigured,
	} {
		if len(names) > 0 {
			m.ConfigReloadPools.WithLabelValues(action).Add(float64(len(names)))
		}
	}
}

// observeAcquire returns a pool.ObserveWaitFunc bound to a pool name —
// pool package emits the timings, this side attributes them to the
// right series.
func (m *proxyMetrics) observeAcquire(pool string) func(time.Duration) {
	obs := m.AcquireWait.WithLabelValues(pool)
	return func(d time.Duration) { obs.Observe(d.Seconds()) }
}
