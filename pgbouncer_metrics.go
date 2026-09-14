// Package main — pgbouncer_exporter-compatible metric surface.
//
// The community Grafana dashboards (grafana.com/dashboards/… "PgBouncer
// Overview", "PgBouncer Database Detail") pivot off the metric names
// exported by prometheus-community/pgbouncer_exporter. Adopting those
// names as an alias layer lets operators drop pgman into an existing
// dashboard/alerting stack without rewriting a single panel.
//
// This collector is a THIN alias: it reads the same underlying state
// (pool.Stats, session registry) that the native pgman_pool_*
// metrics do, then re-emits it under pgbouncer_* names with pgbouncer-
// style labels. No new state, no scrape-time race with the native
// collector.
//
// Names mirrored (subset, focused on the "SHOW POOLS" + "SHOW STATS"
// panels that every dashboard uses):
//
//	pgbouncer_pools_server_active_connections{database}   // = in-use
//	pgbouncer_pools_server_idle_connections{database}     // = idle
//	pgbouncer_pools_client_waiting_connections{database}  // = waiting
//	pgbouncer_databases_pool_size{database}               // = limit
//	pgbouncer_databases_current_connections{database}     // = in-use + idle
//	pgbouncer_stats_queries_pooled_total{database}        // = wait_count
package main

import "github.com/prometheus/client_golang/prometheus"

// pgbouncerCollector re-exports pool stats under PgBouncer names.
type pgbouncerCollector struct {
	registry *PoolRegistry

	serverActive       *prometheus.Desc
	serverIdle         *prometheus.Desc
	clientWaiting      *prometheus.Desc
	poolSize           *prometheus.Desc
	currentConns       *prometheus.Desc
	queriesPooledTotal *prometheus.Desc
}

func newPgbouncerCollector(registry *PoolRegistry) *pgbouncerCollector {
	dbLabel := []string{"database"}
	return &pgbouncerCollector{
		registry: registry,
		serverActive: prometheus.NewDesc(
			"pgbouncer_pools_server_active_connections",
			"Backend connections currently in use (PgBouncer parity).",
			dbLabel, nil),
		serverIdle: prometheus.NewDesc(
			"pgbouncer_pools_server_idle_connections",
			"Backend connections currently idle in the pool (PgBouncer parity).",
			dbLabel, nil),
		clientWaiting: prometheus.NewDesc(
			"pgbouncer_pools_client_waiting_connections",
			"Client sessions parked in Acquire waiting for a backend slot (PgBouncer parity).",
			dbLabel, nil),
		poolSize: prometheus.NewDesc(
			"pgbouncer_databases_pool_size",
			"Configured pool size (max backend connections) — PgBouncer parity.",
			dbLabel, nil),
		currentConns: prometheus.NewDesc(
			"pgbouncer_databases_current_connections",
			"Total backend connections currently open (in_use + idle) — PgBouncer parity.",
			dbLabel, nil),
		queriesPooledTotal: prometheus.NewDesc(
			"pgbouncer_stats_queries_pooled_total",
			"Total pooled queries served (approximated as Acquire count) — PgBouncer parity.",
			dbLabel, nil),
	}
}

func (c *pgbouncerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serverActive
	ch <- c.serverIdle
	ch <- c.clientWaiting
	ch <- c.poolSize
	ch <- c.currentConns
	ch <- c.queriesPooledTotal
}

func (c *pgbouncerCollector) Collect(ch chan<- prometheus.Metric) {
	for name, p := range c.registry.Pools() {
		s := p.Stats()
		ch <- prometheus.MustNewConstMetric(c.serverActive, prometheus.GaugeValue, float64(s.InUse), name)
		ch <- prometheus.MustNewConstMetric(c.serverIdle, prometheus.GaugeValue, float64(s.Idle), name)
		ch <- prometheus.MustNewConstMetric(c.clientWaiting, prometheus.GaugeValue, float64(s.Waiting), name)
		ch <- prometheus.MustNewConstMetric(c.poolSize, prometheus.GaugeValue, float64(s.Limit), name)
		ch <- prometheus.MustNewConstMetric(c.currentConns, prometheus.GaugeValue, float64(s.InUse+s.Idle), name)
		ch <- prometheus.MustNewConstMetric(c.queriesPooledTotal, prometheus.CounterValue, float64(s.WaitCount), name)
	}
}
