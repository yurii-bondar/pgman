package main

import (
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
)

// poolCollectorMetricCount is how many series poolsCollector emits per
// pool. Named rather than repeated as a literal so adding a metric is a
// one-line test change that still fails loudly if Describe and Collect
// disagree — which is the bug these three tests actually guard against.
const poolCollectorMetricCount = 10

func TestPoolsCollectorDescribeCount(t *testing.T) {
	c := newPoolsCollector(NewPoolRegistry(nil, NewEventLog(10)))
	ch := make(chan *prometheus.Desc, 100)
	c.Describe(ch)
	close(ch)

	n := 0
	for range ch {
		n++
	}
	if n != poolCollectorMetricCount {
		t.Fatalf("expected %d metric descriptors, got %d", poolCollectorMetricCount, n)
	}
}

func TestPoolsCollectorCollectPerPool(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"backoffice": dummyPoolConfig(2),
		"game_rgs":   dummyPoolConfig(3),
	}, NewEventLog(10))
	c := newPoolsCollector(registry)

	ch := make(chan prometheus.Metric, 100)
	c.Collect(ch)
	close(ch)

	seen := map[string]map[string]float64{} // pool -> metric name -> value
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		var pool string
		for _, lp := range pb.GetLabel() {
			if lp.GetName() == "pool" {
				pool = lp.GetValue()
			}
		}
		if pool == "" {
			t.Fatal("every metric must carry a non-empty 'pool' label")
		}
		name := m.Desc().String()
		if seen[pool] == nil {
			seen[pool] = map[string]float64{}
		}
		var val float64
		if pb.Gauge != nil {
			val = pb.GetGauge().GetValue()
		} else if pb.Counter != nil {
			val = pb.GetCounter().GetValue()
		}
		seen[pool][name] = val
	}

	if len(seen) != 2 {
		t.Fatalf("expected metrics for 2 pools, got %d: %v", len(seen), seen)
	}
	if len(seen["backoffice"]) != poolCollectorMetricCount {
		t.Errorf("expected %d metrics for backoffice, got %d", poolCollectorMetricCount, len(seen["backoffice"]))
	}
}

func TestPoolsCollectorRegistersCleanly(t *testing.T) {
	// The real regression this guards: registering N pools must use ONE
	// collector for all of them, not one per pool — see poolsCollector's
	// own doc comment for why (duplicate Desc registration panics).
	registry := NewPoolRegistry(map[string]PoolConfig{
		"a": dummyPoolConfig(1),
		"b": dummyPoolConfig(1),
		"c": dummyPoolConfig(1),
	}, NewEventLog(10))

	promRegistry := prometheus.NewRegistry()
	if err := promRegistry.Register(newPoolsCollector(registry)); err != nil {
		t.Fatalf("register: %v", err)
	}

	families, err := promRegistry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(families) != poolCollectorMetricCount {
		t.Fatalf("expected %d metric families, got %d", poolCollectorMetricCount, len(families))
	}
	for _, f := range families {
		if len(f.GetMetric()) != 3 {
			t.Errorf("metric %s: expected 3 series (one per pool), got %d", f.GetName(), len(f.GetMetric()))
		}
	}
}
