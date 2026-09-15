package main

import (
	"runtime"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestBuildInfoMetricCarriesTheVersion: images are published
// automatically and tagged `latest` next to their version, so without
// this series "which build is that pod running" is answered by digging
// out a digest and mapping it back to a tag by hand.
func TestBuildInfoMetricCarriesTheVersion(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(newBuildInfoCollector())

	// The value is meaningless by design — the labels are the payload —
	// so the assertion is on the labels being the real ones.
	var found bool
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "pgman_build_info" {
			continue
		}
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["version"] != version {
				t.Errorf("version label = %q, want %q", labels["version"], version)
			}
			if labels["go_version"] != runtime.Version() {
				t.Errorf("go_version label = %q, want %q", labels["go_version"], runtime.Version())
			}
			if m.GetGauge().GetValue() != 1 {
				t.Errorf("value = %v, want 1", m.GetGauge().GetValue())
			}
			found = true
		}
	}
	if !found {
		t.Error("pgman_build_info was not collected")
	}
}

// TestVersionDefaultsToDev keeps the unstamped case honest: a build
// without -ldflags must say so rather than claim a release number.
func TestVersionDefaultsToDev(t *testing.T) {
	// `go test` does not pass the release ldflags, so this is the
	// unstamped path.
	if version != "dev" {
		t.Skipf("this binary was stamped as %q, nothing to check", version)
	}
	if strings.ContainsAny(version, "0123456789") {
		t.Errorf("unstamped version %q looks like a release number", version)
	}
}
