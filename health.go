package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Liveness and readiness probes.
//
// The two answer genuinely different questions, and conflating them is
// how a deployment ends up restarting healthy pods during an incident:
//
//   - /health (liveness) — "is this process still functioning?" It stays
//     200 for the entire lifetime of the process, including during a
//     graceful drain. A failing liveness probe means "restart me", and
//     restarting a proxy that is deliberately draining is wrong.
//
//   - /ready (readiness) — "should this instance receive new traffic?"
//     It turns 503 as soon as shutdown begins, which is what actually
//     removes the pod from the Service before the listener closes, and
//     also when no pool can reach its backend at all.
//
// Both live on the metrics listener rather than the admin one: probes
// come from the kubelet, which has no credentials, and the metrics
// listener is already the unauthenticated read-only surface.

// poolHealth is the per-pool detail included in a readiness response.
// Returned even when healthy — a probe endpoint that only explains
// itself on failure is useless for the debugging session that follows.
type poolHealth struct {
	Name        string `json:"name"`
	CircuitOpen bool   `json:"circuit_open"`
	InUse       int    `json:"in_use"`
	Idle        int    `json:"idle"`
	Waiting     int    `json:"waiting"`
}

type healthResponse struct {
	Status   string       `json:"status"`
	Draining bool         `json:"draining,omitempty"`
	Reason   string       `json:"reason,omitempty"`
	Pools    []poolHealth `json:"pools,omitempty"`
}

// healthHandler serves liveness. It reports the process is up; it
// deliberately does not consult the pools, because backend availability
// is not something a restart can fix.
func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeHealthJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

// readyHandler serves readiness.
//
// Not ready when:
//   - the process is draining, so traffic stops arriving before the
//     listener closes; this is the case that matters on every deploy.
//   - every configured pool has an open circuit breaker, i.e. this
//     instance cannot reach any backend at all.
//
// Note the "every" rather than "any". With several pools, one degraded
// backend affects every replica identically, so pulling them all out of
// rotation converts a partial outage into a total one. Removing an
// instance only helps when that instance is uniquely broken — which
// total backend loss (a bad node, a broken sidecar, a local network
// partition) plausibly is.
func readyHandler(registry *PoolRegistry, draining *atomic.Bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if draining != nil && draining.Load() {
			writeHealthJSON(w, http.StatusServiceUnavailable, healthResponse{
				Status:   "draining",
				Draining: true,
				Reason:   "shutting down: not accepting new sessions",
			})
			return
		}

		pools := registry.Pools()
		detail := make([]poolHealth, 0, len(pools))
		open := 0
		for _, name := range registry.Names() {
			p, ok := pools[name]
			if !ok {
				continue
			}
			s := p.Stats()
			if s.CircuitOpen {
				open++
			}
			detail = append(detail, poolHealth{
				Name:        name,
				CircuitOpen: s.CircuitOpen,
				InUse:       s.InUse,
				Idle:        s.Idle,
				Waiting:     s.Waiting,
			})
		}

		resp := healthResponse{Status: "ready", Pools: detail}
		// len(detail) == 0 means no pools are configured. That is a
		// misconfiguration, not a backend outage, and reporting ready
		// keeps the failure visible in logs instead of as a pod that
		// never starts.
		if len(detail) > 0 && open == len(detail) {
			resp.Status = "unready"
			resp.Reason = "no pool can reach its backend: every circuit breaker is open"
			writeHealthJSON(w, http.StatusServiceUnavailable, resp)
			return
		}
		writeHealthJSON(w, http.StatusOK, resp)
	}
}

// probeReadyTimeout bounds the self-probe below. A container health
// check that hangs is worse than one that fails: Docker keeps the
// previous verdict while it waits, so a wedged proxy would go on looking
// healthy.
const probeReadyTimeout = 3 * time.Second

// probeReady asks a running pgman on this host whether it is ready, and
// is what `pgman -health-check` runs.
//
// It exists because the runtime image is distroless: there is no shell,
// no curl and no wget to write a HEALTHCHECK with, and adding any of
// them would put a package manager's worth of attack surface next to a
// process that terminates database credentials. The binary already
// speaks HTTP, so it can ask the question itself.
//
// metricsAddr is the configured listen address, which is usually a bare
// port (":8080") or a wildcard — neither is dialable, so the host half is
// replaced with loopback. That is also the only address a probe running
// inside the same container should be using.
func probeReady(metricsAddr string) error {
	host, port, err := net.SplitHostPort(metricsAddr)
	if err != nil {
		return fmt.Errorf("metrics_addr %q: %w", metricsAddr, err)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: probeReadyTimeout}
	url := "http://" + net.JoinHostPort(host, port) + "/ready"
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// The body carries the reason /ready decided against itself —
		// draining, or every backend unreachable — and a health check
		// that discards it makes the container logs the only place to
		// find out, which is one indirection too many at 3am.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("not ready (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func writeHealthJSON(w http.ResponseWriter, status int, body healthResponse) {
	w.Header().Set("Content-Type", "application/json")
	// Probes must never be answered from a cache — an intermediary that
	// served a stale "ready" during a drain would defeat the point.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
