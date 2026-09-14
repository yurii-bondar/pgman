// Package main — periodic DNS re-resolution for backend hosts.
//
// After an RDS/GCP/Aurora failover the DNS record for the primary
// flips to the new node, but our idle backend connections still hold
// the old IP — a stale TCP connection to the old (now demoted /
// unreachable) instance. Health-check-on-acquire eventually notices
// (SELECT 1 timeouts or errors), discards, and dials fresh. That's
// slow: every hot query pays a health-check + dial round trip until
// idle is drained.
//
// dnsWatcher watches the pool's backend hostname and, when its
// resolved IP set changes, calls pool.Reconnect() proactively. That
// bumps the generation counter (see pool.Pool.Reconnect), which:
//
//   - closes every idle backend right now
//   - marks every in-flight backend to be discarded on its next Release
//
// Result: within one poll interval (default 30s) of a DNS flip, every
// backend connection in the pool has been reissued against the new IP.
// Active transactions are never interrupted — they release naturally
// and get dropped instead of returned to idle.
package main

import (
	"context"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yurii-bondar/pgman/pool"
)

// hostResolver is the single method dnsWatcher needs from the DNS
// layer. Declared here, at the consumer, rather than depending on the
// concrete *net.Resolver — which also means a test can drive an address
// change directly instead of standing up a DNS server to cause one.
type hostResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// dnsWatcher periodically resolves host and triggers pool.Reconnect()
// when the resolved IP set changes.
type dnsWatcher struct {
	poolName string
	host     string
	pool     *pool.Pool
	interval time.Duration
	resolver hostResolver

	mu      sync.Mutex
	lastIPs []string

	stopCh chan struct{}
	doneCh chan struct{}
}

// startDNSWatcher launches a background goroutine that polls host's
// A/AAAA records every interval. Returns a stop function the caller
// must invoke when the pool is torn down (e.g. from PoolRegistry.Remove).
//
// If interval <= 0, no watcher is started and the returned stop is a
// no-op — mirrors PgBouncer's default of DNS-lookup disabled.
func startDNSWatcher(poolName, addr string, p *pool.Pool, interval time.Duration) func() {
	if interval <= 0 {
		return func() {}
	}
	// Split host:port. If addr is host-only, that's fine too.
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	// IP literals never change — no point polling.
	if net.ParseIP(host) != nil {
		return func() {}
	}

	w := &dnsWatcher{
		poolName: poolName,
		host:     host,
		pool:     p,
		interval: interval,
		resolver: net.DefaultResolver,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	// Seed the initial IP set so the first legitimate change (not the
	// initial "we've never seen anything" transition) triggers a
	// reconnect. Failure to seed is non-fatal — the first tick will
	// see all IPs as "changed" and reconnect once, harmless.
	if ips, err := w.resolve(); err == nil {
		w.lastIPs = ips
	}
	go w.loop()
	return w.stop
}

func (w *dnsWatcher) resolve() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := w.resolver.LookupHost(ctx, w.host)
	if err != nil {
		return nil, err
	}
	// Normalize: sort so set-equality is trivial with reflect.DeepEqual
	// (or with our tiny slice comparator below).
	sort.Strings(addrs)
	return addrs, nil
}

func (w *dnsWatcher) loop() {
	defer close(w.doneCh)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			ips, err := w.resolve()
			if err != nil {
				slog.Debug("dns_watcher: lookup failed", "pool", w.poolName, "host", w.host, "err", err)
				continue
			}
			w.mu.Lock()
			changed := !stringSlicesEqual(w.lastIPs, ips)
			old := w.lastIPs
			if changed {
				w.lastIPs = ips
			}
			w.mu.Unlock()

			if changed {
				slog.Info("dns_watcher: address change — reconnecting pool",
					"pool", w.poolName,
					"host", w.host,
					"old_ips", strings.Join(old, ","),
					"new_ips", strings.Join(ips, ","))
				dropped := w.pool.Reconnect()
				slog.Info("dns_watcher: pool reconnected", "pool", w.poolName, "idle_dropped", dropped)
			}
		}
	}
}

func (w *dnsWatcher) stop() {
	close(w.stopCh)
	<-w.doneCh
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
