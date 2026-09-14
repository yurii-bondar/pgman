package main

import (
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/yurii-bondar/pgman/pool"
)

type registryEntry struct {
	config  PoolConfig
	pool    *pool.Pool
	dnsStop func() // no-op if DNS watching is disabled
}

// PoolRegistry is the live, mutable set of named pools. Sessions capture
// a *pool.Pool reference once at routing time and keep using it for
// their whole life — removing a name here only stops *new* sessions
// from finding it; existing ones drain naturally via that pool's Close.
type PoolRegistry struct {
	eventLog       *EventLog
	defaults       *Config // top-level defaults for per-pool lifecycle merge; may be nil for tests
	observeAcquire func(poolName string) pool.ObserveWaitFunc

	mu      sync.RWMutex
	entries map[string]*registryEntry
}

func NewPoolRegistry(initial map[string]PoolConfig, eventLog *EventLog) *PoolRegistry {
	return NewPoolRegistryWithDefaults(initial, eventLog, nil, nil)
}

// NewPoolRegistryWithDefaults threads the top-level Config lifecycle
// defaults (idle timeout, max lifetime, etc.) into every pool it
// creates, plus a metric-observer factory for Prometheus histograms.
// Both are optional — nil defaults yield the permissive dev behavior
// tests already rely on, nil observer skips wait-time histograms.
func NewPoolRegistryWithDefaults(initial map[string]PoolConfig, eventLog *EventLog, defaults *Config, observeAcquire func(string) pool.ObserveWaitFunc) *PoolRegistry {
	r := &PoolRegistry{
		eventLog:       eventLog,
		defaults:       defaults,
		observeAcquire: observeAcquire,
		entries:        make(map[string]*registryEntry, len(initial)),
	}
	for name, cfg := range initial {
		p := r.newPool(name, cfg)
		r.entries[name] = &registryEntry{
			config:  cfg,
			pool:    p,
			dnsStop: r.startDNSWatcherFor(name, cfg, p),
		}
	}
	return r
}

// startDNSWatcherFor centralizes the "should this pool have a DNS
// watcher, and if so, at what interval" decision. Returns a no-op
// stopper when the feature is disabled.
func (r *PoolRegistry) startDNSWatcherFor(name string, cfg PoolConfig, p *pool.Pool) func() {
	if r.defaults == nil || r.defaults.DNSResolveInterval <= 0 {
		return func() {}
	}
	return startDNSWatcher(name, cfg.BackendAddr, p, r.defaults.DNSResolveInterval)
}

// newPool centralizes pool.New so lifecycle options (idle timeout,
// lifetime, min idle, healthcheck delay, dial retry, wait observer) are
// resolved from the merged config in exactly one place.
func (r *PoolRegistry) newPool(name string, cfg PoolConfig) *pool.Pool {
	opts := []pool.Option{}
	// healthCheckTimeout is resolved here rather than baked into the
	// healthCheck function, which is why this used to silently ignore
	// the operator's setting: pool.New took a bare HealthCheck with a
	// hardcoded deadline, so health_check_timeout only ever affected
	// server_reset_query.
	healthCheckTimeout := defaultHealthCheckTimeout
	if r.defaults != nil {
		l := poolLifecycleDefaults(r.defaults, cfg)
		if l.IdleTimeout > 0 {
			opts = append(opts, pool.WithIdleTimeout(l.IdleTimeout))
		}
		if l.MaxLifetime > 0 {
			opts = append(opts, pool.WithMaxLifetime(l.MaxLifetime))
		}
		if l.HealthCheckDelay > 0 {
			opts = append(opts, pool.WithHealthCheckDelay(l.HealthCheckDelay))
		}
		if l.MinIdle > 0 {
			opts = append(opts, pool.WithMinIdle(l.MinIdle))
		}
		if l.DialRetry > 0 {
			opts = append(opts, pool.WithDialRetry(l.DialRetry, l.DialRetryBackoff))
		}
		if l.CircuitThreshold > 0 && l.CircuitCooldown > 0 {
			opts = append(opts, pool.WithCircuitBreaker(l.CircuitThreshold, l.CircuitCooldown))
		}
		if r.defaults.HealthCheckTimeout > 0 {
			healthCheckTimeout = r.defaults.HealthCheckTimeout
		}
	}
	if r.observeAcquire != nil {
		if fn := r.observeAcquire(name); fn != nil {
			opts = append(opts, pool.WithObserveWait(fn))
		}
	}
	requireTLS := false
	if r.defaults != nil {
		requireTLS = r.defaults.RequireBackendTLS
	}
	check := func(conn net.Conn) error { return healthCheckWithTimeout(conn, healthCheckTimeout) }
	return pool.New(newDialBackend(cfg.BackendDSN, cfg.BackendAddr, requireTLS), cfg.Limit, check, r.onEvent(name), opts...)
}

// onEvent returns a pool.EventFunc bound to name, for tagging each event
// with which pool it came from before handing it to the shared log.
func (r *PoolRegistry) onEvent(name string) pool.EventFunc {
	return func(kind string, err error) {
		r.eventLog.Record(name, kind, err)
	}
}

func (r *PoolRegistry) Get(name string) (*pool.Pool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[name]; ok {
		return e.pool, true
	}
	// Alias resolution: allows one pool to serve multiple client-
	// visible database names (r/w split, sharding fronts). Linear
	// scan is fine here — pool counts are single-to-low-double-digit
	// in every realistic pgman deployment.
	for _, e := range r.entries {
		for _, alias := range e.config.Aliases {
			if alias == name {
				return e.pool, true
			}
		}
	}
	return nil, false
}

// ResolveName maps a client-visible database name to the registry key
// of the pool that serves it, following aliases. Returns name unchanged
// when nothing matches, so callers can use the result as a metric label
// without a second existence check.
func (r *PoolRegistry) ResolveName(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, ok := r.entries[name]; ok {
		return name
	}
	for key, e := range r.entries {
		for _, alias := range e.config.Aliases {
			if alias == name {
				return key
			}
		}
	}
	return name
}

// PoolConfig returns the config that was used to instantiate the named
// pool — used by Router to look up per-pool policy (pooling mode, etc.)
// without needing a second lookup path.
func (r *PoolRegistry) PoolConfig(name string) (PoolConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[name]; ok {
		return e.config, true
	}
	// Same alias resolution as Get — kept in sync so a router lookup
	// pairs correctly with a config lookup for the same client name.
	for _, e := range r.entries {
		for _, alias := range e.config.Aliases {
			if alias == name {
				return e.config, true
			}
		}
	}
	return PoolConfig{}, false
}

// Pools returns a shallow snapshot safe to range over without holding
// the registry's lock.
func (r *PoolRegistry) Pools() map[string]*pool.Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*pool.Pool, len(r.entries))
	for name, e := range r.entries {
		out[name] = e.pool
	}
	return out
}

// Names returns configured pool names, sorted, for stable UI rendering.
func (r *PoolRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.entries))
	for name := range r.entries {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *PoolRegistry) Add(name string, cfg PoolConfig) error {
	if name == "" {
		return fmt.Errorf("pool name is required")
	}
	if cfg.BackendDSN == "" || cfg.BackendAddr == "" {
		return fmt.Errorf("backend_dsn and backend_addr are required")
	}
	if cfg.Limit <= 0 {
		return fmt.Errorf("limit must be positive, got %d", cfg.Limit)
	}
	// Add is the admin-API entry point, so the address arrives from an
	// HTTP form rather than from a reviewed config file. See
	// validateBackendAddr for what that allows if left unchecked.
	if err := validateBackendAddr(cfg.BackendAddr); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		return fmt.Errorf("pool %q already exists", name)
	}
	p := r.newPool(name, cfg)
	r.entries[name] = &registryEntry{
		config:  cfg,
		pool:    p,
		dnsStop: r.startDNSWatcherFor(name, cfg, p),
	}
	return nil
}

// Configs returns each pool's originating configuration (current Limit
// included) — used by the admin UI to render the management panel.
func (r *PoolRegistry) Configs() map[string]PoolConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]PoolConfig, len(r.entries))
	for name, e := range r.entries {
		out[name] = e.config
	}
	return out
}

// Remove takes name out of the registry immediately and returns its
// pool so the caller can drain it.
func (r *PoolRegistry) Remove(name string) (*pool.Pool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, fmt.Errorf("pool %q not found", name)
	}
	delete(r.entries, name)
	if e.dnsStop != nil {
		e.dnsStop()
	}
	return e.pool, nil
}

// Resize swaps in a fresh pool at the new limit immediately.
func (r *PoolRegistry) Resize(name string, newLimit int) (old *pool.Pool, err error) {
	if newLimit <= 0 {
		return nil, fmt.Errorf("limit must be positive, got %d", newLimit)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[name]
	if !ok {
		return nil, fmt.Errorf("pool %q not found", name)
	}
	cfg := e.config
	cfg.Limit = newLimit
	// Stop the old watcher before we swap the pool — the watcher
	// closes over the OLD pool pointer and would call Reconnect on a
	// pool that's about to be drained anyway.
	if e.dnsStop != nil {
		e.dnsStop()
	}
	newPool := r.newPool(name, cfg)
	r.entries[name] = &registryEntry{
		config:  cfg,
		pool:    newPool,
		dnsStop: r.startDNSWatcherFor(name, cfg, newPool),
	}
	return e.pool, nil
}
