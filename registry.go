package main

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/yurii-bondar/pgman/pool"
)

// poolKeySeparator joins a pool's name and the backend role its
// connections are opened under, forming the registry key. Config
// validation rejects it inside either half, so a key parses back
// unambiguously and two pools can never collide on one.
const poolKeySeparator = "/"

// poolKey is the registry key for the pool serving backendUser on the
// named pool. An empty backendUser means the pool's own BackendDSN
// identity, and yields the bare pool name — so a deployment that does
// not use backend_users sees exactly the keys, metric labels and admin
// SQL rows it saw before per-user pools existed.
func poolKey(name, backendUser string) string {
	if backendUser == "" {
		return name
	}
	return name + poolKeySeparator + backendUser
}

type registryEntry struct {
	// poolName is the configured pool this entry belongs to; several
	// entries share it when backend_users splits the pool by identity.
	poolName string
	// backendUser is the client role whose credentials this entry
	// dials with. Empty means the pool's default BackendDSN identity.
	backendUser string
	// config has BackendDSN already resolved to this entry's identity,
	// so newPool needs to know nothing about the split.
	config PoolConfig
	// passthrough marks an entry that dials with a ClientKey recovered
	// from the client's own handshake rather than with the DSN's
	// credentials.
	passthrough bool
	pool        *pool.Pool
	dnsStop     func() // no-op if DNS watching is disabled
}

// PoolRegistry is the live, mutable set of pools. Sessions capture
// a *pool.Pool reference once at routing time and keep using it for
// their whole life — removing a name here only stops *new* sessions
// from finding it; existing ones drain naturally via that pool's Close.
//
// Pools are keyed by (pool name, backend role) rather than by database
// alone, because two clients that reach Postgres as different roles
// must not share a connection: the whole point of giving alice her own
// backend credentials is that her statements run as alice. Clients that
// do end up as the same role share one pool, which is both correct —
// Postgres cannot tell them apart — and what keeps the connection count
// from multiplying for deployments that never split by user.
//
// This is what PgBouncer does too: a pool per (database, user),
// collapsing to one pool per database when the database definition
// forces a single `user=`.
type PoolRegistry struct {
	eventLog       *EventLog
	defaults       *Config // top-level defaults for per-pool lifecycle merge; may be nil for tests
	observeAcquire func(poolName string) pool.ObserveWaitFunc

	// keys is the SCRAM pass-through credential store, consulted to
	// decide whether a user can have a pool of its own. Nil when no
	// pool asks for pass-through.
	keys *clientKeyStore

	mu      sync.RWMutex
	entries map[string]*registryEntry
	// byDatabase maps every client-visible database name — including
	// aliases — to the pool name serving it. Replaces the linear alias
	// scan the lookups used to do, which would now have to skip over
	// one duplicate per backend user.
	byDatabase map[string]string
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
		byDatabase:     make(map[string]string, len(initial)),
	}
	for name, cfg := range initial {
		r.addEntries(name, cfg)
	}
	return r
}

// addEntries creates every pool one configured entry needs: the default
// identity, plus one per backend_users role. Caller holds r.mu (or is
// the constructor, where nothing else can see r yet).
func (r *PoolRegistry) addEntries(name string, cfg PoolConfig) {
	r.byDatabase[name] = name
	for _, alias := range cfg.Aliases {
		r.byDatabase[alias] = name
	}

	r.entries[poolKey(name, "")] = r.newEntry(name, "", cfg, false)
	for user, dsn := range cfg.BackendUsers {
		// Same pool in every respect except who it connects as.
		userCfg := cfg
		userCfg.BackendDSN = dsn
		r.entries[poolKey(name, user)] = r.newEntry(name, user, userCfg, false)
	}
	// Pass-through pools cannot be built here: the credential does not
	// exist until a client authenticates. They appear on first use, in
	// Resolve.
}

func (r *PoolRegistry) newEntry(name, backendUser string, cfg PoolConfig, passthrough bool) *registryEntry {
	key := poolKey(name, backendUser)
	p := r.newPool(key, cfg, r.dialerFor(cfg, backendUser, passthrough))
	return &registryEntry{
		poolName:    name,
		backendUser: backendUser,
		config:      cfg,
		passthrough: passthrough,
		pool:        p,
		dnsStop:     r.startDNSWatcherFor(key, cfg, p),
	}
}

// dialerFor picks how an entry opens backend connections: with the
// DSN's own credentials, or as backendUser via SCRAM pass-through.
func (r *PoolRegistry) dialerFor(cfg PoolConfig, backendUser string, passthrough bool) pool.Dialer {
	requireTLS := r.defaults != nil && r.defaults.RequireBackendTLS
	if passthrough {
		return newPassthroughDialer(cfg.BackendDSN, backendUser, r.keys, requireTLS)
	}
	return newDialBackend(cfg.BackendDSN, cfg.BackendAddr, requireTLS)
}

// SetClientKeyStore wires the pass-through credential store. Called at
// startup, before any listener accepts, so no Resolve can race it.
func (r *PoolRegistry) SetClientKeyStore(store *clientKeyStore) {
	r.keys = store
}

// Resolve maps a client's (database, user) onto the pool that will
// carry its queries, following aliases and honouring backend_users and
// scram_passthrough. The returned key is the registry key — also the
// metric label and the name every admin surface shows.
func (r *PoolRegistry) Resolve(database, user string) (key string, p *pool.Pool, cfg PoolConfig, ok bool) {
	r.mu.RLock()
	name, found := r.byDatabase[database]
	if !found {
		r.mu.RUnlock()
		return "", nil, PoolConfig{}, false
	}
	base, hasBase := r.entries[poolKey(name, "")]
	if !hasBase {
		r.mu.RUnlock()
		return "", nil, PoolConfig{}, false
	}
	backendUser, passthrough := r.backendIdentityFor(base.config, user)
	e, exists := r.entries[poolKey(name, backendUser)]
	baseCfg := base.config
	r.mu.RUnlock()

	if exists {
		return poolKey(name, backendUser), e.pool, e.config, true
	}
	// The only way to miss is a pass-through user seen for the first
	// time: its credential did not exist until it logged in, so its pool
	// could not have been built at startup.
	if !passthrough {
		return "", nil, PoolConfig{}, false
	}
	return r.createPassthroughEntry(name, user, baseCfg)
}

// backendIdentityFor decides which backend role a client reaches
// Postgres as, and whether that role's credentials come from a
// pass-through ClientKey. An empty user means the pool's own BackendDSN
// identity.
//
// backend_users wins over scram_passthrough: an explicitly configured
// DSN is the operator saying exactly how this user should connect, and
// a recovered ClientKey should not quietly override it.
func (r *PoolRegistry) backendIdentityFor(cfg PoolConfig, user string) (backendUser string, passthrough bool) {
	if user == "" {
		return "", false
	}
	if _, configured := cfg.BackendUsers[user]; configured {
		return user, false
	}
	// No ClientKey means the client authenticated by some other method
	// — trust, peer, cert — and there is nothing to pass through.
	if cfg.ScramPassthrough && r.keys.has(user) {
		return user, true
	}
	return "", false
}

// createPassthroughEntry builds a per-user pass-through pool on first
// use. Pools are never evicted afterwards, which is bounded because
// only a client that completed a SCRAM handshake can cause one: the set
// of pools is the set of real roles that have connected, not anything a
// caller can inflate.
func (r *PoolRegistry) createPassthroughEntry(name, user string, cfg PoolConfig) (string, *pool.Pool, PoolConfig, bool) {
	key := poolKey(name, user)

	r.mu.Lock()
	defer r.mu.Unlock()
	// Another session for the same user may have won the race between
	// dropping the read lock and taking this one.
	if e, exists := r.entries[key]; exists {
		return key, e.pool, e.config, true
	}
	// Re-check the pool still exists: a Remove could have landed in the
	// same window, and resurrecting it here would route clients into a
	// database the operator has taken out.
	if _, stillThere := r.entries[poolKey(name, "")]; !stillThere {
		return "", nil, PoolConfig{}, false
	}

	e := r.newEntry(name, user, cfg, true)
	r.entries[key] = e
	slog.Info("pool: opened a SCRAM pass-through pool",
		"pool", key, "user", user, "limit", cfg.Limit)
	return key, e.pool, e.config, true
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
func (r *PoolRegistry) newPool(name string, cfg PoolConfig, dial pool.Dialer) *pool.Pool {
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
	check := func(conn net.Conn) error { return healthCheckWithTimeout(conn, healthCheckTimeout) }
	return pool.New(dial, cfg.Limit, check, r.onEvent(name), opts...)
}

// onEvent returns a pool.EventFunc bound to name, for tagging each event
// with which pool it came from before handing it to the shared log.
func (r *PoolRegistry) onEvent(name string) pool.EventFunc {
	return func(kind string, err error) {
		r.eventLog.Record(name, kind, err)
	}
}

// Get returns the pool stored under an exact registry key — "<pool>" or
// "<pool>/<backend user>". Routing goes through Resolve instead; this is
// for admin surfaces, which address pools by the key they display.
func (r *PoolRegistry) Get(key string) (*pool.Pool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[key]; ok {
		return e.pool, true
	}
	// A bare database name (or alias) also resolves, to that pool's
	// default-identity entry, so operators can name pools the way the
	// config file does.
	if name, ok := r.byDatabase[key]; ok {
		if e, ok := r.entries[poolKey(name, "")]; ok {
			return e.pool, true
		}
	}
	return nil, false
}

// ResolveName maps a client-visible database name to the name of the
// pool that serves it, following aliases. Returns name unchanged when
// nothing matches.
func (r *PoolRegistry) ResolveName(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if resolved, ok := r.byDatabase[name]; ok {
		return resolved
	}
	return name
}

// PoolConfig returns the config behind a registry key — for the key of
// a per-user pool, with BackendDSN already resolved to that user's.
func (r *PoolRegistry) PoolConfig(key string) (PoolConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[key]; ok {
		return e.config, true
	}
	if name, ok := r.byDatabase[key]; ok {
		if e, ok := r.entries[poolKey(name, "")]; ok {
			return e.config, true
		}
	}
	return PoolConfig{}, false
}

// Pools returns a shallow snapshot safe to range over without holding
// the registry's lock, keyed by registry key.
func (r *PoolRegistry) Pools() map[string]*pool.Pool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*pool.Pool, len(r.entries))
	for key, e := range r.entries {
		out[key] = e.pool
	}
	return out
}

// Names returns every registry key, sorted, for stable UI rendering.
func (r *PoolRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.entries))
	for key := range r.entries {
		names = append(names, key)
	}
	sort.Strings(names)
	return names
}

func (r *PoolRegistry) Add(name string, cfg PoolConfig) error {
	if name == "" {
		return fmt.Errorf("pool name is required")
	}
	if strings.Contains(name, poolKeySeparator) {
		return fmt.Errorf("pool name %q must not contain %q", name, poolKeySeparator)
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
	if _, exists := r.entries[poolKey(name, "")]; exists {
		return fmt.Errorf("pool %q already exists", name)
	}
	r.addEntries(name, cfg)
	return nil
}

// Configs returns each pool's originating configuration (current Limit
// included), keyed by registry key — used by the admin UI to render the
// management panel.
func (r *PoolRegistry) Configs() map[string]PoolConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]PoolConfig, len(r.entries))
	for key, e := range r.entries {
		out[key] = e.config
	}
	return out
}

// Remove takes a pool out of the registry immediately and returns its
// pools so the caller can drain them.
//
// name is a pool name, not a registry key: removing "backoffice" takes
// out every identity serving it. Removing one user's pool while the
// others keep routing would leave that user's clients failing to route
// with no way to see why from the pool list.
func (r *PoolRegistry) Remove(name string) ([]*pool.Pool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := r.takeEntries(name)
	if len(removed) == 0 {
		return nil, fmt.Errorf("pool %q not found", name)
	}
	pools := make([]*pool.Pool, 0, len(removed))
	for _, e := range removed {
		if e.dnsStop != nil {
			e.dnsStop()
		}
		pools = append(pools, e.pool)
	}
	return pools, nil
}

// takeEntries removes and returns every entry belonging to a pool name,
// along with the database names that routed to it. Caller holds r.mu.
func (r *PoolRegistry) takeEntries(name string) []*registryEntry {
	var out []*registryEntry
	for key, e := range r.entries {
		if e.poolName == name {
			out = append(out, e)
			delete(r.entries, key)
		}
	}
	if len(out) == 0 {
		return nil
	}
	for db, target := range r.byDatabase {
		if target == name {
			delete(r.byDatabase, db)
		}
	}
	return out
}

// Resize swaps in fresh pools at the new limit immediately, for every
// identity serving name. Returns the replaced pools to drain.
func (r *PoolRegistry) Resize(name string, newLimit int) ([]*pool.Pool, error) {
	if newLimit <= 0 {
		return nil, fmt.Errorf("limit must be positive, got %d", newLimit)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Take the default-identity entry first: it carries the config the
	// whole pool is rebuilt from, backend_users included.
	base, ok := r.entries[poolKey(name, "")]
	if !ok {
		return nil, fmt.Errorf("pool %q not found", name)
	}
	cfg := base.config
	cfg.Limit = newLimit

	// Stop the old watchers before swapping: each closes over the OLD
	// pool pointer and would call Reconnect on one that is about to be
	// drained anyway.
	old := r.takeEntries(name)
	pools := make([]*pool.Pool, 0, len(old))
	for _, e := range old {
		if e.dnsStop != nil {
			e.dnsStop()
		}
		pools = append(pools, e.pool)
	}
	r.addEntries(name, cfg)
	return pools, nil
}
