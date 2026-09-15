package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML shape. All duration fields accept Go's
// standard time.Duration syntax ("30s", "5m", "1h").
type Config struct {
	// ---- Network / TLS ----------------------------------------------

	ListenAddr  string `yaml:"listen_addr"`  // Postgres wire, data plane
	MetricsAddr string `yaml:"metrics_addr"` // Prometheus /metrics only
	AdminAddr   string `yaml:"admin_addr"`   // Admin UI + pool CRUD; separated from /metrics so a public scrape target never exposes controls

	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// TLSClientCAFile enables mTLS for data-plane clients: any
	// presented client cert is verified against this CA bundle.
	// Combined with HBA METHOD=cert, the peer certificate's Common
	// Name becomes the client's identity — no password exchange.
	// Uses VerifyClientCertIfGiven (not RequireAnyClientCert) so
	// clients hitting other HBA methods (scram-sha-256, trust) can
	// still connect without a client cert.
	TLSClientCAFile string `yaml:"tls_client_ca_file"`

	// ---- Client-facing auth -----------------------------------------

	AuthUsers              map[string]string `yaml:"auth_users"`                // user -> SCRAM verifier
	AllowInsecureTrustAuth bool              `yaml:"allow_insecure_trust_auth"` // opt-in trust=all fallback

	// ---- Admin-facing auth ------------------------------------------

	// AdminBasicAuthUser + AdminBasicAuthPasswordHash: HTTP Basic auth
	// on the admin listener. Password is stored as a bcrypt hash;
	// generate one via `pgman -gen-admin-password '<pwd>'`. When
	// both are empty, the admin listener only accepts loopback callers
	// (safe default for dev).
	AdminBasicAuthUser         string `yaml:"admin_basic_auth_user"`
	AdminBasicAuthPasswordHash string `yaml:"admin_basic_auth_password_hash"`

	// ---- Admin TLS / mTLS ------------------------------------------
	//
	// AdminTLSCertFile + AdminTLSKeyFile: enable HTTPS on the admin
	// listener. Independent of the data-plane TLS (TLSCertFile) — a
	// realistic deployment often serves the admin UI on a shorter,
	// internally-signed cert while the Postgres wire uses a public one.
	//
	// AdminTLSClientCAFile: if set, the admin listener enables mutual
	// TLS. Clients presenting a certificate signed by any CA in this
	// bundle are treated as authenticated without needing Basic auth or
	// OIDC. Combined with AdminMTLSAllowedCNs it lets operators pin
	// exactly which certificate identities may reach the admin plane —
	// typically ops laptops issued via corp CA. When empty, plain HTTPS.
	AdminTLSCertFile     string `yaml:"admin_tls_cert_file"`
	AdminTLSKeyFile      string `yaml:"admin_tls_key_file"`
	AdminTLSClientCAFile string `yaml:"admin_tls_client_ca_file"`

	// AdminMTLSAllowedCNs restricts which client-certificate Common
	// Names may authenticate via mTLS. Empty list ⇒ any cert issued by
	// the configured CA is accepted (still no anonymous access). Length
	// > 0 ⇒ the client cert's CN must be in this set. CN is a very
	// coarse identifier — most modern deployments would prefer SAN
	// emails, but pinning CN is enough for the common case of a single
	// human-issued cert per operator.
	AdminMTLSAllowedCNs []string `yaml:"admin_mtls_allowed_cns"`

	// ---- Admin OIDC ------------------------------------------------
	//
	// AdminOIDCIssuerURL: OpenID Provider (e.g. Google, Okta, Keycloak)
	// discovery root. Empty ⇒ OIDC path disabled.
	// AdminOIDCClientID: expected audience claim on the id_token.
	// AdminOIDCAllowedEmails / AdminOIDCAllowedSubjects: allowlists on
	// the "email" / "sub" claim. At least one must be non-empty when
	// OIDC is enabled (otherwise anyone with a valid id_token from the
	// issuer — including newly-registered strangers on public IDPs —
	// could reach admin, which is never what an operator intends).
	// AdminOIDCSkipEmailVerified defaults to false; keep it that way
	// unless the IDP is a corporate one that intentionally omits the
	// claim.
	AdminOIDCIssuerURL         string   `yaml:"admin_oidc_issuer_url"`
	AdminOIDCClientID          string   `yaml:"admin_oidc_client_id"`
	AdminOIDCAllowedEmails     []string `yaml:"admin_oidc_allowed_emails"`
	AdminOIDCAllowedSubjects   []string `yaml:"admin_oidc_allowed_subjects"`
	AdminOIDCSkipEmailVerified bool     `yaml:"admin_oidc_skip_email_verified"`

	// EnablePprof exposes net/http/pprof on the admin listener (under
	// the same auth). Off by default: pprof is a live-heap dump gun.
	EnablePprof bool `yaml:"enable_pprof"`

	// AdminDatabase is the virtual database name that switches a
	// client connecting on the DATA plane into PgBouncer-compatible
	// admin SQL mode (SHOW POOLS, PAUSE, RESUME, RECONNECT, etc.).
	// Defaults to "pgbouncer" to match PgBouncer muscle memory and
	// existing dashboards. Set to "" to disable admin SQL entirely.
	AdminDatabase string `yaml:"admin_database"`

	// AdminUsers lists the client usernames allowed into that console.
	// Mirrors PgBouncer's admin_users, and exists for the same reason:
	// passing client auth proves who you are, not that you may PAUSE
	// every pool on the proxy or read every other tenant's session list
	// out of SHOW CLIENTS.
	//
	// Empty (the default) denies everyone — a client naming
	// AdminDatabase then gets the same "database is not configured"
	// answer as any other unknown name, so the console isn't
	// discoverable by probing.
	AdminUsers []string `yaml:"admin_users"`

	// AuthHBAFile is the path to a PgBouncer/Postgres-style host-based
	// authentication file. When set, every incoming client connection
	// is matched against rules in order (first match wins). Method
	// determines the auth exchange: trust, reject, or scram-sha-256
	// (which delegates to the configured SCRAM backend). Empty path
	// disables HBA and every client hits the base AuthBackend directly.
	AuthHBAFile string `yaml:"auth_hba_file"`

	// ShutdownTimeout is how long the process waits, after receiving
	// SIGTERM/SIGINT, for in-flight sessions to finish before force-
	// exiting. Mirrors PgBouncer's server_check_delay semantics for
	// graceful drain. On expiry we still exit — the exit code is 0
	// only if the drain completed cleanly.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`

	// RequireBackendTLS gates pool creation on every backend DSN
	// having a strict sslmode (require / verify-ca / verify-full).
	// PgBouncer-equivalent operational safety: prevents accidental
	// plain-text traffic to a managed Postgres. Recommended: true
	// in production, false only for local dev docker-compose.
	RequireBackendTLS bool `yaml:"require_backend_tls"`

	// MaxDBConnections caps concurrent client sessions per configured
	// database name. 0 = unlimited (PgBouncer default). Enforced at
	// startup, after auth/routing succeed. Protects against one
	// noisy tenant starving every other database on this proxy.
	MaxDBConnections int `yaml:"max_db_connections"`

	// MaxUserConnections caps concurrent client sessions per
	// authenticated user, aggregated across databases. 0 = unlimited.
	// Complements MaxDBConnections when your tenancy model is
	// user-scoped rather than database-scoped.
	MaxUserConnections int `yaml:"max_user_connections"`

	// AuthQueryDSN is the DSN to connect to when resolving unknown
	// users via auth_query. Typically the same host+port as a pool,
	// but with an "auth_user" role that has SELECT on pg_shadow.
	// Empty disables auth_query (fall back to static AuthUsers only).
	AuthQueryDSN string `yaml:"auth_query_dsn"`
	// AuthQuery is the SELECT run against AuthQueryDSN. Must return
	// (username TEXT, passwd TEXT) and take one $1 bound param.
	// Empty falls back to PgBouncer's default: SELECT usename, passwd
	// FROM pg_shadow WHERE usename = $1.
	AuthQuery string `yaml:"auth_query"`
	// AuthQueryCacheTTL is how long resolved credentials are cached.
	// 0 = 60s. Short values (5-30s) are appropriate when passwords
	// rotate frequently; longer values reduce load on pg_shadow.
	AuthQueryCacheTTL time.Duration `yaml:"auth_query_cache_ttl"`

	// DNSResolveInterval is how often background watchers re-resolve
	// each pool's backend_addr hostname. On IP-set change, the whole
	// pool's Reconnect() is fired proactively — the operational win
	// after an RDS failover (bounded staleness window instead of "wait
	// for health-check to trip on every idle conn"). 0 disables.
	// Recommended prod value: 30s.
	DNSResolveInterval time.Duration `yaml:"dns_resolve_interval"`

	// UnixSocketDir, if non-empty, causes the proxy to also listen on
	// a Unix-domain socket at <dir>/.s.PGSQL.<port> (matching libpq's
	// convention). Local clients get lower overhead, isolation via
	// filesystem permissions, and — with HBA METHOD=peer — SO_PEERCRED
	// identity binding without any password exchange.
	UnixSocketDir string `yaml:"unix_socket_dir"`
	// UnixSocketMode is the octal permission mode set on the socket
	// file after bind. 0777 (world-writable) matches PgBouncer's
	// default. Tighten to 0770 (group-only) or 0700 (owner-only)
	// when combined with METHOD=peer for real security.
	UnixSocketMode string `yaml:"unix_socket_mode"`

	// AuditLogPath: where to write the structured JSON audit stream.
	// "" or "-" = stderr (same stream as operational logs, tagged by
	// component=audit). Anything else is a file path opened in append
	// mode. Recommended prod setup: dedicated file + logrotate + SIEM
	// tail.
	AuditLogPath string `yaml:"audit_log_path"`

	// MaxSessionsPerSecPerUser is the sustained session-open rate cap
	// per user (token bucket). 0 disables. See rate_limit.go for why
	// this is session-open rather than per-query.
	MaxSessionsPerSecPerUser int `yaml:"max_sessions_per_sec_per_user"`
	// MaxSessionsBurstPerUser is the bucket capacity — how many
	// simultaneous session opens per user pass without rate check.
	// Defaults to MaxSessionsPerSecPerUser when 0.
	MaxSessionsBurstPerUser int `yaml:"max_sessions_burst_per_user"`

	// TrackExtraParameters lists StartupMessage RuntimeParams that
	// should be replayed on every fresh backend Acquire in transaction
	// pooling mode. Without this, session-scoped GUCs a client set at
	// connect (application_name is the classic example — it's how
	// pg_stat_activity distinguishes apps) get "lost" every time we
	// route the next tx to a different backend.
	//
	// Empty slice = only "application_name" is tracked. To disable
	// entirely, set to ["-"] or leave TrackExtraParameters=nil AND
	// unset AppNameTracking (not exposed — see applyDefaults).
	TrackExtraParameters []string `yaml:"track_extra_parameters"`

	// MaxPreparedStatements caps how many named prepared statements the
	// proxy tracks per client session, so that transaction-mode replay
	// cannot be turned into unbounded memory growth by a client that
	// keeps inventing statement names. Mirrors PgBouncer's key of the
	// same name; 0 takes the default (200), negative disables the cap.
	//
	// Past the cap the least recently used entry is dropped. Set this
	// at or above the statement-cache size of your driver (pgx defaults
	// to 512) if you want replay to never miss — and budget for it:
	// the worst case is roughly cap × average statement size ×
	// max_client_conn.
	MaxPreparedStatements int `yaml:"max_prepared_statements"`

	// ---- Limits & timeouts (data plane) -----------------------------

	// MaxClientConn caps the total concurrent client connections
	// accepted. 0 = unlimited (the old default; not safe for
	// internet-facing use). Mirrors PgBouncer's max_client_conn.
	MaxClientConn int `yaml:"max_client_conn"`

	// ClientLoginTimeout bounds the whole startup + auth handshake per
	// client. A client that opens TCP but never sends bytes ties up an
	// accept slot forever without this. Mirrors PgBouncer's
	// client_login_timeout. 0 disables (unsafe).
	ClientLoginTimeout time.Duration `yaml:"client_login_timeout"`

	// QueryTimeout caps how long a single query may run on a backend
	// before the proxy gives up on it, closes that backend (which
	// aborts the query server-side) and reports the failure to the
	// client. Mirrors PgBouncer's query_timeout.
	//
	// 0 disables it, matching PgBouncer — the right ceiling is entirely
	// workload-specific and a proxy that silently kills a legitimate
	// 20-minute report is worse than one that does nothing.
	//
	// Deliberately not applied to COPY or replication streams: those
	// are bulk transfers whose duration says nothing about health.
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// ClientIdleTimeout closes a client that has been connected but
	// silent for this long while NOT inside a transaction. Mirrors
	// PgBouncer's client_idle_timeout. 0 disables.
	//
	// The failure it prevents: in session pooling a silent client holds
	// its backend for as long as the socket stays open, which — with
	// default OS keepalives — can be hours after the peer is gone.
	ClientIdleTimeout time.Duration `yaml:"client_idle_timeout"`

	// IdleTransactionTimeout closes a client that is sitting inside an
	// open transaction without sending anything. Mirrors PgBouncer's
	// idle_transaction_timeout. 0 disables.
	//
	// This is the more dangerous sibling of ClientIdleTimeout: an idle
	// open transaction pins a backend *and* holds whatever locks and
	// snapshot it has already taken, so it blocks other writers and
	// stops vacuum from advancing.
	IdleTransactionTimeout time.Duration `yaml:"idle_transaction_timeout"`

	// CircuitBreakerThreshold is how many consecutive dial failures
	// trip a pool's breaker. While open, Acquire fails immediately
	// instead of dialing, and the client gets a retryable error.
	//
	// Enabled by default (unlike the timeouts above) because it only
	// engages once a backend has failed this many times in a row — at
	// which point every alternative behaviour is worse for both the
	// proxy and the server it is hammering. Set to -1 to disable.
	CircuitBreakerThreshold int `yaml:"circuit_breaker_threshold"`

	// CircuitBreakerCooldown is how long the breaker stays open before
	// admitting a single probe connection.
	CircuitBreakerCooldown time.Duration `yaml:"circuit_breaker_cooldown"`

	// QueryWaitTimeout is the max time a client will block in Acquire
	// waiting for a backend when the pool is saturated. On expiry, the
	// client sees a FATAL and the goroutine returns instead of parking
	// forever. Mirrors PgBouncer's query_wait_timeout. 0 disables
	// (unsafe under load).
	QueryWaitTimeout time.Duration `yaml:"query_wait_timeout"`

	// ServerResetQuery runs on the backend between transactions from
	// *different clients* — session state (SET, prepared statements,
	// temp tables, listen/notify, GUCs) that survived the previous
	// client's commit must be scrubbed before the next client sees it.
	// Default: "DISCARD ALL". Set to "" to disable (breaks isolation).
	// Mirrors PgBouncer's server_reset_query.
	ServerResetQuery string `yaml:"server_reset_query"`

	// ServerResetQueryAlways runs ServerResetQuery on every backend
	// handover, including when the connection goes straight back to the
	// session that just released it.
	//
	// Off by default, because that scrub isolates a session from itself
	// and costs two round trips per transaction to do it (the DISCARD
	// plus the tracked-parameter replay that restores what it wiped).
	// Isolation between *different* clients is unaffected either way —
	// see adoptBackend.
	//
	// The reason to turn it on is determinism rather than safety. With
	// it off, a session-level SET survives into the next transaction
	// whenever the pool hands back the same connection and is lost when
	// it doesn't, so a client can appear to get away with session state
	// in transaction pooling until load makes connections start moving
	// between clients. On, session state is reliably discarded, exactly
	// as before this option existed.
	ServerResetQueryAlways bool `yaml:"server_reset_query_always"`

	// TCPKeepAlive interval on both accepted client sockets and dialed
	// backend sockets — detects and evicts dead peers instead of
	// leaking them until the OS FIN-timeout fires. 0 uses OS default.
	TCPKeepAlive time.Duration `yaml:"tcp_keepalive"`

	// ---- Pool lifecycle defaults (per-pool override in PoolConfig) --

	ServerIdleTimeout  time.Duration `yaml:"server_idle_timeout"`  // close pooled conn if idle > this
	ServerLifetime     time.Duration `yaml:"server_lifetime"`      // close pooled conn if older than this
	ServerCheckDelay   time.Duration `yaml:"server_check_delay"`   // skip healthcheck if idle < this
	ServerLoginRetry   int           `yaml:"server_login_retry"`   // extra dial attempts on failure
	ServerLoginBackoff time.Duration `yaml:"server_login_backoff"` // initial dial-retry backoff
	MinPoolSize        int           `yaml:"min_pool_size"`        // warm-up target per pool
	HealthCheckTimeout time.Duration `yaml:"health_check_timeout"` // per-conn healthcheck deadline

	// ---- HTTP server timeouts (metrics + admin) ---------------------

	HTTPReadHeaderTimeout time.Duration `yaml:"http_read_header_timeout"`
	HTTPReadTimeout       time.Duration `yaml:"http_read_timeout"`
	HTTPWriteTimeout      time.Duration `yaml:"http_write_timeout"` // 0 for SSE-capable listener
	HTTPIdleTimeout       time.Duration `yaml:"http_idle_timeout"`

	// ---- Logging ----------------------------------------------------

	LogFormat string `yaml:"log_format"` // "json" (default) or "text"
	LogLevel  string `yaml:"log_level"`  // debug/info/warn/error, default info

	// ---- Pools ------------------------------------------------------

	Pools map[string]PoolConfig `yaml:"pools"`
}

type PoolConfig struct {
	// BackendDSN carries the credentials + host the proxy uses to
	// dial this pool. The USERNAME baked into this DSN IS the effective
	// PgBouncer-style `pool_user`: clients auth against the proxy under
	// their own role (see AuthUsers / auth_query), but every backend
	// connection is opened under whatever user this DSN specifies.
	// This decouples client identity from backend credentials — the
	// typical setup is one restricted "app_ro" backend user for a
	// whole tenant's worth of client roles.
	BackendDSN  string `yaml:"backend_dsn"`
	BackendAddr string `yaml:"backend_addr"`
	Limit       int    `yaml:"limit"`
	// Aliases are extra client-visible database names that route to
	// this pool. The primary building block for r/w split (an "app_ro"
	// alias on a replica pool sends read-only clients to replicas
	// without any app-side change beyond the DSN's database name)
	// and for basic sharding (one pool per shard, each with the
	// customer-visible names it hosts as aliases).
	Aliases []string `yaml:"aliases"`

	// PoolMode selects how aggressively backends are recycled between
	// clients. Values (case-insensitive):
	//   "transaction" (default) — release backend on every RFQ 'I'.
	//   "session"               — hold backend until client disconnect.
	// Session mode is required for LISTEN/NOTIFY, temp tables that
	// must survive across transactions, prepared statements that
	// outlive one tx, or apps that rely on session-level GUCs (SET).
	PoolMode string `yaml:"pool_mode"`

	// Per-pool overrides. Any zero value inherits from Config's
	// corresponding top-level default.
	MinIdle          int           `yaml:"min_idle"`
	IdleTimeout      time.Duration `yaml:"idle_timeout"`
	MaxLifetime      time.Duration `yaml:"max_lifetime"`
	HealthCheckDelay time.Duration `yaml:"health_check_delay"`
	LoginRetry       int           `yaml:"login_retry"`
	LoginBackoff     time.Duration `yaml:"login_backoff"`
}

// applyDefaults fills unset top-level fields with production-sane
// defaults. Kept explicit rather than done in loadConfig so it's easy
// to see every value one place, and easy to test independently.
func (c *Config) applyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":6435"
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":8080"
	}
	if c.AdminAddr == "" {
		// Default to loopback-only — safe out of the box; operators
		// binding to a public interface must do so deliberately.
		c.AdminAddr = "127.0.0.1:8081"
	}
	if c.AdminDatabase == "" {
		c.AdminDatabase = AdminDatabaseDefault
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.TrackExtraParameters == nil {
		// PgBouncer defaults minus a couple that our proxy doesn't
		// re-negotiate anyway (e.g. server_version differs).
		c.TrackExtraParameters = []string{
			"application_name",
			"client_encoding",
			"DateStyle",
			"TimeZone",
			"IntervalStyle",
			"standard_conforming_strings",
		}
	}
	if c.MaxClientConn == 0 {
		c.MaxClientConn = 10_000
	}
	if c.MaxPreparedStatements == 0 {
		c.MaxPreparedStatements = defaultMaxPreparedStatements
	}
	if c.ClientLoginTimeout == 0 {
		c.ClientLoginTimeout = 60 * time.Second
	}
	if c.QueryWaitTimeout == 0 {
		c.QueryWaitTimeout = 120 * time.Second
	}
	// QueryTimeout / ClientIdleTimeout / IdleTransactionTimeout keep
	// their zero value on purpose: 0 means "disabled", same as
	// PgBouncer and same as Postgres' own statement_timeout. Enabling
	// them by default would start severing connections on upgrade.
	if c.CircuitBreakerThreshold == 0 {
		c.CircuitBreakerThreshold = 5
	}
	if c.CircuitBreakerCooldown == 0 {
		c.CircuitBreakerCooldown = 5 * time.Second
	}
	// ServerResetQuery: distinguish "unset" from "explicitly disabled".
	// yaml.v3 leaves an unset string as "" — we can't tell that apart
	// from an explicit empty string. We accept that; the operator who
	// wants to disable it can put `server_reset_query: " "` (whitespace)
	// or edit the code. In practice DISCARD ALL is what everyone wants.
	if c.ServerResetQuery == "" {
		c.ServerResetQuery = "DISCARD ALL"
	}
	if c.TCPKeepAlive == 0 {
		c.TCPKeepAlive = 30 * time.Second
	}
	if c.ServerIdleTimeout == 0 {
		c.ServerIdleTimeout = 10 * time.Minute
	}
	if c.ServerLifetime == 0 {
		c.ServerLifetime = 1 * time.Hour
	}
	if c.ServerCheckDelay == 0 {
		c.ServerCheckDelay = 30 * time.Second
	}
	if c.ServerLoginRetry == 0 {
		c.ServerLoginRetry = 3
	}
	if c.ServerLoginBackoff == 0 {
		c.ServerLoginBackoff = 200 * time.Millisecond
	}
	if c.HealthCheckTimeout == 0 {
		c.HealthCheckTimeout = 500 * time.Millisecond
	}
	if c.HTTPReadHeaderTimeout == 0 {
		c.HTTPReadHeaderTimeout = 5 * time.Second
	}
	if c.HTTPReadTimeout == 0 {
		c.HTTPReadTimeout = 30 * time.Second
	}
	// HTTPWriteTimeout intentionally left at 0 by default — the admin
	// listener serves long-lived SSE streams. Callers who split
	// admin/metrics listeners can override per-listener.
	if c.HTTPIdleTimeout == 0 {
		c.HTTPIdleTimeout = 60 * time.Second
	}
	if c.LogFormat == "" {
		c.LogFormat = "json"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
}

// dsnSSLMode extracts the sslmode parameter from a DSN, in either URL
// or keyword form. Returns "" when unset — which pgconn treats as
// "prefer", but we report separately so the warning can say so.
func dsnSSLMode(dsn string) string {
	lower := strings.ToLower(dsn)
	idx := strings.Index(lower, "sslmode=")
	if idx < 0 {
		if dsn == "" {
			return ""
		}
		return "prefer (unset)"
	}
	rest := lower[idx+len("sslmode="):]
	if end := strings.IndexAny(rest, "& "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// strictSSLMode reports whether an sslmode actually guarantees TLS.
// "prefer" and "allow" do not: both fall back to a plain connection if
// the server declines, with no error.
func strictSSLMode(mode string) bool {
	switch mode {
	case "require", "verify-ca", "verify-full":
		return true
	}
	return false
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	cfg.applyDefaults()

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("%s: tls_cert_file and tls_key_file must both be set or both be empty", path)
	}

	// A client that entered Acquire just before SIGTERM can legitimately
	// wait query_wait_timeout for a backend. If the shutdown budget is
	// shorter than that, the process is guaranteed to give up on it and
	// exit non-zero — not a failure of the drain, a mis-set budget.
	// Warn rather than reject: the defaults land here (30s vs 120s), and
	// for many deployments the short budget is the deliberate choice.
	// Plain-text traffic to the database is the kind of thing that is
	// only ever noticed in an audit. require_backend_tls stays off by
	// default so a local Postgres keeps working out of the box, but a
	// weak sslmode should never be silent.
	if !cfg.RequireBackendTLS {
		for name, pc := range cfg.Pools {
			if mode := dsnSSLMode(pc.BackendDSN); mode != "" && !strictSSLMode(mode) {
				slog.Warn("config: pool connects to its backend without enforced TLS — "+
					"traffic and credentials cross the network in plain text",
					"pool", name, "sslmode", mode,
					"fix", "set sslmode=verify-full in backend_dsn, and require_backend_tls: true")
			}
		}
	}

	if cfg.ShutdownTimeout < cfg.QueryWaitTimeout {
		slog.Warn("config: shutdown_timeout is shorter than query_wait_timeout — "+
			"a client already waiting for a backend when SIGTERM arrives cannot "+
			"finish within the shutdown budget",
			"shutdown_timeout", cfg.ShutdownTimeout,
			"query_wait_timeout", cfg.QueryWaitTimeout)
	}

	// Not an error: disabling the console is a legitimate stance, and
	// making it fatal would break every config that predates
	// admin_users. But silently losing SHOW POOLS after an upgrade is
	// the kind of thing an operator discovers mid-incident.
	if cfg.AdminDatabase != "" && len(cfg.AdminUsers) == 0 {
		slog.Warn("config: admin_database is set but admin_users is empty — "+
			"the PgBouncer-compatible admin console is disabled",
			"admin_database", cfg.AdminDatabase,
			"fix", "list the operator roles in admin_users, or set admin_database: \"\" to disable explicitly")
	}

	if len(cfg.AuthUsers) == 0 && !cfg.AllowInsecureTrustAuth {
		return nil, fmt.Errorf("%s: no auth_users configured — set at least one, or explicitly set allow_insecure_trust_auth: true to accept every client unauthenticated", path)
	}

	if (cfg.AdminBasicAuthUser == "") != (cfg.AdminBasicAuthPasswordHash == "") {
		return nil, fmt.Errorf("%s: admin_basic_auth_user and admin_basic_auth_password_hash must both be set or both be empty", path)
	}
	// mTLS: cert+key pair is all-or-nothing; a lone cert or key is
	// almost always a copy-paste mistake, and silently ignoring it
	// would leave the admin listener on plain HTTP where the operator
	// expected TLS.
	if (cfg.AdminTLSCertFile == "") != (cfg.AdminTLSKeyFile == "") {
		return nil, fmt.Errorf("%s: admin_tls_cert_file and admin_tls_key_file must both be set or both be empty", path)
	}
	// Client-CA without server cert is nonsensical (mTLS requires TLS).
	if cfg.AdminTLSClientCAFile != "" && cfg.AdminTLSCertFile == "" {
		return nil, fmt.Errorf("%s: admin_tls_client_ca_file requires admin_tls_cert_file and admin_tls_key_file to be set", path)
	}
	// OIDC: allowlist must be non-empty when OIDC is enabled — see the
	// AdminOIDC* doc comment for why "no allowlist" is a footgun.
	if cfg.AdminOIDCIssuerURL != "" {
		if cfg.AdminOIDCClientID == "" {
			return nil, fmt.Errorf("%s: admin_oidc_client_id must be set when admin_oidc_issuer_url is set", path)
		}
		if len(cfg.AdminOIDCAllowedEmails) == 0 && len(cfg.AdminOIDCAllowedSubjects) == 0 {
			return nil, fmt.Errorf("%s: at least one of admin_oidc_allowed_emails or admin_oidc_allowed_subjects must be non-empty when OIDC is enabled", path)
		}
	}

	if cfg.AdminBasicAuthPasswordHash != "" && !strings.HasPrefix(cfg.AdminBasicAuthPasswordHash, "$2") {
		return nil, fmt.Errorf("%s: admin_basic_auth_password_hash does not look like a bcrypt hash (missing $2 prefix) — use `pgman -gen-admin-password`", path)
	}

	if len(cfg.Pools) == 0 {
		return nil, fmt.Errorf("%s: at least one pool required", path)
	}
	for name, pc := range cfg.Pools {
		if pc.BackendDSN == "" {
			return nil, fmt.Errorf("%s: pool %q: backend_dsn required", path, name)
		}
		if pc.BackendAddr == "" {
			return nil, fmt.Errorf("%s: pool %q: backend_addr required", path, name)
		}
		if pc.Limit <= 0 {
			return nil, fmt.Errorf("%s: pool %q: limit must be positive, got %d", path, name, pc.Limit)
		}
	}

	return &cfg, nil
}

// poolLifecycle is the effective lifecycle configuration for one pool.
// Grouped in a struct rather than returned positionally: these are all
// durations and ints of the same shape, and a caller that transposes
// two of them gets a pool that compiles and misbehaves at 3am.
type poolLifecycle struct {
	IdleTimeout      time.Duration
	MaxLifetime      time.Duration
	HealthCheckDelay time.Duration
	MinIdle          int
	DialRetry        int
	DialRetryBackoff time.Duration
	CircuitThreshold int
	CircuitCooldown  time.Duration
}

// poolLifecycleDefaults resolves a PoolConfig's per-pool overrides
// against the top-level Config defaults. This is the single place the
// "override else default" merge happens, so pool.New in registry.go
// doesn't reimplement it.
func poolLifecycleDefaults(cfg *Config, pc PoolConfig) poolLifecycle {
	l := poolLifecycle{
		IdleTimeout:      pc.IdleTimeout,
		MaxLifetime:      pc.MaxLifetime,
		HealthCheckDelay: pc.HealthCheckDelay,
		MinIdle:          pc.MinIdle,
		DialRetry:        pc.LoginRetry,
		DialRetryBackoff: pc.LoginBackoff,
		// The breaker has no per-pool override: it is a property of
		// how a backend fails, and no deployment so far has wanted a
		// different threshold per pool. Add one when someone does.
		CircuitThreshold: cfg.CircuitBreakerThreshold,
		CircuitCooldown:  cfg.CircuitBreakerCooldown,
	}
	if l.IdleTimeout == 0 {
		l.IdleTimeout = cfg.ServerIdleTimeout
	}
	if l.MaxLifetime == 0 {
		l.MaxLifetime = cfg.ServerLifetime
	}
	if l.HealthCheckDelay == 0 {
		l.HealthCheckDelay = cfg.ServerCheckDelay
	}
	if l.MinIdle == 0 {
		l.MinIdle = cfg.MinPoolSize
	}
	if l.DialRetry == 0 {
		l.DialRetry = cfg.ServerLoginRetry
	}
	if l.DialRetryBackoff == 0 {
		l.DialRetryBackoff = cfg.ServerLoginBackoff
	}
	return l
}
