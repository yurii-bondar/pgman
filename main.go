package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/yurii-bondar/pgman/pool"
)

// runtimeOpts collects the data-plane knobs referenced on the hot path
// (accept/handshake/relay). Threaded through as one struct rather than
// captured via package globals so tests can construct a permissive
// default and drive handleConn/relay directly. Zero-value = "no timeout
// / no reset query / unlimited clients", exactly what the pre-existing
// tests already assumed.
type runtimeOpts struct {
	clientLoginTimeout time.Duration
	queryWaitTimeout   time.Duration
	tcpKeepAlive       time.Duration
	healthCheckTimeout time.Duration
	// The three timeouts that bound a session's I/O once the handshake
	// is done. All default to 0 (disabled), same as PgBouncer. See the
	// matching Config fields for what each one protects against.
	queryTimeout           time.Duration
	clientIdleTimeout      time.Duration
	idleTransactionTimeout time.Duration
	// clientWriteTimeout bounds a single write towards a client, so a
	// peer that has stopped reading cannot park a relay goroutine — and
	// the backend it holds — inside write(2). See client_write.go.
	clientWriteTimeout time.Duration
	serverResetQuery   string
	// resetSkipSameSession skips the scrub when the same session
	// reacquires the connection. See
	// Config.ServerResetQuerySkipSameSession.
	resetSkipSameSession bool

	// clientSlots is the max_client_conn semaphore: one buffered slot
	// per admissible client connection, nil meaning unlimited.
	//
	// It lives here, shared, rather than being allocated inside
	// acceptLoopWithOpts, because there is more than one accept loop —
	// TCP and the optional Unix socket — and a per-loop semaphore made
	// the real ceiling 2 × max_client_conn. The cap has to be a
	// property of the process, since so are the file descriptors and
	// the memory it is there to protect. Set it through
	// setMaxClientConn, never by hand.
	clientSlots chan struct{}

	metrics *proxyMetrics // nil in tests — every observe call must nil-check first

	// adminDatabase names the virtual DB that switches a client into
	// PgBouncer-compatible admin SQL mode (SHOW POOLS, PAUSE, RESUME…).
	// Empty string disables admin SQL entirely.
	adminDatabase string
	// adminSession is called instead of relay() when a client connects
	// to adminDatabase. Closes over the pool registry so SHOW POOLS
	// sees the live set.
	adminSession func(pg *pgproto3.Backend)

	// adminUsers is the set of client usernames allowed into that
	// console. A nil/empty set denies everyone — admin SQL is opt-in,
	// because the alternative (any authenticated client) hands every
	// tenant a PAUSE that takes the whole proxy down.
	adminUsers map[string]bool

	// maxPreparedStmts caps the per-session prepared-statement cache;
	// <= 0 disables the cap. See Config.MaxPreparedStatements.
	maxPreparedStmts int

	// trackExtraParams is the whitelist of client StartupMessage
	// RuntimeParams to replay on every new backend Acquire (transaction
	// mode). Order matters — some GUCs depend on others being set first.
	trackExtraParams []string

	// connLimiter enforces max_db_connections + max_user_connections
	// at startup, right after auth/routing. Nil = no per-user/db caps
	// (only the global max_client_conn semaphore applies).
	connLimiter *ConnLimiter

	// userRateLimiter throttles session-open rate per user. Nil =
	// disabled. Applied right after startup parse, before auth.
	userRateLimiter *RateLimiter

	// draining is set once on SIGTERM/SIGINT. A session that is between
	// transactions when it flips gets closed with a standard
	// admin_shutdown error instead of being allowed to start new work.
	//
	// This is deliberately not pool.Pause(): pausing makes the next
	// Acquire *block* for up to query_wait_timeout, which turns a
	// rolling restart into a client-visible freeze and guarantees the
	// shutdown budget expires with sessions still parked. Refusing
	// fast, with a code every driver knows how to reconnect from, is
	// what actually drains.
	draining atomic.Bool
}

// version is stamped at link time by the release build
// (-ldflags "-X main.version=..."). The Dockerfile has always passed
// that flag, but without this variable to write into, the linker had
// nothing to do and every published image would have been
// indistinguishable from every other one.
var version = "dev"

func defaultRuntimeOpts() *runtimeOpts {
	return &runtimeOpts{
		healthCheckTimeout: 500 * time.Millisecond,
		// Not zero like the other knobs: zero here would mean
		// "uncapped", and a permissive default that reintroduces the
		// unbounded cache is the wrong direction to be wrong in.
		maxPreparedStmts: defaultMaxPreparedStatements,
	}
}

// runtimeOptsFromConfig builds the accepted-connection runtime knobs
// from parsed Config values. Kept separate so main() stays orchestration-
// only and tests can build stripped-down opts without loading YAML.
func runtimeOptsFromConfig(cfg *Config, metrics *proxyMetrics) *runtimeOpts {
	opts := &runtimeOpts{
		clientLoginTimeout: cfg.ClientLoginTimeout,
		queryWaitTimeout:   cfg.QueryWaitTimeout,
		tcpKeepAlive:       cfg.TCPKeepAlive,
		healthCheckTimeout: cfg.HealthCheckTimeout,

		queryTimeout:           cfg.QueryTimeout,
		clientIdleTimeout:      cfg.ClientIdleTimeout,
		idleTransactionTimeout: cfg.IdleTransactionTimeout,
		clientWriteTimeout:     cfg.ClientWriteTimeout,

		serverResetQuery:     cfg.ServerResetQuery,
		resetSkipSameSession: cfg.ServerResetQuerySkipSameSession,
		maxPreparedStmts:     cfg.MaxPreparedStatements,
		metrics:              metrics,
		adminDatabase:        cfg.AdminDatabase,
		adminUsers:           adminUserSet(cfg.AdminUsers),
		trackExtraParams:     cfg.TrackExtraParameters,
		// adminSession is wired up by main() where the registry is
		// available. Left nil here so plain runtimeOptsFromConfig
		// callers (tests) don't accidentally enable admin SQL without
		// providing a registry.
	}
	opts.setMaxClientConn(cfg.MaxClientConn)
	return opts
}

// setMaxClientConn allocates the one semaphore every accept loop shares.
// n <= 0 means unlimited.
//
// This is the only way to set the cap. Making it a method rather than a
// plain field is what stops the previous bug from coming back: a caller
// that assigned a number and left the semaphore to be created later,
// per listener, got a limit that multiplied by the number of listeners.
func (o *runtimeOpts) setMaxClientConn(n int) {
	if n <= 0 {
		o.clientSlots = nil
		return
	}
	o.clientSlots = make(chan struct{}, n)
}

// adminUserSet turns the configured admin_users list into the lookup
// the startup path uses. Returns nil for an empty list, which reads as
// "deny everyone" — a nil map lookup is false, so the caller needs no
// separate nil check.
func adminUserSet(users []string) map[string]bool {
	if len(users) == 0 {
		return nil
	}
	set := make(map[string]bool, len(users))
	for _, u := range users {
		if u != "" {
			set[u] = true
		}
	}
	return set
}

func main() {
	os.Exit(cli(os.Args[1:], os.Stdout, os.Stderr))
}

// cli parses the command line, handles the modes that print something
// and exit, and otherwise runs the proxy until it is signalled. Returns
// the process exit code.
//
// Split from main so that the flag handling — including the three modes
// that never start a proxy at all — is reachable from a test. main
// itself is then the one thing that genuinely cannot be tested: a call
// to os.Exit.
func cli(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pgman", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "config.yaml", "path to YAML config file")
	genVerifierFor := flags.String("gen-scram-verifier", "", "print a SCRAM-SHA-256 verifier for this password (for auth_users in config.yaml) and exit")
	genAdminPassword := flags.String("gen-admin-password", "", "print a bcrypt hash for this admin password (for admin_basic_auth_password_hash in config.yaml) and exit")
	showVersion := flags.Bool("version", false, "print the version and exit")
	healthCheck := flags.Bool("health-check", false, "probe a pgman already running in this container and exit 0 when it is ready (for Docker HEALTHCHECK)")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	// Before anything that can fail: identifying a binary must not
	// require a valid config file, since "which build is this?" is a
	// question people ask precisely when something is misconfigured.
	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "pgman %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return 0
	}

	if *genVerifierFor != "" {
		verifier, err := GenerateSCRAMVerifier(*genVerifierFor, 4096)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "generate verifier: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, verifier)
		return 0
	}
	if *genAdminPassword != "" {
		hash, err := generateAdminPasswordHash(*genAdminPassword)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "generate admin password hash: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, hash)
		return 0
	}

	if *healthCheck {
		// loadConfig warns about weak backend TLS and an empty
		// admin_users, which are worth saying once at startup and not
		// every fifteen seconds for the life of the container. The probe
		// reads the config only to find a port, so it says nothing at
		// all unless it has a verdict.
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "config: %v\n", err)
		return 1
	}

	// Asks the proxy already running beside it. This is a second,
	// short-lived process inside somebody else's container, and it should
	// leave nothing behind but an exit code.
	if *healthCheck {
		if err := probeReady(cfg.MetricsAddr); err != nil {
			_, _ = fmt.Fprintf(stderr, "health-check: %v\n", err)
			return 1
		}
		return 0
	}

	setupLogging(cfg.LogFormat, cfg.LogLevel)

	// Route the standard log package through slog, so any leftover
	// log.Printf calls in dependencies land in structured output too.
	stdlog.SetFlags(0)
	stdlog.SetOutput(slogWriter{})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, *configPath, nil); err != nil {
		// A drain that ran out of budget is not a failure to start: the
		// proxy did its job and then some session outstayed the
		// shutdown deadline. k8s / systemd read the exit code, so it has
		// to be non-zero, but reporting it as a startup failure would
		// send whoever reads the log looking for a crash.
		if !errors.Is(err, errDrainIncomplete) {
			_, _ = fmt.Fprintf(stderr, "%v\n", err)
		}
		return 1
	}
	return 0
}

// errDrainIncomplete reports that shutdown hit its deadline with
// sessions still active. Distinct from a startup failure because it
// means something different to whoever is reading: the process ran.
var errDrainIncomplete = errors.New("shutdown: drain did not complete within shutdown_timeout")

// runtimeAddrs are the addresses a running proxy actually bound, which
// are not always the ones the config asked for: a config may say ":0"
// and mean "pick a port". Handed to run's ready callback so a caller
// that did not choose the ports can still reach them — which is what
// makes it possible to test the whole wiring rather than its pieces.
type runtimeAddrs struct {
	Listen     string
	Metrics    string
	Admin      string
	UnixSocket string
}

// run builds and operates the entire proxy: pools, listeners, HTTP
// surfaces, signal handling, and the ordered shutdown. It returns when
// ctx is cancelled, or earlier with an error if the process cannot be
// brought up.
//
// Everything here used to live in main(), where none of it could be
// tested: the failure modes ended in stdlog.Fatalf, the ports came from
// a config file, and the only way to stop it was a signal. Startup
// errors are now returned, the bound addresses are reported through
// ready, and cancelling ctx is the shutdown trigger — so a test can
// bring the real thing up on ephemeral ports, use it, and take it down.
//
// ready is called once, after every listener is bound and before the
// first client can be served. nil means nobody is interested.
func run(ctx context.Context, cfg *Config, configPath string, ready func(runtimeAddrs)) error {
	cancelDialTimeout = cfg.CancelDialTimeout

	eventLog := NewEventLog(50)

	promRegistry := prometheus.NewRegistry()
	promRegistry.MustRegister(collectors.NewGoCollector())
	promRegistry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := newProxyMetrics(promRegistry)

	// The pass-through store exists only when a pool asks for it, so a
	// deployment that does not use the feature never derives, and never
	// holds, any authentication material.
	var keyStore *clientKeyStore
	for _, pc := range cfg.Pools {
		if pc.ScramPassthrough {
			keyStore = newClientKeyStore()
			break
		}
	}

	poolRegistry := NewPoolRegistryWithDefaults(cfg.Pools, eventLog, cfg, func(name string) pool.ObserveWaitFunc {
		return metrics.observeAcquire(name)
	})
	poolRegistry.SetClientKeyStore(keyStore)
	// Only pass-through deployments create pools on demand, so only
	// they need something to take them back.
	if keyStore != nil {
		defer startPassthroughReaper(poolRegistry, cfg.ScramPassthroughIdleTimeout, metrics)()
	}
	promRegistry.MustRegister(newPoolsCollector(poolRegistry))
	// pgbouncer_exporter-compatible aliases: same underlying stats,
	// PgBouncer-named metrics so Grafana dashboards work unchanged.
	promRegistry.MustRegister(newPgbouncerCollector(poolRegistry))

	// Built here rather than next to the listener setup below because
	// the readiness probe needs the same draining flag the relay reads.
	opts := runtimeOptsFromConfig(cfg, metrics)

	metricsSrv := newMetricsServer(cfg, promRegistry, poolRegistry, &opts.draining)
	adminSrv, err := newAdminServer(ctx, cfg, configPath, poolRegistry, eventLog)
	if err != nil {
		return err
	}

	tlsConfig, tlsCert, err := buildDataPlaneTLS(cfg)
	if err != nil {
		return err
	}

	// Structured audit-log stream. Failures here are fatal — an
	// operator who set audit_log_path expects the file to exist.
	if err := setupAuditLog(cfg.AuditLogPath); err != nil {
		return fmt.Errorf("audit_log_path: %w", err)
	}

	authBackend, err := buildAuthBackend(cfg, keyStore, tlsCert)
	if err != nil {
		return err
	}

	router := NewDatabaseRouter(poolRegistry)
	limiter := newAuthLimiter()
	applyRuntimeLimits(cfg, opts, poolRegistry)

	// ---- Bind everything before serving anything ---------------------
	//
	// All three listeners are opened here, and a failure on any of them
	// aborts startup. The HTTP servers used to bind inside their own
	// goroutines via ListenAndServe, which meant an address already in
	// use logged an error somewhere behind a proxy that had already
	// announced itself as up — and then ran without the surface an
	// operator was relying on.
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// Closed by shutdown on the normal path; this covers the startup
	// failures below, where shutdown never runs.
	defer func() { closeListener(listener, "data plane") }()

	metricsLn, err := net.Listen("tcp", cfg.MetricsAddr)
	if err != nil {
		return fmt.Errorf("metrics listen: %w", err)
	}
	adminLn, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		_ = metricsLn.Close()
		return fmt.Errorf("admin listen: %w", err)
	}

	// Every accept loop holds a token in wg for its whole life, not just
	// its sessions.
	//
	// Without it the drain has a race it cannot win: the loop calls
	// wg.Add(1) for each connection it accepts, and shutdown calls
	// wg.Wait(). A connection accepted in the instant between the
	// listener closing and Wait observing a zero counter means Add runs
	// concurrently with Wait, which is documented misuse — the session
	// can be missed by the drain, and the runtime is entitled to panic.
	// A token held by the loop keeps the counter above zero for exactly
	// as long as another Add is still possible.
	//
	// The consequence is that shutdown must close every listener before
	// waiting, which is what it does.
	var wg sync.WaitGroup
	listeners := []net.Listener{listener}
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptLoopWithOpts(listener, router, authBackend, tlsConfig, limiter, &wg, opts)
	}()

	// Optional Unix-domain socket listener alongside TCP. Local
	// clients get lower overhead and — with HBA METHOD=peer —
	// SO_PEERCRED identity binding without a password exchange.
	var unixListener net.Listener
	var unixSockPath string
	if cfg.UnixSocketDir != "" {
		ul, path, err := openUnixSocket(cfg.UnixSocketDir, cfg.ListenAddr, cfg.UnixSocketMode)
		if err != nil {
			_ = metricsLn.Close()
			_ = adminLn.Close()
			return fmt.Errorf("unix socket: %w", err)
		}
		unixListener = ul
		unixSockPath = path
		listeners = append(listeners, ul)
		slog.Info("unix socket listening", "path", path, "mode", cfg.UnixSocketMode)
		// TLS makes no sense over a Unix socket — pass nil so the accept
		// loop doesn't offer SSLRequest.
		wg.Add(1)
		go func() {
			defer wg.Done()
			acceptLoopWithOpts(ul, router, authBackend, nil, limiter, &wg, opts)
		}()
	}
	// Ensure the socket file is removed on shutdown so subsequent
	// restarts don't hit ENOTCONN / EADDRINUSE. The listener itself is
	// closed by shutdown; closing it again here only matters on the
	// startup-failure paths, where shutdown never runs.
	defer func() {
		if unixListener != nil {
			closeListener(unixListener, "unix")
		}
		if unixSockPath != "" {
			_ = os.Remove(unixSockPath)
		}
	}()

	go func() {
		if err := metricsSrv.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server", "err", err)
		}
	}()
	go func() {
		// TLSConfig != nil ⇒ operator asked for HTTPS on the admin
		// listener. Passing "" for cert/key uses whatever's in
		// TLSConfig.Certificates (loaded by buildAdminTLSConfig).
		var srvErr error
		if adminSrv.TLSConfig != nil {
			srvErr = adminSrv.ServeTLS(adminLn, "", "")
		} else {
			srvErr = adminSrv.Serve(adminLn)
		}
		if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			slog.Error("admin server", "err", srvErr)
		}
	}()

	stopSighup := startConfigReloader(ctx, configPath, poolRegistry, metrics)
	defer stopSighup()

	slog.Info("pgman up",
		"version", version,
		"listen", listener.Addr().String(),
		"tls", tlsConfig != nil,
		"pools", len(poolRegistry.Names()),
		"metrics", metricsLn.Addr().String(),
		"admin", adminLn.Addr().String(),
		"max_client_conn", cfg.MaxClientConn,
		"query_wait_timeout", cfg.QueryWaitTimeout,
		"client_login_timeout", cfg.ClientLoginTimeout,
	)

	if ready != nil {
		ready(runtimeAddrs{
			Listen:     listener.Addr().String(),
			Metrics:    metricsLn.Addr().String(),
			Admin:      adminLn.Addr().String(),
			UnixSocket: unixSockPath,
		})
	}

	<-ctx.Done()
	return shutdown(cfg, listeners, metricsSrv, adminSrv, poolRegistry, opts, &wg)
}

// closeListener closes a listener once, treating "already closed" as the
// success it is: both the shutdown path and run's deferred cleanup can
// reach the same listener, and only one of them gets there first.
func closeListener(l net.Listener, what string) {
	if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		slog.Warn("shutdown: listener close", "listener", what, "err", err)
	}
}

// newMetricsServer builds the unauthenticated read-only listener:
// Prometheus scrapes and the two probes. They share it because the
// kubelet has no credentials and this is already the surface that
// answers without them.
func newMetricsServer(cfg *Config, promRegistry *prometheus.Registry, poolRegistry *PoolRegistry, draining *atomic.Bool) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /health", healthHandler())
	mux.HandleFunc("GET /ready", readyHandler(poolRegistry, draining))
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}
}

// newAdminServer builds the authenticated control plane: the dashboard,
// its SSE stream, the pool and session endpoints, and — only when asked
// for — pprof.
//
// ctx bounds the OIDC discovery round-trip, which is a real network call
// to a third party and must not be able to hang startup forever.
func newAdminServer(ctx context.Context, cfg *Config, configPath string, poolRegistry *PoolRegistry, eventLog *EventLog) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", indexHandler(poolRegistry, eventLog))
	// htmx and its SSE extension, compiled in rather than fetched from a
	// CDN — see web/static.go for why.
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /events", sseHandler(poolRegistry, eventLog))
	mux.HandleFunc("POST /reload", reloadHandler(configPath, poolRegistry))
	mux.HandleFunc("POST /pools", addPoolHandler(poolRegistry))
	mux.HandleFunc("POST /pools/{name}/resize", resizePoolHandler(poolRegistry))
	mux.HandleFunc("POST /pools/{name}/remove", removePoolHandler(poolRegistry))
	mux.HandleFunc("POST /pools/{name}/pause", pausePoolHandler(poolRegistry))
	mux.HandleFunc("POST /pools/{name}/resume", resumePoolHandler(poolRegistry))
	mux.HandleFunc("POST /pools/{name}/reconnect", reconnectPoolHandler(poolRegistry))
	mux.HandleFunc("POST /sessions/{pid}/cancel", cancelSessionHandler)

	if cfg.EnablePprof {
		// pprof is registered here so it inherits adminAuth below —
		// exposing a live heap dump publicly is a straightforward
		// pre-attack recon vector.
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	oidcCtx, oidcCancel := context.WithTimeout(ctx, 15*time.Second)
	oidcVerifier, err := buildOIDCVerifier(oidcCtx, cfg)
	oidcCancel()
	if err != nil {
		return nil, fmt.Errorf("admin oidc: %w", err)
	}
	if oidcVerifier != nil {
		slog.Info("admin: OIDC enabled", "issuer", cfg.AdminOIDCIssuerURL)
	}

	adminTLSConfig, err := buildAdminTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("admin tls: %w", err)
	}

	return &http.Server{
		Handler:           adminAuth(cfg, oidcVerifier, mux),
		TLSConfig:         adminTLSConfig, // nil unless AdminTLSCertFile is set
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		// WriteTimeout intentionally 0 — SSE streams hold the response
		// writer open for the whole subscription lifetime.
		WriteTimeout: 0,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}, nil
}

// buildDataPlaneTLS loads the certificate clients connect with, and the
// client-CA bundle if the deployment wants mutual TLS on the wire
// protocol. Returns (nil, nil, nil) when no certificate is configured,
// which is a valid — if plain-text — setup.
//
// The certificate is returned alongside the tls.Config because SCRAM
// channel binding needs the leaf to compute tls-server-end-point.
func buildDataPlaneTLS(cfg *Config) (*tls.Config, *tls.Certificate, error) {
	if cfg.TLSCertFile == "" {
		return nil, nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("tls: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	// Optional mTLS for data plane. Client cert is verified only if
	// presented — HBA rules decide whether the connection actually
	// needs one (METHOD=cert) or a password (METHOD=scram-sha-256).
	if cfg.TLSClientCAFile != "" {
		caPEM, err := os.ReadFile(cfg.TLSClientCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tls_client_ca_file: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, nil, fmt.Errorf("tls_client_ca_file: no valid PEM certs in %s", cfg.TLSClientCAFile)
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		slog.Info("data-plane mTLS enabled", "client_ca_file", cfg.TLSClientCAFile)
	}
	return tlsConfig, &cert, nil
}

// buildAuthBackend assembles the chain a client's credentials travel
// through: HBA rules on the outside if configured, then SCRAM (with an
// optional auth_query lookup behind it), or trust when the operator has
// explicitly asked for no authentication at all.
func buildAuthBackend(cfg *Config, keyStore *clientKeyStore, tlsCert *tls.Certificate) (AuthBackend, error) {
	var authBackend AuthBackend
	if len(cfg.AuthUsers) > 0 || cfg.AuthQueryDSN != "" {
		scramAuth, err := NewSCRAMAuth(cfg.AuthUsers, tlsCert)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		// Optional auth_query provider: on cache miss, SELECT the
		// SCRAM verifier from a live pg_shadow. Lets operators avoid
		// listing every user in YAML.
		if cfg.AuthQueryDSN != "" {
			provider := NewAuthQueryProvider(cfg.AuthQueryDSN, cfg.AuthQuery, cfg.AuthQueryCacheTTL)
			scramAuth.SetDynamicLookup(provider.Lookup)
			slog.Info("auth_query enabled",
				"dsn_host_hint", firstToken(cfg.AuthQueryDSN, "@"),
				"cache_ttl", cfg.AuthQueryCacheTTL)
		}
		scramAuth.SetClientKeyStore(keyStore)
		if keyStore != nil {
			slog.Info("scram pass-through enabled — backend connections are opened as the authenticated client",
				"note", "pgman holds a password-equivalent in memory for every user that logs in")
		}
		authBackend = scramAuth
	} else {
		slog.Warn("allow_insecure_trust_auth is set — every client is accepted without a password")
		authBackend = TrustAuth{}
	}

	// If an auth_hba_file is configured, gate every client through it.
	// Rules can accept (trust / scram-sha-256) or reject before we
	// even reach the base authBackend; scram-sha-256 delegates to the
	// SCRAM backend already built above. Empty file → HBAAuth returns
	// authBackend unchanged.
	if cfg.AuthHBAFile != "" {
		rules, err := LoadHBAFile(cfg.AuthHBAFile)
		if err != nil {
			return nil, fmt.Errorf("auth_hba_file: %w", err)
		}
		slog.Info("hba: loaded", "file", cfg.AuthHBAFile, "rules", len(rules))
		authBackend = NewHBAAuth(rules, authBackend)
	}
	return authBackend, nil
}

// applyRuntimeLimits wires the optional per-session gates onto opts:
// the admin console, per-database/user connection caps, and the
// session-open rate limiter. Each is off unless configured.
func applyRuntimeLimits(cfg *Config, opts *runtimeOpts, poolRegistry *PoolRegistry) {
	// Wire in the PgBouncer-compatible admin SQL handler. It closes
	// over poolRegistry so SHOW POOLS / PAUSE / RESUME reflect live
	// state (including pools added/resized via the HTTP admin).
	if opts.adminDatabase != "" {
		opts.adminSession = adminSessionHandler(poolRegistry)
	}
	if cfg.MaxDBConnections > 0 || cfg.MaxUserConnections > 0 {
		opts.connLimiter = NewConnLimiter(cfg.MaxDBConnections, cfg.MaxUserConnections)
		slog.Info("conn limits",
			"max_db_connections", cfg.MaxDBConnections,
			"max_user_connections", cfg.MaxUserConnections)
	}
	if cfg.MaxSessionsPerSecPerUser > 0 {
		burst := cfg.MaxSessionsBurstPerUser
		if burst <= 0 {
			burst = cfg.MaxSessionsPerSecPerUser
		}
		opts.userRateLimiter = NewRateLimiter(cfg.MaxSessionsPerSecPerUser, burst)
		slog.Info("per-user session rate limit",
			"rate_per_sec", cfg.MaxSessionsPerSecPerUser,
			"burst", burst)
	}
}

// startConfigReloader watches for SIGHUP and applies the config file to
// the live registry. Returns a function that stops watching.
//
// A separate channel from the shutdown signals on purpose: those are
// owned by signal.NotifyContext, and a reload delivered into the same
// channel would be indistinguishable from a request to exit.
func startConfigReloader(ctx context.Context, configPath string, poolRegistry *PoolRegistry, metrics *proxyMetrics) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	// Stopping goes through its own channel rather than by closing ch,
	// which was wrong twice over: a receive from a closed channel is
	// always ready, so the loop would spin re-reading the config file as
	// fast as it could, and a signal delivered while it is closed makes
	// the runtime send on a closed channel and panic.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ch:
				slog.Info("SIGHUP received: reloading config", "path", configPath)
				result, err := applyConfigReload(configPath, poolRegistry)
				metrics.observeConfigReload(result, err)
				if err != nil {
					slog.Error("SIGHUP reload failed", "err", err)
					continue
				}
				slog.Info("SIGHUP reload applied",
					"added", result.Added,
					"removed", result.Removed,
					"reconfigured", result.Reconfigured,
					"unchanged", result.Unchanged)
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(stop)
		<-done
	}
}

// shutdown runs the ordered drain. The order is the point: each step
// exists because doing it later would abort work that could have
// finished.
//
// Returns errDrainIncomplete when the budget expired with sessions still
// running, so the caller can exit non-zero — that is how k8s and systemd
// find out this instance did not drain in time.
func shutdown(
	cfg *Config,
	listeners []net.Listener,
	metricsSrv, adminSrv *http.Server,
	poolRegistry *PoolRegistry,
	opts *runtimeOpts,
	wg *sync.WaitGroup,
) error {
	shutdownDeadline := cfg.ShutdownTimeout
	slog.Info("shutdown: signal received — pausing pools and draining active sessions", "timeout", shutdownDeadline)

	// Step 1: Stop accepting new connections — every listener, not just
	// the TCP one, because each accept loop holds a WaitGroup token that
	// the drain in step 4 waits on. Existing accepted handleConn
	// goroutines keep running: their sessions must be allowed to
	// complete cleanly.
	// Unblocks acceptLoop's Accept() with net.ErrClosed.
	for _, l := range listeners {
		closeListener(l, l.Addr().Network())
	}

	// Step 2: Mark the data plane as draining. Sessions currently
	// inside a transaction keep their backend and finish normally;
	// sessions between transactions are closed with 57P01 the moment
	// they ask for a backend, so they reconnect elsewhere instead of
	// waiting out query_wait_timeout on a pause gate.
	opts.draining.Store(true)

	// Step 3: Shut the admin & metrics HTTP servers with the same
	// deadline. They're independent of client sessions but should
	// obey the operator's shutdown budget too.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownDeadline)
	defer cancel()
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown: metrics server", "err", err)
	}
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("shutdown: admin server", "err", err)
	}

	// Step 4: Wait for accepted client goroutines to finish. Every
	// handleConn tracks itself on wg, so wg.Wait() drains exactly
	// once each active session has returned.
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()

	cleanExit := true
	select {
	case <-drained:
		slog.Info("shutdown: all sessions drained cleanly")
	case <-time.After(shutdownDeadline):
		slog.Warn("shutdown: timeout reached, forcing exit", "timeout", shutdownDeadline)
		cleanExit = false
	}

	// Step 5: Close every pool. This closes idle backend conns and
	// returns ErrPoolClosed to anything still parked. Wait a short
	// grace period per pool — Close blocks on in-flight release.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), poolCloseGrace)
	defer closeCancel()
	for _, name := range poolRegistry.Names() {
		if p, ok := poolRegistry.Get(name); ok {
			if err := p.Close(closeCtx); err != nil {
				slog.Warn("shutdown: pool close", "pool", name, "err", err)
			}
		}
	}

	if cleanExit {
		return nil
	}
	// Closing the pools handed ErrPoolClosed to every Acquire still
	// parked, so the sessions that made us miss the deadline are
	// now unwinding. Give them a brief window to actually return
	// before the process dies — without this second wait we exit
	// while handleConn goroutines are still mid-teardown, which
	// looks to the client like a reset rather than a close.
	select {
	case <-drained:
		slog.Warn("shutdown: sessions drained only after pools were force-closed",
			"timeout", shutdownDeadline)
	case <-time.After(poolCloseGrace):
		slog.Warn("shutdown: sessions still active after pool close, exiting anyway")
	}
	return errDrainIncomplete
}

// poolCloseGrace bounds the two post-deadline shutdown steps: draining
// in-flight releases inside Pool.Close, and the final wait for session
// goroutines to unwind afterwards.
const poolCloseGrace = 5 * time.Second

// slogWriter bridges stdlib log writes into slog at Info level. Kept
// tiny — we only need to convert "log.Print" into structured events.
type slogWriter struct{}

func (slogWriter) Write(p []byte) (int, error) {
	msg := string(p)
	// Trim trailing newline the stdlib log package always appends.
	if n := len(msg); n > 0 && msg[n-1] == '\n' {
		msg = msg[:n-1]
	}
	slog.Info(msg, "source", "stdlib_log")
	return len(p), nil
}

// acceptLoop is the pre-existing test entry point; it delegates to
// acceptLoopWithOpts with permissive defaults so existing tests keep
// working without change.
func acceptLoop(listener net.Listener, router Router, authBackend AuthBackend, tlsConfig *tls.Config, limiter *authLimiter, wg *sync.WaitGroup) {
	acceptLoopWithOpts(listener, router, authBackend, tlsConfig, limiter, wg, defaultRuntimeOpts())
}

// acceptLoopWithOpts accepts connections until listener is closed,
// enforcing max_client_conn via the semaphore in opts (nil = unlimited)
// and tagging every accepted conn with TCP keepalive when tcpKeepAlive
// > 0. Every handleConn goroutine is tracked in wg so main can wait for
// in-flight sessions to finish instead of cutting them off
// mid-transaction.
//
// The semaphore comes from opts and is shared with every other accept
// loop in the process: max_client_conn caps the proxy, not each
// listener it happens to be running.
func acceptLoopWithOpts(listener net.Listener, router Router, authBackend AuthBackend, tlsConfig *tls.Config, limiter *authLimiter, wg *sync.WaitGroup, opts *runtimeOpts) {
	sem := opts.clientSlots

	for {
		client, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return // expected: main closed the listener for shutdown
			}
			slog.Warn("accept", "err", err)
			continue
		}

		if opts.metrics != nil {
			opts.metrics.ClientConnTotal.Inc()
		}

		// TCP keepalive on the accepted socket so a peer that vanished
		// (VM reset, cable pull) doesn't linger as a live goroutine
		// until the OS TCP FIN-timeout fires an hour later.
		if opts.tcpKeepAlive > 0 {
			if tc, ok := client.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(opts.tcpKeepAlive)
			}
		}

		// max_client_conn: try to reserve a slot. If none is available,
		// reject synchronously (fast, non-blocking, non-queuing) — a
		// queue would just move the OOM one hop over.
		if sem != nil {
			select {
			case sem <- struct{}{}:
			default:
				if opts.metrics != nil {
					opts.metrics.MaxConnRejected.Inc()
				}
				slog.Warn("max_client_conn reached, rejecting", "remote", client.RemoteAddr())
				_ = client.Close()
				continue
			}
		}

		wg.Add(1)
		if opts.metrics != nil {
			opts.metrics.ClientConnActive.Inc()
		}
		go func() {
			defer wg.Done()
			defer func() {
				if opts.metrics != nil {
					opts.metrics.ClientConnActive.Dec()
				}
			}()
			if sem != nil {
				defer func() { <-sem }()
			}
			handleConnWithOpts(client, router, authBackend, tlsConfig, limiter, opts)
		}()
	}
}

// newDialBackend builds a pool.Dialer bound to one pool's own DSN and
// address — each configured pool gets its own dialer, since different
// pools may point at entirely different real Postgres instances.
//
// Backend TLS: fully delegated to pgconn.Connect via the DSN's
// sslmode / sslrootcert / sslcert / sslkey / sslpassword params (the
// standard libpq surface). Values:
//
//	disable      — no TLS. Rejected here if requireTLS is true.
//	allow/prefer — try TLS, fall back to plain. Also rejected under requireTLS.
//	require      — TLS is mandatory; server cert not verified.
//	verify-ca    — TLS + verify cert against sslrootcert (or system store).
//	verify-full  — verify-ca + hostname match. This is what RDS docs recommend.
//
// After pgconn's TLS handshake completes, Hijack() returns the
// already-encrypted *tls.Conn — from that point on every Send/Receive
// through the pool is TLS-wrapped end-to-end. No further plumbing here.
func newDialBackend(dsn, addr string, requireTLS bool) pool.Dialer {
	// Parse once at construction so a busted DSN fails at pool creation,
	// not on the first client query. Also lets us fast-fail requireTLS
	// before any dial round-trip is spent.
	parsed, parseErr := pgconn.ParseConfig(dsn)
	if parseErr == nil && requireTLS {
		if !dsnRequiresTLS(parsed, dsn) {
			parseErr = fmt.Errorf("require_backend_tls=true but DSN sslmode is not require/verify-ca/verify-full")
		}
	}

	return func(ctx context.Context) (net.Conn, error) {
		if parseErr != nil {
			return nil, parseErr
		}
		pc, err := pgconn.Connect(ctx, dsn)
		if err != nil {
			return nil, fmt.Errorf("connect: %w", err)
		}
		// v5's Hijack contract requires SyncConn first so pgconn's
		// internal state matches the wire state before we take over —
		// omitting it can leave partially-consumed buffers behind that
		// then desynchronise the first message we send through the
		// hijacked socket.
		if err := pc.SyncConn(ctx); err != nil {
			_ = pc.Close(ctx)
			return nil, fmt.Errorf("sync: %w", err)
		}
		hijacked, err := pc.Hijack()
		if err != nil {
			return nil, fmt.Errorf("hijack: %w", err)
		}
		cancelTLS, err := cancelTLSConfigFor(hijacked.Conn, parsed)
		if err != nil {
			_ = hijacked.Conn.Close()
			return nil, err
		}
		return &backendConn{
			Conn: hijacked.Conn,
			addr: addr,
			pid:  hijacked.PID,
			// v5's SecretKey is already []byte; the type change ripples
			// through backendConn/session/sendRealCancelRequest.
			secretKey: hijacked.SecretKey,
			cancelTLS: cancelTLS,
		}, nil
	}
}

// cancelTLSConfigFor decides how a later CancelRequest for this backend
// must be dialed. A cancel needs its own connection, so it has to repeat
// whatever transport the original one negotiated.
//
// The established connection is the authority, not the DSN: sslmode
// values like "prefer" decide per attempt, and only the resulting
// net.Conn says which way it went. Returns nil for a plaintext backend.
func cancelTLSConfigFor(conn net.Conn, parsed *pgconn.Config) (*tls.Config, error) {
	if _, isTLS := conn.(*tls.Conn); !isTLS {
		return nil, nil
	}
	if parsed == nil || parsed.TLSConfig == nil {
		// The connection is encrypted but we cannot reconstruct how.
		// Failing the dial is the only honest option: handing back a
		// backend whose cancels are silently impossible is exactly the
		// bug this field exists to fix, and falling back to a plaintext
		// cancel would put the cancel key on the wire in the clear.
		return nil, fmt.Errorf("backend negotiated TLS but the DSN exposes no TLS config to reuse for cancel requests")
	}
	return parsed.TLSConfig, nil
}

// firstToken returns everything after the last occurrence of sep in s
// (empty if sep not present) — used only for log-friendly DSN redaction
// where we want to hint at the host without leaking credentials.
func firstToken(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// dsnRequiresTLS returns true when the DSN specifies an sslmode that
// mandates TLS (require, verify-ca, verify-full). "prefer" and "allow"
// are considered non-mandatory because they silently accept a plain
// connection if the server refuses TLS — that's the exact hole
// require_backend_tls exists to close.
func dsnRequiresTLS(cfg *pgconn.Config, dsn string) bool {
	// pgconn.Config exposes TLSConfig + Fallbacks; a strict sslmode
	// means len(Fallbacks) == 0. This is the most robust check.
	if cfg != nil && cfg.TLSConfig != nil && len(cfg.Fallbacks) == 0 {
		return true
	}
	// Belt-and-braces: string sniff for explicit sslmode= override.
	// pgconn's structural check is authoritative; this fires only if
	// somebody uses a wrapper that changes Fallbacks semantics.
	lower := strings.ToLower(dsn)
	return strings.Contains(lower, "sslmode=require") ||
		strings.Contains(lower, "sslmode=verify-ca") ||
		strings.Contains(lower, "sslmode=verify-full")
}

// defaultHealthCheckTimeout is the deadline used when no config is
// available (tests, and the permissive defaultRuntimeOpts path).
const defaultHealthCheckTimeout = 500 * time.Millisecond

// healthCheck runs a lightweight SELECT 1 round-trip on an idle pooled
// connection. Called only when the pool decides the conn is stale
// enough to be worth checking (see server_check_delay in pool.Pool).
func healthCheck(conn net.Conn) error {
	return healthCheckWithTimeout(conn, defaultHealthCheckTimeout)
}

func healthCheckWithTimeout(conn net.Conn, timeout time.Duration) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		return fmt.Errorf("send: %w", err)
	}

	for {
		msg, err := fe.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("backend error: %s", m.Message)
		case *pgproto3.ReadyForQuery:
			return nil
		}
	}
}

// handleConn is the pre-existing test entry — permissive defaults.
func handleConn(client net.Conn, router Router, authBackend AuthBackend, tlsConfig *tls.Config, limiter *authLimiter) {
	handleConnWithOpts(client, router, authBackend, tlsConfig, limiter, defaultRuntimeOpts())
}

func handleConnWithOpts(client net.Conn, router Router, authBackend AuthBackend, tlsConfig *tls.Config, limiter *authLimiter, opts *runtimeOpts) {
	// Closure, not `defer client.Close()`: receiveStartupMessage may
	// rebind client to a *tls.Conn wrapping the original on SSL
	// upgrade. A plain `defer client.Close()` would capture today's
	// pre-upgrade value and skip a clean TLS close_notify.
	defer func() { _ = client.Close() }()

	// client_login_timeout: bound the whole startup + auth handshake.
	// Cleared on success so relay's per-message I/O isn't affected;
	// left in place on early-return paths so a stalled attacker's
	// socket is torn down at the deadline.
	if opts.clientLoginTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(opts.clientLoginTimeout))
	}

	pg := pgproto3.NewBackend(client, newClientWriter(client, opts.clientWriteTimeout))

	// Don't overwrite client on error — receiveStartupMessage returns
	// a nil conn on failure, and the outer `defer client.Close()` would
	// then panic on a nil-interface call. Reassign only on success,
	// which also handles the SSL upgrade path (client → *tls.Conn).
	msg, upgradedClient, upgradedPG, err := receiveStartupMessage(pg, client, tlsConfig, opts.clientWriteTimeout)
	if err != nil {
		slog.Info("startup: aborted", "err", err)
		if opts.metrics != nil {
			opts.metrics.ClientLoginFail.WithLabelValues("startup").Inc()
		}
		return
	}
	client, pg = upgradedClient, upgradedPG

	switch m := msg.(type) {
	case *pgproto3.CancelRequest:
		handleCancelRequest(m)

	case *pgproto3.StartupMessage:
		remoteHost, _, _ := net.SplitHostPort(client.RemoteAddr().String())
		if !limiter.Allowed(remoteHost) {
			slog.Warn("startup: rate-limited",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"remote", remoteHost)
			pg.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "28000",
				Message:  "too many failed authentication attempts — try again later",
			})
			_ = pg.Flush()
			if opts.metrics != nil {
				opts.metrics.ClientLoginFail.WithLabelValues("rate_limited").Inc()
			}
			return
		}

		if err := authBackend.Authenticate(pg, client, m); err != nil {
			limiter.RecordFailure(remoteHost)
			slog.Info("startup: auth rejected",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"err", err)
			pg.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "28P01",
				Message:  "password authentication failed",
			})
			_ = pg.Flush()
			if opts.metrics != nil {
				opts.metrics.ClientLoginFail.WithLabelValues("auth").Inc()
			}
			auditLog("auth_fail",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"remote", remoteHost,
				"err", err.Error())
			return
		}
		limiter.RecordSuccess(remoteHost)

		// Per-user session-open rate limiting — applied only AFTER
		// successful auth so bogus/probing attempts don't burn tokens
		// for a legitimate user's key.
		if opts.userRateLimiter != nil && !opts.userRateLimiter.Allow(m.Parameters["user"]) {
			slog.Info("startup: rate limited", "user", m.Parameters["user"], "remote", remoteHost)
			pg.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "53400", // configuration_limit_exceeded
				Message:  "session open rate limit exceeded for user",
			})
			_ = pg.Flush()
			auditLog("rate_limit_reject",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"remote", remoteHost)
			return
		}

		// PgBouncer-style admin SQL: when the client connects to the
		// virtual admin database, don't route — run our in-process
		// SHOW / PAUSE / RESUME / RECONNECT handler and never touch a
		// real Postgres.
		//
		// Passing client auth is NOT enough to get in here. The console
		// can PAUSE every pool (a total outage issued by any tenant)
		// and SHOW CLIENTS lists every other tenant's user/database, so
		// it needs its own allowlist on top — PgBouncer's admin_users.
		if opts.adminDatabase != "" && m.Parameters["database"] == opts.adminDatabase {
			if opts.adminSession != nil && opts.adminUsers[m.Parameters["user"]] {
				slog.Info("startup: admin session",
					"user", m.Parameters["user"],
					"database", m.Parameters["database"])
				if opts.metrics != nil {
					opts.metrics.ClientLoginOK.Inc()
				}
				pid, sess := registerSession(m.Parameters["user"], m.Parameters["database"])
				defer deregisterSession(pid)
				if err := fakeAuth(pg, pid, sess.secret); err != nil {
					slog.Warn("admin: fake auth", "err", err)
					return
				}
				if opts.clientLoginTimeout > 0 {
					_ = client.SetDeadline(time.Time{})
				}
				opts.adminSession(pg)
				return
			}
			// Not authorised. Deliberately no distinct error: fall
			// through to routing, which answers exactly as it would for
			// any other unconfigured database name. A dedicated
			// "not an admin" reply would confirm the console exists and
			// hand an attacker a probe for which users are admins.
			slog.Warn("startup: admin console denied",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"reason", "user is not listed in admin_users")
			auditLog("admin_denied",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"])
		}

		decision, err := router.Route(m)
		if err != nil {
			slog.Info("startup: routing rejected",
				"user", m.Parameters["user"],
				"database", m.Parameters["database"],
				"err", err)
			pg.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "3D000",
				Message:  err.Error(),
			})
			_ = pg.Flush()
			if opts.metrics != nil {
				opts.metrics.ClientLoginFail.WithLabelValues("routing").Inc()
			}
			return
		}
		slog.Info("startup: authenticated",
			"user", m.Parameters["user"],
			"database", m.Parameters["database"])

		// Per-user / per-db connection caps — enforce BEFORE we
		// register the session so a cap-rejected connection isn't
		// visible in SHOW CLIENTS / cancel-request handling.
		if opts.connLimiter != nil {
			if err := opts.connLimiter.Reserve(m.Parameters["user"], m.Parameters["database"]); err != nil {
				slog.Info("startup: connection-limit rejected",
					"user", m.Parameters["user"],
					"database", m.Parameters["database"],
					"err", err)
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "53300", // too_many_connections
					Message:  err.Error(),
				})
				_ = pg.Flush()
				if opts.metrics != nil {
					opts.metrics.ClientLoginFail.WithLabelValues("conn_limit").Inc()
				}
				auditLog("conn_limit_reject",
					"user", m.Parameters["user"],
					"database", m.Parameters["database"],
					"err", err.Error())
				return
			}
			defer opts.connLimiter.Release(m.Parameters["user"], m.Parameters["database"])
		}

		if opts.metrics != nil {
			opts.metrics.ClientLoginOK.Inc()
		}

		pid, sess := registerSession(m.Parameters["user"], m.Parameters["database"])
		defer deregisterSession(pid)

		if err := fakeAuth(pg, pid, sess.secret); err != nil {
			slog.Warn("fake auth", "err", err)
			return
		}

		// Handshake complete — clear the login deadline for the
		// long-lived relay loop.
		if opts.clientLoginTimeout > 0 {
			_ = client.SetDeadline(time.Time{})
		}

		sess.poolMode = decision.PoolMode
		if sess.poolMode == "" {
			sess.poolMode = "transaction"
		}
		sess.poolName = decision.PoolName
		if sess.poolName == "" {
			sess.poolName = sess.database
		}
		sess.psLimit = opts.maxPreparedStmts
		sess.metrics = opts.metrics
		sess.trackedParams = extractTrackedParams(m.Parameters, opts.trackExtraParams)
		relay(client, pg, decision.Pool, sess, opts)
	}
}

// receiveStartupMessage reads until StartupMessage or CancelRequest.
// On SSLRequest with tls configured, performs the TLS handshake in
// place and returns the upgraded connection.
//
// writeTimeout is the client_write_timeout the returned Backend must
// write under; it has to be passed in rather than read from a global
// because the TLS branch builds a second Backend over the upgraded
// connection, and a Backend built without the bound would leave every
// TLS session's writes unbounded.
func receiveStartupMessage(pg *pgproto3.Backend, client net.Conn, tlsConfig *tls.Config, writeTimeout time.Duration) (msg pgproto3.FrontendMessage, conn net.Conn, out *pgproto3.Backend, err error) {
	conn, out = client, pg
	for {
		m, err := out.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("receive: %w", err)
		}

		switch v := m.(type) {
		case *pgproto3.StartupMessage, *pgproto3.CancelRequest:
			return m, conn, out, nil

		case *pgproto3.SSLRequest:
			if tlsConfig == nil {
				if _, err := conn.Write([]byte{'N'}); err != nil {
					return nil, nil, nil, fmt.Errorf("reject ssl: %w", err)
				}
				continue
			}
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return nil, nil, nil, fmt.Errorf("accept ssl: %w", err)
			}
			tlsConn := tls.Server(conn, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return nil, nil, nil, fmt.Errorf("tls handshake: %w", err)
			}
			conn = tlsConn
			out = pgproto3.NewBackend(conn, newClientWriter(conn, writeTimeout))

		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return nil, nil, nil, fmt.Errorf("reject gss: %w", err)
			}

		default:
			return nil, nil, nil, fmt.Errorf("unsupported startup message: %T", v)
		}
	}
}

// fakeAuth simulates a Postgres server handshake without touching a
// real backend. Whether this client is allowed to connect was already
// decided by AuthBackend before this is called.
//
// secret is []byte (v5's BackendKeyData.SecretKey type — Postgres 18
// lengthened cancel-key material past the historic 4 bytes and
// pgproto3 v5 exposes it as raw bytes). We generate 4-byte secrets in
// registerSession so libpq clients on any Postgres version continue to
// interoperate.
func fakeAuth(pg *pgproto3.Backend, pid uint32, secret []byte) error {
	messages := []pgproto3.BackendMessage{
		&pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0 (pgman)"},
		&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
		&pgproto3.ParameterStatus{Name: "DateStyle", Value: "ISO, MDY"},
		&pgproto3.ParameterStatus{Name: "TimeZone", Value: "UTC"},
		&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"},
		&pgproto3.BackendKeyData{ProcessID: pid, SecretKey: secret},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	}

	for _, m := range messages {
		pg.Send(m) // v5: Send buffers, Flush surfaces the actual write error
	}
	return pg.Flush()
}
