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
	serverResetQuery       string
	maxClientConn          int
	metrics                *proxyMetrics // nil in tests — every observe call must nil-check first

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
	return &runtimeOpts{
		clientLoginTimeout: cfg.ClientLoginTimeout,
		queryWaitTimeout:   cfg.QueryWaitTimeout,
		tcpKeepAlive:       cfg.TCPKeepAlive,
		healthCheckTimeout: cfg.HealthCheckTimeout,

		queryTimeout:           cfg.QueryTimeout,
		clientIdleTimeout:      cfg.ClientIdleTimeout,
		idleTransactionTimeout: cfg.IdleTransactionTimeout,

		serverResetQuery: cfg.ServerResetQuery,
		maxClientConn:    cfg.MaxClientConn,
		maxPreparedStmts: cfg.MaxPreparedStatements,
		metrics:          metrics,
		adminDatabase:    cfg.AdminDatabase,
		adminUsers:       adminUserSet(cfg.AdminUsers),
		trackExtraParams: cfg.TrackExtraParameters,
		// adminSession is wired up by main() where the registry is
		// available. Left nil here so plain runtimeOptsFromConfig
		// callers (tests) don't accidentally enable admin SQL without
		// providing a registry.
	}
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
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	genVerifierFor := flag.String("gen-scram-verifier", "", "print a SCRAM-SHA-256 verifier for this password (for auth_users in config.yaml) and exit")
	genAdminPassword := flag.String("gen-admin-password", "", "print a bcrypt hash for this admin password (for admin_basic_auth_password_hash in config.yaml) and exit")
	flag.Parse()

	if *genVerifierFor != "" {
		verifier, err := GenerateSCRAMVerifier(*genVerifierFor, 4096)
		if err != nil {
			stdlog.Fatalf("generate verifier: %v", err)
		}
		fmt.Println(verifier)
		return
	}
	if *genAdminPassword != "" {
		hash, err := generateAdminPasswordHash(*genAdminPassword)
		if err != nil {
			stdlog.Fatalf("generate admin password hash: %v", err)
		}
		fmt.Println(hash)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		stdlog.Fatalf("config: %v", err)
	}

	setupLogging(cfg.LogFormat, cfg.LogLevel)

	// Route the standard log package through slog, so any leftover
	// log.Printf calls in dependencies land in structured output too.
	stdlog.SetFlags(0)
	stdlog.SetOutput(slogWriter{})

	cancelDialTimeout = 5 * time.Second // could be config; keep constant for now

	eventLog := NewEventLog(50)

	promRegistry := prometheus.NewRegistry()
	promRegistry.MustRegister(collectors.NewGoCollector())
	promRegistry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := newProxyMetrics(promRegistry)

	poolRegistry := NewPoolRegistryWithDefaults(cfg.Pools, eventLog, cfg, func(name string) pool.ObserveWaitFunc {
		return metrics.observeAcquire(name)
	})
	promRegistry.MustRegister(newPoolsCollector(poolRegistry))
	// pgbouncer_exporter-compatible aliases: same underlying stats,
	// PgBouncer-named metrics so Grafana dashboards work unchanged.
	promRegistry.MustRegister(newPgbouncerCollector(poolRegistry))

	// Built here rather than next to the listener setup below because
	// the readiness probe needs the same draining flag the relay reads.
	opts := runtimeOptsFromConfig(cfg, metrics)

	// ---- HTTP servers: metrics (public, GET-only) vs admin (auth) ----
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{}))
	// Probes share the metrics listener: the kubelet has no credentials,
	// and this listener is already the unauthenticated read-only surface.
	metricsMux.HandleFunc("GET /health", healthHandler())
	metricsMux.HandleFunc("GET /ready", readyHandler(poolRegistry, &opts.draining))
	metricsSrv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           metricsMux,
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		WriteTimeout:      cfg.HTTPWriteTimeout,
		IdleTimeout:       cfg.HTTPIdleTimeout,
	}

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /", indexHandler(poolRegistry, eventLog))
	adminMux.HandleFunc("GET /events", sseHandler(poolRegistry, eventLog))
	adminMux.HandleFunc("POST /reload", reloadHandler(*configPath, poolRegistry))
	adminMux.HandleFunc("POST /pools", addPoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /pools/{name}/resize", resizePoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /pools/{name}/remove", removePoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /pools/{name}/pause", pausePoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /pools/{name}/resume", resumePoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /pools/{name}/reconnect", reconnectPoolHandler(poolRegistry))
	adminMux.HandleFunc("POST /sessions/{pid}/cancel", cancelSessionHandler)

	if cfg.EnablePprof {
		// pprof is registered here so it inherits adminAuth below —
		// exposing a live heap dump publicly is a straightforward
		// pre-attack recon vector.
		adminMux.HandleFunc("/debug/pprof/", pprof.Index)
		adminMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		adminMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		adminMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		adminMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	// OIDC discovery is a real network round-trip — bound it with a
	// 15s ctx so a broken IDP doesn't hang startup indefinitely.
	oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 15*time.Second)
	oidcVerifier, err := buildOIDCVerifier(oidcCtx, cfg)
	oidcCancel()
	if err != nil {
		stdlog.Fatalf("admin oidc: %v", err)
	}
	if oidcVerifier != nil {
		slog.Info("admin: OIDC enabled", "issuer", cfg.AdminOIDCIssuerURL)
	}

	adminTLSConfig, err := buildAdminTLSConfig(cfg)
	if err != nil {
		stdlog.Fatalf("admin tls: %v", err)
	}

	adminSrv := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           adminAuth(cfg, oidcVerifier, adminMux),
		TLSConfig:         adminTLSConfig, // nil unless AdminTLSCertFile is set
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout,
		ReadTimeout:       cfg.HTTPReadTimeout,
		// WriteTimeout intentionally 0 — SSE streams hold the response
		// writer open for the whole subscription lifetime.
		WriteTimeout: 0,
		IdleTimeout:  cfg.HTTPIdleTimeout,
	}

	// ---- Data plane -------------------------------------------------

	var tlsConfig *tls.Config
	var tlsCert *tls.Certificate
	if cfg.TLSCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			stdlog.Fatalf("tls: %v", err)
		}
		tlsCert = &cert
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		// Optional mTLS for data plane. Client cert is verified only if
		// presented — HBA rules decide whether the connection actually
		// needs one (METHOD=cert) or a password (METHOD=scram-sha-256).
		if cfg.TLSClientCAFile != "" {
			caPEM, err := os.ReadFile(cfg.TLSClientCAFile)
			if err != nil {
				stdlog.Fatalf("tls_client_ca_file: %v", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				stdlog.Fatalf("tls_client_ca_file: no valid PEM certs in %s", cfg.TLSClientCAFile)
			}
			tlsConfig.ClientCAs = pool
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			slog.Info("data-plane mTLS enabled", "client_ca_file", cfg.TLSClientCAFile)
		}
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		stdlog.Fatalf("listen: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP triggers a safe subset config reload (add/remove pools).
	// Kept on a separate channel so a shutdown signal (SIGINT/TERM)
	// doesn't get eaten as a reload — signal.NotifyContext already owns
	// those two.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			slog.Info("SIGHUP received: reloading config", "path", *configPath)
			result, err := applyConfigReload(*configPath, poolRegistry)
			if err != nil {
				slog.Error("SIGHUP reload failed", "err", err)
				continue
			}
			slog.Info("SIGHUP reload applied",
				"added", result.Added,
				"removed", result.Removed,
				"unchanged", result.Unchanged)
		}
	}()

	// Structured audit-log stream. Failures here are fatal — an
	// operator who set audit_log_path expects the file to exist.
	if err := setupAuditLog(cfg.AuditLogPath); err != nil {
		stdlog.Fatalf("audit_log_path: %v", err)
	}

	router := NewDatabaseRouter(poolRegistry)

	var authBackend AuthBackend
	if len(cfg.AuthUsers) > 0 || cfg.AuthQueryDSN != "" {
		scramAuth, err := NewSCRAMAuth(cfg.AuthUsers, tlsCert)
		if err != nil {
			stdlog.Fatalf("auth: %v", err)
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
			stdlog.Fatalf("auth_hba_file: %v", err)
		}
		slog.Info("hba: loaded", "file", cfg.AuthHBAFile, "rules", len(rules))
		authBackend = NewHBAAuth(rules, authBackend)
	}

	limiter := newAuthLimiter()
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

	var wg sync.WaitGroup
	go acceptLoopWithOpts(listener, router, authBackend, tlsConfig, limiter, &wg, opts)

	// Optional Unix-domain socket listener alongside TCP. Local
	// clients get lower overhead and — with HBA METHOD=peer —
	// SO_PEERCRED identity binding without a password exchange.
	var unixListener net.Listener
	var unixSockPath string
	if cfg.UnixSocketDir != "" {
		ul, path, err := openUnixSocket(cfg.UnixSocketDir, cfg.ListenAddr, cfg.UnixSocketMode)
		if err != nil {
			stdlog.Fatalf("unix socket: %v", err)
		}
		unixListener = ul
		unixSockPath = path
		slog.Info("unix socket listening", "path", path, "mode", cfg.UnixSocketMode)
		// TLS makes no sense over a Unix socket — pass nil so the accept
		// loop doesn't offer SSLRequest.
		go acceptLoopWithOpts(ul, router, authBackend, nil, limiter, &wg, opts)
	}
	// Ensure the socket file is removed on shutdown so subsequent
	// restarts don't hit ENOTCONN / EADDRINUSE.
	defer func() {
		if unixListener != nil {
			if err := unixListener.Close(); err != nil {
				slog.Warn("shutdown: unix listener close", "err", err)
			}
		}
		if unixSockPath != "" {
			_ = os.Remove(unixSockPath)
		}
	}()
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server", "err", err)
		}
	}()
	go func() {
		// TLSConfig != nil ⇒ operator asked for HTTPS on the admin
		// listener. Passing "" for cert/key uses whatever's in
		// TLSConfig.Certificates (loaded by buildAdminTLSConfig).
		var srvErr error
		if adminSrv.TLSConfig != nil {
			srvErr = adminSrv.ListenAndServeTLS("", "")
		} else {
			srvErr = adminSrv.ListenAndServe()
		}
		if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			slog.Error("admin server", "err", srvErr)
		}
	}()

	slog.Info("pgman up",
		"listen", cfg.ListenAddr,
		"tls", tlsConfig != nil,
		"pools", len(poolRegistry.Names()),
		"metrics", cfg.MetricsAddr,
		"admin", cfg.AdminAddr,
		"max_client_conn", cfg.MaxClientConn,
		"query_wait_timeout", cfg.QueryWaitTimeout,
		"client_login_timeout", cfg.ClientLoginTimeout,
	)

	<-ctx.Done()
	shutdownDeadline := cfg.ShutdownTimeout
	slog.Info("shutdown: signal received — pausing pools and draining active sessions", "timeout", shutdownDeadline)

	// Step 1: Stop accepting new connections. Existing accepted
	// handleConn goroutines keep running — their sessions must be
	// allowed to complete cleanly.
	// Unblocks acceptLoop's Accept() with net.ErrClosed.
	if err := listener.Close(); err != nil {
		slog.Warn("shutdown: listener close", "err", err)
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

	if !cleanExit {
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
		// Non-zero exit code lets k8s / systemd / operators observe
		// that this instance did not drain in time and surface it in
		// termination logs.
		os.Exit(1)
	}
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
// enforcing max_client_conn via a semaphore (0 = unlimited) and tagging
// every accepted conn with TCP keepalive when tcpKeepAlive > 0. Every
// handleConn goroutine is tracked in wg so main can wait for in-flight
// sessions to finish instead of cutting them off mid-transaction.
func acceptLoopWithOpts(listener net.Listener, router Router, authBackend AuthBackend, tlsConfig *tls.Config, limiter *authLimiter, wg *sync.WaitGroup, opts *runtimeOpts) {
	var sem chan struct{}
	if opts.maxClientConn > 0 {
		sem = make(chan struct{}, opts.maxClientConn)
	}

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
		return &backendConn{
			Conn: hijacked.Conn,
			addr: addr,
			pid:  hijacked.PID,
			// v5's SecretKey is already []byte; the type change ripples
			// through backendConn/session/sendRealCancelRequest.
			secretKey: hijacked.SecretKey,
		}, nil
	}
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

	pg := pgproto3.NewBackend(client, client)

	// Don't overwrite client on error — receiveStartupMessage returns
	// a nil conn on failure, and the outer `defer client.Close()` would
	// then panic on a nil-interface call. Reassign only on success,
	// which also handles the SSL upgrade path (client → *tls.Conn).
	msg, upgradedClient, upgradedPG, err := receiveStartupMessage(pg, client, tlsConfig)
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
		sess.trackedParams = extractTrackedParams(m.Parameters, opts.trackExtraParams)
		relay(client, pg, decision.Pool, sess, opts)
	}
}

// receiveStartupMessage reads until StartupMessage or CancelRequest.
// On SSLRequest with tls configured, performs the TLS handshake in
// place and returns the upgraded connection.
func receiveStartupMessage(pg *pgproto3.Backend, client net.Conn, tlsConfig *tls.Config) (msg pgproto3.FrontendMessage, conn net.Conn, out *pgproto3.Backend, err error) {
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
			out = pgproto3.NewBackend(conn, conn)

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

// relay is the pre-existing test entry — permissive defaults.
//
// client is the raw socket behind pg. relay needs it, not just the
// pgproto3 wrapper, because idle timeouts are enforced with read
// deadlines and pgproto3 deliberately exposes no way to reach through
// to the connection it was built on.
func relay(client net.Conn, pg *pgproto3.Backend, p *pool.Pool, sess *session, opts ...*runtimeOpts) {
	o := defaultRuntimeOpts()
	if len(opts) > 0 && opts[0] != nil {
		o = opts[0]
	}
	relayImpl(client, pg, p, sess, o)
}

// relayImpl implements transaction pooling: a backend is acquired only
// for the span of one transaction (BEGIN..COMMIT, or a single autocommit
// statement) and released the instant it reports ReadyForQuery{TxStatus:
// 'I'} — idle, outside any transaction. Between transactions the client
// holds no backend at all, so a later transaction may land on a
// completely different one.
//
// Two production-safety details this loop enforces that the naive
// version does not:
//
//   - query_wait_timeout: Acquire uses a bounded ctx (opts.queryWaitTimeout).
//     Without this, a saturated pool parks every waiting client goroutine
//     forever, growing memory/FDs unboundedly until the OOM killer wins.
//
//   - server_reset_query (DISCARD ALL): before a backend is returned to
//     the shared idle stack, any session state left over from this
//     client (SET, prepared statements, temp tables, listen/notify,
//     GUCs) is scrubbed synchronously. Without this, a later client
//     inherits the previous client's state — a correctness bug at best,
//     a data-leak (application_name/GUCs containing PII) at worst.
//
// Terminate is never forwarded to a held backend: real Postgres closes
// the connection on Terminate, which would destroy a backend we might
// still want to reuse. If we're holding a backend that's idle when
// Terminate arrives, we release it cleanly for the next client;
// otherwise (mid-transaction), we discard.
func relayImpl(client net.Conn, pg *pgproto3.Backend, p *pool.Pool, sess *session, opts *runtimeOpts) {
	var backend *backendConn
	var fe *pgproto3.Frontend
	var lastTxStatus byte // last RFQ status byte seen; 'I' = idle

	// inTransaction reports whether the client is sitting inside an open
	// transaction, which selects which of the two idle timeouts applies.
	// 'T' is an open transaction, 'E' is one that has errored but not
	// yet been rolled back — both still pin a backend and its locks.
	inTransaction := func() bool {
		return backend != nil && (lastTxStatus == 'T' || lastTxStatus == 'E')
	}

	// armClientIdleDeadline sets the read deadline that bounds how long
	// we will wait for the client's next message. Returns the SQLSTATE
	// and message to report if it fires, so the caller doesn't have to
	// re-derive which timeout was in force.
	//
	// Both codes are real Postgres SQLSTATEs for exactly these
	// conditions, so drivers and operators already know them.
	armClientIdleDeadline := func() (code, reason string) {
		if inTransaction() {
			if opts.idleTransactionTimeout <= 0 {
				_ = client.SetReadDeadline(time.Time{})
				return "", ""
			}
			_ = client.SetReadDeadline(time.Now().Add(opts.idleTransactionTimeout))
			return "25P03", "terminating connection due to idle-in-transaction timeout"
		}
		if opts.clientIdleTimeout <= 0 {
			_ = client.SetReadDeadline(time.Time{})
			return "", ""
		}
		_ = client.SetReadDeadline(time.Now().Add(opts.clientIdleTimeout))
		return "57P05", "terminating connection due to idle-session timeout"
	}

	// Once a message starts arriving the idle clock no longer applies —
	// a slow large COPY batch is not an idle client.
	disarmClientIdleDeadline := func() { _ = client.SetReadDeadline(time.Time{}) }

	// release hands the held backend back: reusable if this transaction
	// ended cleanly, discarded if we're abandoning it in an unknown or
	// mid-transaction state (never let another client inherit open
	// locks). When reusable AND server_reset_query is configured, the
	// scrub runs synchronously before the release so the next Acquire
	// on this conn sees a clean session.
	release := func(reusable bool) {
		if backend == nil {
			return
		}
		// Clear any query_timeout deadline before this connection can
		// reach another session. A leftover deadline travels with the
		// conn into the idle stack and makes the *next* client's first
		// read fail instantly, which is about as hard to diagnose as
		// bugs get.
		_ = backend.SetReadDeadline(time.Time{})
		// The backend's prepared-statement set records which statements
		// THIS session taught it, and statement names are per-client.
		// It therefore must not survive the handover, whatever
		// server_reset_query is set to: the next session's Bind for a
		// name that happens to collide would find the backend "already
		// knows" it, skip the lazy Parse, and silently execute the
		// previous client's statement.
		//
		// Unconditional on purpose. Doing this only when
		// server_reset_query is configured made correctness here a
		// property of the config rather than of the code.
		clearBackendPSCache(backend)
		if reusable {
			if opts.serverResetQuery != "" {
				if err := runResetQuery(backend, opts.serverResetQuery, opts.healthCheckTimeout); err != nil {
					// A failed reset means we can't guarantee session
					// isolation — discard instead of reusing.
					slog.Warn("relay: server_reset_query failed, discarding backend", "err", err)
					p.Discard(backend)
					backend, fe = nil, nil
					sess.setBackend(nil)
					return
				}
			}
			p.Release(backend)
		} else {
			p.Discard(backend)
		}
		backend, fe = nil, nil
		sess.setBackend(nil)
	}

	// pending counts the bytes of backend replies sitting unwritten in
	// pg's encode buffer. pgproto3.Backend.Send only appends to that
	// buffer — Flush is what performs the write(2) — so batching Sends
	// is how a result set becomes one syscall instead of one per row.
	//
	// The invariant every flush point below maintains: never block
	// reading from the client while pending > 0.
	pending := 0
	flushClient := func() error {
		if pending == 0 {
			return nil
		}
		pending = 0
		if err := pg.Flush(); err != nil {
			slog.Warn("relay: send to client", "err", err)
			release(false)
			return err
		}
		return nil
	}

	for {
		idleCode, idleReason := armClientIdleDeadline()
		msg, err := pg.Receive()
		disarmClientIdleDeadline()
		if err != nil {
			if idleCode != "" && errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Info("relay: idle timeout",
					"code", idleCode, "user", sess.user, "database", sess.database,
					"in_transaction", inTransaction())
				// Report before releasing: once the backend is
				// discarded the error is just an unexplained close.
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     idleCode,
					Message:  idleReason,
				})
				_ = pg.Flush()
				// An idle-in-transaction backend is mid-transaction and
				// must be discarded; an idle *session* may be holding a
				// perfectly clean one worth keeping.
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				slog.Debug("relay: client receive", "err", err)
			}
			// If we happen to be holding a clean-idle backend when the
			// client vanishes without Terminate, don't waste it.
			release(backend != nil && lastTxStatus == 'I')
			return
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			release(backend != nil && lastTxStatus == 'I')
			return
		}

		if backend == nil {
			// Shutdown boundary. We hold no backend, so this client is
			// between transactions and can be let go without aborting
			// anything. 57P01 (admin_shutdown) is what Postgres itself
			// sends on a fast shutdown, so drivers already treat it as
			// "reconnect", not as a query failure.
			if opts.draining.Load() {
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "57P01",
					Message:  "terminating connection due to administrator command (pgman is shutting down)",
				})
				_ = pg.Flush()
				return
			}

			ctx := context.Background()
			var cancel context.CancelFunc
			if opts.queryWaitTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, opts.queryWaitTimeout)
			}
			conn, err := p.Acquire(ctx)
			if cancel != nil {
				cancel()
			}
			if err != nil {
				slog.Info("relay: acquire failed", "err", err)
				// A closed pool means the process is going away, so the
				// session genuinely cannot continue — that one stays
				// fatal. Everything else is transient: the backend is
				// down or the pool is momentarily full, and both are
				// survivable if we let the client retry.
				//
				// Killing the session instead (the previous behaviour)
				// is actively harmful under load: application-side pools
				// answer a dropped connection with a reconnect storm,
				// aimed at a proxy that is already saturated.
				if errors.Is(err, pool.ErrPoolClosed) {
					pg.Send(&pgproto3.ErrorResponse{
						Severity: "FATAL",
						Code:     "57P01",
						Message:  "terminating connection due to administrator command (pgman is shutting down)",
					})
					_ = pg.Flush()
					return
				}
				code, message := "53300", "no backend connection available: "+err.Error()
				if errors.Is(err, pool.ErrCircuitOpen) {
					// 08006 connection_failure says "the server side is
					// broken", which is exactly what an open breaker
					// means and is distinct from "we are full".
					code, message = "08006", "backend unavailable: circuit breaker open"
				}
				if err := failQuery(pg, msg, code, message); err != nil {
					return
				}
				continue
			}
			backend = conn.(*backendConn)
			fe = pgproto3.NewFrontend(backend, backend)
			sess.setBackend(backend)

			// application_name & friends: replay startup params on
			// the freshly-acquired backend so pg_stat_activity /
			// TimeZone / client_encoding match what the client asked
			// for. Silent — the client never sees these SETs.
			if len(sess.trackedParams) > 0 {
				if err := applyTrackedParams(fe, sess.trackedParams); err != nil {
					slog.Warn("relay: apply tracked params", "err", err)
					release(false)
					return
				}
			}
		}

		// Extended query protocol awareness: Postgres buffers responses
		// for Parse/Bind/Describe/Execute until Sync arrives, then
		// flushes everything including ReadyForQuery. If we forwarded
		// one message at a time and waited for RFQ after each, we'd
		// deadlock on Parse (backend waits for Sync, relay waits for
		// RFQ). Instead: buffer-forward all messages until we see a
		// terminal message (Query or Sync) that triggers RFQ from the
		// backend, then flush and read the response stream.
		//
		// Simple query protocol: a single Query message triggers an
		// immediate response ending with RFQ — treated as terminal.
		//
		// Prepared-statement replay: interceptClientMsg may prepend a
		// Parse for a stmt this backend doesn't yet know. Each such
		// prepend emits an extra ParseComplete from the backend that
		// the client didn't ask for — swallowParseComplete counts how
		// many we owe the client (i.e. must drop before forwarding).
		// Fused per-message intercept: PS lazy-replay + LISTEN warn +
		// DDL cache flush in one type switch. Hot Bind/Execute/Sync
		// loop hits the "nothing to do" branch for 2 of every 3 msgs.
		var swallowParseComplete int
		outMsg, swallow := processClientMsg(fe, backend, sess, msg)
		swallowParseComplete += swallow
		fe.Send(outMsg)

		terminal := isTerminalMessage(msg)

		// If not terminal yet, keep reading + forwarding until we see
		// one. This covers the common extended-protocol batch:
		// Parse → Bind → Describe → Execute → Sync.
		for !terminal {
			next, err := pg.Receive()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					slog.Debug("relay: client receive (ext batch)", "err", err)
				}
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			if _, ok := next.(*pgproto3.Terminate); ok {
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			outNext, swallowN := processClientMsg(fe, backend, sess, next)
			swallowParseComplete += swallowN
			fe.Send(outNext)
			terminal = isTerminalMessage(next)
		}

		if err := fe.Flush(); err != nil {
			slog.Warn("relay: forward to backend", "err", err)
			release(false)
			return
		}

		// The query is now in flight. Everything from here to
		// ReadyForQuery is "the backend working", which is both what
		// query_timeout bounds and what the latency histogram measures.
		queryStart := time.Now()
		if opts.queryTimeout > 0 {
			// A read deadline, not a refreshing one: query_timeout is
			// the total time a statement may take, so it must not be
			// extended by a backend that keeps trickling rows.
			_ = backend.SetReadDeadline(queryStart.Add(opts.queryTimeout))
		}

		for {
			reply, err := fe.Receive()
			if err != nil {
				if opts.queryTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
					slog.Warn("relay: query_timeout exceeded",
						"timeout", opts.queryTimeout,
						"user", sess.user, "database", sess.database)
					// Discard, don't release: the backend is still
					// executing. Closing the socket is what actually
					// aborts the statement server-side, and it can
					// never be reused in that state.
					release(false)
					pg.Send(&pgproto3.ErrorResponse{
						Severity: "FATAL",
						Code:     "57014", // query_canceled
						Message:  "canceling statement due to query_timeout",
					})
					_ = pg.Flush()
					return
				}
				slog.Warn("relay: backend receive", "err", err)
				release(false)
				return
			}
			// Swallow ParseCompletes generated by our lazy-prepare
			// prepends — the client didn't send those Parses and
			// isn't expecting matching ParseComplete acks.
			if swallowParseComplete > 0 {
				if _, ok := reply.(*pgproto3.ParseComplete); ok {
					swallowParseComplete--
					continue
				}
			}
			pg.Send(reply)
			pending += replyEncodedSize(reply)
			// Only pay a write(2) once the buffer is worth writing.
			// Flushing per message turned a 10k-row result set into
			// 10k syscalls; the threshold keeps memory bounded for
			// large streams while the flushes below guarantee the
			// client sees everything before we block on it.
			if pending >= clientFlushThreshold {
				if err := flushClient(); err != nil {
					return
				}
			}

			// COPY sub-protocol handoff. When the backend enters COPY
			// IN mode (client streams data to server), the roles flip:
			// we must relay client → backend until the client ends the
			// copy with CopyDone or CopyFail. Failing to do this makes
			// the whole session deadlock — backend sits waiting for
			// CopyData, we sit waiting for backend messages.
			if _, ok := reply.(*pgproto3.CopyInResponse); ok {
				// The client will not send a single CopyData byte
				// until it has actually seen CopyInResponse, and
				// relayCopyIn immediately blocks reading from it.
				// Flushing here is what stops that from deadlocking.
				if err := flushClient(); err != nil {
					return
				}
				// A bulk load takes as long as it takes; its duration
				// carries no information about backend health, so
				// query_timeout does not apply past this point.
				_ = backend.SetReadDeadline(time.Time{})
				if err := relayCopyIn(pg, fe); err != nil {
					slog.Warn("relay: copy-in", "err", err)
					release(false)
					return
				}
				// After CopyDone/CopyFail the backend produces
				// CommandComplete + RFQ — fall through to the outer
				// receive loop.
				continue
			}
			// CopyBothResponse: replication protocol (walsender /
			// logical CDC — Debezium, wal2json, pgoutput). Client
			// and server exchange CopyData messages asynchronously
			// in both directions, ended by client's CopyDone.
			if _, ok := reply.(*pgproto3.CopyBothResponse); ok {
				// Same handoff rule as COPY IN: relayCopyBoth starts a
				// goroutine that reads from the client straight away.
				if err := flushClient(); err != nil {
					return
				}
				// Replication streams are open-ended by design — a
				// walsender can idle for minutes between WAL records.
				_ = backend.SetReadDeadline(time.Time{})
				if err := relayCopyBoth(pg, fe); err != nil {
					slog.Warn("relay: copy-both", "err", err)
					release(false)
					return
				}
				continue
			}
			// CopyOutResponse: backend streams CopyData → CopyDone →
			// CommandComplete → RFQ. The existing loop already handles
			// this correctly (keep reading until RFQ) — no special case
			// needed.

			rfq, ok := reply.(*pgproto3.ReadyForQuery)
			if !ok {
				continue
			}
			// End of the response cycle: the client is about to be the
			// only one with anything to say, so everything buffered
			// has to be on the wire before we go back to reading it.
			if err := flushClient(); err != nil {
				return
			}
			// The statement is done, so the query clock stops and the
			// deadline must come off before the conn can be released.
			_ = backend.SetReadDeadline(time.Time{})
			opts.metrics.observeQuery(sess.poolName, time.Since(queryStart))
			lastTxStatus = rfq.TxStatus
			// Release decision per pooling mode:
			//   transaction — release when backend is idle ('I')
			//   session     — never release on RFQ (only on disconnect)
			//   statement   — release on EVERY RFQ regardless of TxStatus.
			// Statement mode is the most aggressive: it makes BEGIN /
			// COMMIT / SET LOCAL effectively useless (each statement
			// lands on a fresh backend), so it's only appropriate for
			// pure autocommit read workloads.
			switch sess.poolMode {
			case "statement":
				release(rfq.TxStatus != 'E') // 'E' = errored, poison; discard
			case "session":
				// no-op
			default: // transaction (also empty string)
				if rfq.TxStatus == 'I' {
					release(true)
				}
			}
			break
		}
	}
}

// clientFlushThreshold is how many bytes of backend replies may sit in
// the client write buffer before we force a write(2). It bounds the
// memory a single streaming result set can pin (per client connection)
// while still amortising the syscall across many rows. 64 KiB is well
// above a typical TCP send buffer's useful chunk and far below anything
// that matters against max_client_conn.
const clientFlushThreshold = 64 << 10

// replyEncodedSize approximates the wire size of a backend reply. It
// feeds the flush threshold only, so it needs to be cheap and roughly
// right, not exact. DataRow and CopyData are the only backend messages
// that can be arbitrarily large and the only ones that appear in bulk;
// everything else is small and bounded, so a flat estimate covers it.
func replyEncodedSize(msg pgproto3.BackendMessage) int {
	switch m := msg.(type) {
	case *pgproto3.DataRow:
		// type byte + int32 length + int16 column count, then an
		// int32 length prefix per column value.
		n := 7
		for _, v := range m.Values {
			n += 4 + len(v)
		}
		return n
	case *pgproto3.CopyData:
		return 5 + len(m.Data)
	default:
		return 128
	}
}

// failQuery reports a recoverable, query-scoped error and leaves the
// connection in a state the client can keep using.
//
// The subtlety is the extended query protocol. If the message we failed
// on is not the terminal one, the client has already pipelined the rest
// of its batch (Bind, Describe, Execute, Sync) and is waiting for a
// single response. Replying immediately would leave those messages in
// the socket to be misread as the start of the next query. Postgres
// solves this by discarding messages until Sync, and so do we.
//
// Returns a non-nil error only when the client itself is gone, in which
// case the caller must unwind.
func failQuery(pg *pgproto3.Backend, msg pgproto3.FrontendMessage, code, message string) error {
	if !isTerminalMessage(msg) {
		for {
			next, err := pg.Receive()
			if err != nil {
				return fmt.Errorf("drain to sync: %w", err)
			}
			if _, ok := next.(*pgproto3.Terminate); ok {
				return errClientTerminated
			}
			if isTerminalMessage(next) {
				break
			}
		}
	}

	// Severity ERROR, not FATAL: FATAL tells the driver the connection
	// is finished, which is precisely the reconnect storm we are trying
	// to avoid.
	pg.Send(&pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     code,
		Message:  message,
	})
	pg.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := pg.Flush(); err != nil {
		return fmt.Errorf("report query failure: %w", err)
	}
	return nil
}

// errClientTerminated marks "the client hung up while we were putting
// the protocol back together" — not an error worth logging.
var errClientTerminated = errors.New("client terminated")

// isTerminalMessage returns true for messages that cause Postgres to
// flush its response pipeline and end with ReadyForQuery in the *outer*
// protocol level:
//   - Query (simple protocol) — immediate full response
//   - Sync (extended protocol) — flushes buffered responses
//
// CopyDone / CopyFail are NOT terminal at this level — they're
// sub-protocol messages inside the COPY handoff, handled by
// relayCopyIn (which switches its own direction until it sees them).
// If we left them here, a client's COPY FROM STDIN batch would prematurely
// terminate the outer batching loop.
func isTerminalMessage(msg pgproto3.FrontendMessage) bool {
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Sync:
		return true
	}
	return false
}

// relayCopyBoth drives the bidirectional CopyBoth sub-protocol used by
// PostgreSQL replication clients (walsender for physical, logical
// decoding plugins for CDC — Debezium, wal2json, pgoutput). Both sides
// send CopyData asynchronously; the exchange ends when the client sends
// CopyDone (or CopyFail / Terminate), which the backend acknowledges
// with its own CopyDone → CommandComplete → RFQ.
//
// Implementation: two goroutines pump each direction independently
// with per-message flush (replication is latency-sensitive, and each
// CopyData carries a WAL record or keepalive that the peer needs
// promptly). Errors on either side abort the pair.
func relayCopyBoth(pg *pgproto3.Backend, fe *pgproto3.Frontend) error {
	// Channel carries a single error from whichever direction fails
	// first. Second failure (usually the peer noticing the socket
	// closing) is discarded — the first error is the interesting one.
	errCh := make(chan error, 2)

	// client → backend
	go func() {
		for {
			msg, err := pg.Receive()
			if err != nil {
				errCh <- fmt.Errorf("client→backend receive: %w", err)
				return
			}
			switch msg.(type) {
			case *pgproto3.Terminate:
				// Synthesize CopyDone so the backend cleans up
				// gracefully instead of ending with a broken pipe.
				fe.Send(&pgproto3.CopyDone{})
				_ = fe.Flush()
				errCh <- nil
				return
			case *pgproto3.CopyDone, *pgproto3.CopyFail:
				fe.Send(msg)
				if err := fe.Flush(); err != nil {
					errCh <- fmt.Errorf("flush end-of-copy: %w", err)
					return
				}
				// After CopyDone/CopyFail the backend responds with
				// its own CopyDone + CommandComplete + RFQ. Leave the
				// other goroutine to relay those, then exit.
				errCh <- nil
				return
			default:
				fe.Send(msg)
				if err := fe.Flush(); err != nil {
					errCh <- fmt.Errorf("client→backend flush: %w", err)
					return
				}
			}
		}
	}()

	// backend → client
	go func() {
		for {
			msg, err := fe.Receive()
			if err != nil {
				errCh <- fmt.Errorf("backend→client receive: %w", err)
				return
			}
			pg.Send(msg)
			if err := pg.Flush(); err != nil {
				errCh <- fmt.Errorf("backend→client flush: %w", err)
				return
			}
			// ReadyForQuery from backend closes the copy-both round.
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				errCh <- nil
				return
			}
		}
	}()

	// First goroutine to finish decides the outcome. Drain the second
	// so we don't leave it blocked on a dead socket (Receive will
	// error once the peer closes, so this returns fast).
	first := <-errCh
	<-errCh
	return first
}

// relayCopyIn drives the COPY-IN sub-protocol: backend has sent
// CopyInResponse and is now blocked waiting for the client's data
// stream (CopyData messages) terminated by CopyDone or CopyFail. We
// pass each client message straight through to the backend and flush
// every 32 messages (or on end-of-copy) to strike a balance between
// syscall cost and memory footprint for very large loads.
//
// Returns nil once CopyDone or CopyFail has been forwarded — the
// caller then resumes reading the backend's post-COPY response
// (CommandComplete + RFQ).
func relayCopyIn(pg *pgproto3.Backend, fe *pgproto3.Frontend) error {
	const flushEvery = 32
	pending := 0
	for {
		msg, err := pg.Receive()
		if err != nil {
			return fmt.Errorf("client receive: %w", err)
		}
		switch msg.(type) {
		case *pgproto3.Terminate:
			// Client abandoned mid-copy — synthesize a CopyFail so
			// the backend rolls back cleanly instead of thinking
			// this is a partial copy waiting to resume.
			fe.Send(&pgproto3.CopyFail{Message: "client terminated during COPY"})
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush copyfail: %w", err)
			}
			return nil
		case *pgproto3.CopyData:
			fe.Send(msg)
			pending++
			if pending >= flushEvery {
				if err := fe.Flush(); err != nil {
					return fmt.Errorf("flush: %w", err)
				}
				pending = 0
			}
		case *pgproto3.CopyDone, *pgproto3.CopyFail:
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush end-of-copy: %w", err)
			}
			return nil
		default:
			// Anything else during COPY IN is a protocol violation
			// by the client — pass through and let the backend
			// generate the appropriate error.
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush unexpected: %w", err)
			}
		}
	}
}

// runResetQuery sends the configured server_reset_query on the backend
// and consumes until ReadyForQuery. Uses the same deadline as the
// health-check path since it's the same round-trip shape.
func runResetQuery(backend *backendConn, query string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if err := backend.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = backend.SetDeadline(time.Time{}) }()

	fe := pgproto3.NewFrontend(backend, backend)
	fe.Send(&pgproto3.Query{String: query})
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
