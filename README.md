# pgman

A PostgreSQL connection pooler written in Go — transaction, session and
statement pooling behind the native Postgres wire protocol, with
Prometheus metrics and a live admin UI built into the same binary.

[![ci](https://github.com/yurii-bondar/pgman/actions/workflows/ci.yml/badge.svg)](https://github.com/yurii-bondar/pgman/actions/workflows/ci.yml)

## Status

Pre-1.0. The protocol handling, pooling and auth paths are covered by
unit tests and by integration tests against a real Postgres, but pgman
has not been run in production. Read [Known limitations](#known-limitations)
before deploying it anywhere that matters.

## Why this exists

PgBouncer is excellent at what it does and pgman does not claim to beat
it on raw efficiency — C with a single-threaded event loop is hard to
out-allocate from Go. The bet is on the parts operators complain about:

- **Observability without a sidecar.** Native Prometheus metrics,
  including an acquire-wait histogram, instead of scraping `SHOW STATS`
  through a separate exporter process.
- **A config format from this century.** YAML with `SIGHUP` reload,
  rather than an INI file.
- **A live dashboard in the same binary.** Pool state over SSE, no
  separate admin process and no JavaScript bundle to deploy.
- **A codebase you can actually change.** Go with narrow interfaces for
  auth backends and routing, so adding one does not mean patching a
  monolithic C core.

## Quick start

```sh
# Postgres for local development (bound to 127.0.0.1)
docker compose up -d postgres

# TLS material for local development — certs/ is gitignored and ships empty
scripts/gen-dev-certs.sh

go build -o pgman .
./pgman -config config.yaml
```

Then point any Postgres client at the proxy:

```sh
psql "postgres://rgs@127.0.0.1:6435/backoffice"
```

The whole stack, proxy included, also runs from Compose:

```sh
docker compose up -d
```

> `config.docker.yaml` and the Compose stack use trust auth and no TLS.
> Every port there is bound to `127.0.0.1` on purpose. It is a
> development fixture, not a deployment template — start from
> `config.yaml` instead.

### Command-line flags

| Flag | Purpose |
| --- | --- |
| `-config <path>` | Config file to load. Default `config.yaml`. |
| `-gen-scram-verifier <password>` | Print a SCRAM-SHA-256 verifier for `auth_users`, then exit. |
| `-gen-admin-password <password>` | Print a bcrypt hash for `admin_basic_auth_password_hash`, then exit. |

## Configuration

`config.yaml` in this repository is a commented reference covering every
supported key; it is the authoritative documentation until a manual
exists. The settings worth knowing up front:

| Key | Meaning | Default |
| --- | --- | --- |
| `listen_addr` | Postgres wire listener (data plane). | `:6435` |
| `metrics_addr` | Prometheus `/metrics` listener. | `:8080` |
| `admin_addr` | Admin UI and pool API. | `127.0.0.1:8081` |
| `auth_users` | Map of user to SCRAM-SHA-256 verifier. | — |
| `allow_insecure_trust_auth` | Accept every client without a password. | `false` |
| `max_client_conn` | Global cap on accepted client connections. | `10000` |
| `query_wait_timeout` | How long a client waits for a backend. | `120s` |
| `query_timeout` | Max runtime of a single statement. | `0` (off) |
| `client_idle_timeout` | Close a client silent outside a transaction. | `0` (off) |
| `idle_transaction_timeout` | Close a client idle inside a transaction. | `0` (off) |
| `circuit_breaker_threshold` | Consecutive dial failures before failing fast. | `5` |
| `circuit_breaker_cooldown` | How long the breaker stays open. | `5s` |
| `require_backend_tls` | Refuse pools whose DSN does not mandate TLS. | `false` |
| `server_reset_query` | Scrub run before a backend re-enters the pool. | `DISCARD ALL` |
| `server_lifetime` | Max age of a backend connection, from dial. | unset |
| `server_idle_timeout` | Max idle time before a backend is closed. | unset |
| `shutdown_timeout` | Drain budget on `SIGTERM`. | `30s` |
| `pools.<name>.pool_mode` | `transaction`, `session` or `statement`. | `transaction` |
| `pools.<name>.limit` | Backend connections for this pool. | — |

Each pool is defined under `pools:` with its own backend DSN and limit,
and may expose `aliases` so several client-facing database names share
one pool.

### Pool modes and what they cost you

| Mode | Backend held for | Breaks |
| --- | --- | --- |
| `session` | The whole client connection | Nothing; also pools the least. |
| `transaction` | One transaction | Session-level `SET`, session prepared statements (replayed transparently), advisory locks, `LISTEN`/`NOTIFY`. |
| `statement` | One statement | Everything above, plus explicit transactions — `BEGIN` and the statement after it can land on different backends. |

These are architectural consequences of pooling, not bugs, and they are
the same in PgBouncer. `statement` mode is only appropriate for pure
autocommit read workloads.

## Operating pgman

### Metrics

`GET /metrics` on `metrics_addr` exports, alongside the standard Go and
process collectors:

| Metric | Type |
| --- | --- |
| `pgman_pool_limit`, `pgman_pool_in_use`, `pgman_pool_idle`, `pgman_pool_waiting` | Gauge, per pool |
| `pgman_pool_acquire_total`, `pgman_pool_acquire_seconds_total` | Counter |
| `pgman_pool_discards_total`, `pgman_pool_dial_errors_total`, `pgman_pool_reaped_total` | Counter |
| `pgman_pool_acquire_wait_seconds` | Histogram |
| `pgman_query_duration_seconds` | Histogram, per pool |
| `pgman_pool_circuit_open` | Gauge, per pool |
| `pgman_client_conn_active`, `pgman_client_conn_total` | Gauge / Counter |
| `pgman_client_login_ok_total`, `pgman_client_login_failures_total` | Counter |
| `pgman_max_client_conn_rejected_total` | Counter |

A subset is also published under `pgbouncer_*` names so existing
PgBouncer dashboards keep working.

### Admin SQL

Connecting to the virtual database named by `admin_database` (default
`pgbouncer`) switches the session into admin mode:

```
SHOW POOLS · SHOW STATS · SHOW CLIENTS · SHOW SERVERS
SHOW DATABASES · SHOW LISTS · SHOW VERSION
PAUSE [pool] · RESUME [pool] · RECONNECT [pool]
```

### Admin UI

`admin_addr` serves a read-mostly dashboard (pool sizes, in-use, idle,
waiters, errors) that updates over SSE, plus endpoints for pool
create/resize/remove, pause/resume/reconnect, session cancel and a
config-reload preview.

It binds to loopback by default. Binding it anywhere else requires
configuring authentication — HTTP Basic (bcrypt), OIDC, or mutual TLS.

### Health probes

Served on `metrics_addr`, unauthenticated, because the kubelet has no
credentials:

| Endpoint | Meaning |
| --- | --- |
| `GET /health` | Liveness. 200 for the whole life of the process, including during a drain — a failing liveness probe means "restart me", and restarting a draining proxy drops transactions. |
| `GET /ready` | Readiness. 503 while draining, and 503 when every pool's circuit breaker is open. Body is JSON with per-pool detail. |

`/ready` stays 200 when only *some* backends are unreachable: a degraded
backend affects every replica identically, so failing readiness there
would turn a partial outage into a total one.

```yaml
readinessProbe:
  httpGet: { path: /ready, port: 8080 }
  periodSeconds: 5
livenessProbe:
  httpGet: { path: /health, port: 8080 }
  periodSeconds: 10
```

### Signals

| Signal | Effect |
| --- | --- |
| `SIGHUP` | Reload the config file. Adds pools that appeared and drains pools that disappeared. Existing pools are not reconfigured. |
| `SIGTERM` / `SIGINT` | Graceful drain: stop accepting connections, let in-flight transactions finish, close sessions that are between transactions with `57P01`, then exit. Bounded by `shutdown_timeout`. |

## Known limitations

Honest list, so nobody discovers these in an incident:

- **The session timeouts ship disabled.** `query_timeout`,
  `client_idle_timeout` and `idle_transaction_timeout` all default to
  `0`, matching PgBouncer and Postgres. Until you set them, a hung peer
  is bounded only by TCP keepalive. `config.yaml` has starting values.
- **No write deadline on the client socket.** A client that stops
  reading can still stall a relay goroutine at the TCP level.
- **No `max_prepared_statements`.** The per-session prepared-statement
  cache grows until the client disconnects.
- **`SIGHUP` does not resize or re-target existing pools** — only adds
  and removes them. Changing a limit, DSN or TLS setting needs a restart.
- **No online restart (`-R`).** This is deliberate; see `DEV_PLAN.md`
  for the reasoning and the Kubernetes-shaped alternative.
- **`SHOW POOLS` and `SHOW DATABASES` report `pool_mode` as
  `transaction`** regardless of the pool's actual mode.
- **No published container image or release binaries** yet; build from
  source.

## Development

```sh
go build ./...
go vet ./...
go test -race ./...          # unit tests
golangci-lint run            # see .golangci.yml
```

Integration tests live in `tests/integration` as a separate module and
need a real Postgres:

```sh
docker compose up -d postgres
cd tests/integration
PGMAN_TEST_PG_DSN="postgres://pgman_test:pgman_test@127.0.0.1:15432/pgman_test?sslmode=disable" \
  go test -tags integration -race ./...
```

Benchmarks and the soak suite are excluded from the default CI run and
live in the `perf` workflow, which can be triggered on a pull request by
adding the `perf` label.

Design rules for contributions are in
[`.aiassistant/rules/principles.md`](.aiassistant/rules/principles.md);
the implementation plan and its rationale are in
[`DEV_PLAN.md`](DEV_PLAN.md).

## License

[MIT](LICENSE).
