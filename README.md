<p align="center">
  <img src="docs/images/pgman-logo.jpg" alt="pgman — a keeper marshalling Postgres elephants through a connection pool" width="520">
</p>

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

Released images are published for `linux/amd64` and `linux/arm64`:

```sh
docker run --rm \
  -v "$PWD/config.yaml:/etc/pgman/config.yaml:ro" \
  -p 6435:6435 -p 8080:8080 \
  bondevn/pgman:1            # or ghcr.io/yurii-bondar/pgman:1
```

Pin a major (`:1`) or an exact version (`:1.4.2`) rather than `latest`,
which moves under you on every release.

To build from source instead:

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
psql "postgres://rgs@127.0.0.1:6435/shop"
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
| `max_client_conn` | Global cap on accepted client connections, shared across the TCP and Unix listeners. | `10000` |
| `query_wait_timeout` | How long a client waits for a backend. | `120s` |
| `query_timeout` | Max runtime of a single statement. | `15m` |
| `client_idle_timeout` | Close a client silent outside a transaction. | `30m` |
| `idle_transaction_timeout` | Close a client idle inside a transaction. | `5m` |
| `client_write_timeout` | Max time one write to a client may block. | `60s` |
| `max_prepared_statements` | Named statements kept prepared per backend connection (LRU). | `200` |
| `scram_passthrough_idle_timeout` | Close a pass-through pool unused for this long. | `30m` |
| `circuit_breaker_threshold` | Consecutive dial failures before failing fast. | `5` |
| `circuit_breaker_cooldown` | How long the breaker stays open. | `5s` |
| `require_backend_tls` | Refuse pools whose DSN does not mandate TLS. | `false` |
| `server_reset_query` | Scrub run before a backend is handed to a different session. | `DISCARD ALL` |
| `server_reset_query_skip_same_session` | Skip the scrub when the same session reacquires the connection. | `false` |
| `server_lifetime` | Max age of a backend connection, from dial. | unset |
| `server_idle_timeout` | Max idle time before a backend is closed. | unset |
| `shutdown_timeout` | Drain budget on `SIGTERM`. | `30s` |
| `pools.<name>.pool_mode` | `transaction`, `session` or `statement`. | `transaction` |
| `pools.<name>.limit` | Backend connections for this pool. | — |
| `pools.<name>.backend_users` | Per-role backend DSNs; each gets its own pool. | — |
| `pools.<name>.scram_passthrough` | Authenticate to Postgres as the client, reusing its SCRAM proof. | `false` |

Each pool is defined under `pools:` with its own backend DSN and limit,
and may expose `aliases` so several client-facing database names share
one pool.

### Backend identity

By default every client reaches Postgres as the `backend_dsn` role,
whatever role it authenticated as. That is PgBouncer's forced-user mode
(`user=` on a database) and it has the same consequence: `GRANT` and
`REVOKE` no longer distinguish your clients, row-level security sees a
single identity, and `pg_stat_activity` attributes every statement to
the same role.

`backend_users` gives individual roles their own backend credentials:

```yaml
pools:
  shop:
    backend_dsn: "postgres://app_ro@db:5432/shop?sslmode=verify-full"
    backend_addr: "db:5432"
    limit: 20
    backend_users:
      alice: "postgres://alice@db:5432/shop?sslmode=verify-full&passfile=/etc/pgman/pgpass"
```

A full DSN rather than a password, so the secret need not live in the
config at all — point it at a `.pgpass` with `passfile=`, or use
certificate auth with `sslcert=`/`sslkey=`.

Pools are keyed by the identity they dial with, so a listed user gets
its own pool — shown as `shop/alice` in metrics, `SHOW POOLS` and
the admin UI — while everyone else keeps sharing the `backend_dsn` one.
That is what PgBouncer does too: a pool per (database, user), collapsing
to one per database when the definition forces a single user. Size for
it: one pool per listed user, each up to `limit` connections.

#### SCRAM pass-through

`backend_users` needs a DSN per role. `scram_passthrough` needs nothing
per role at all:

```yaml
pools:
  shop:
    backend_dsn: "postgres://unused@db:5432/shop?sslmode=verify-full"
    backend_addr: "db:5432"
    limit: 20
    scram_passthrough: true
```

When a client authenticates to pgman with SCRAM, the server half of that
exchange recovers the client's `ClientKey` — the value a SCRAM *client*
signs with. pgman reuses it to authenticate to Postgres as that same
role. No backend password is configured, stored or transmitted, and
users resolved through `auth_query` are covered, which `backend_users`
cannot do. PgBouncer works the same way.

Per-user pools appear on first use, since the credential does not exist
until the client logs in, and are named `shop/alice` like any
other. Only a completed SCRAM handshake can create one, so the set of
pools is the set of real roles that have connected.

Two conditions:

- **pgman's verifier must be the backend's verifier.** `ClientKey`
  derives from the salt and iteration count, so a verifier built
  independently will not authenticate. Copy `rolpassword` from
  `pg_authid` into `auth_users`, or point `auth_query` at that backend's
  `pg_shadow`. A mismatch is reported as a mismatch, not as a wrong
  password.
- **The backend must ask for `scram-sha-256`.** `md5`, `password` and
  GSSAPI cannot be answered with a `ClientKey`; the error names what was
  asked for.

Clients that authenticate by some other method — `trust`, `peer`,
`cert` — have no `ClientKey` to reuse and keep sharing the
`backend_dsn` role.

The trade is where the credential lives. With pass-through pgman holds a
password-equivalent in memory for every user that has logged in, where
otherwise it holds only verifiers, which authenticate nowhere. That is
still the better half of the bargain against a per-user password or
passfile on disk — but it is a real change, which is why it is opt-in.

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

The console is restricted to the roles listed in `admin_users`, and the
list is empty by default — passing client auth proves who you are, not
that you may `PAUSE` every pool or read every other tenant's session
list. A client that is not on the list gets the same
`database "pgbouncer" is not configured` answer as any other unknown
database name, so the console cannot be found by probing.

```yaml
admin_users:
  - ops
```

### `server_reset_query_skip_same_session`

`server_reset_query` scrubs a backend when it passes from one session to
another. Between two transactions of the *same* session it isolates that
session from itself, and the tracked-parameter replay then restores what
it wiped — two round trips per transaction. Setting
`server_reset_query_skip_same_session: true` skips both when the pool
returns a connection to the session that just released it.

The skip only fires when a session gets its own connection back, so the
win shrinks as clients oversubscribe the pool. Measured on a laptop
against a Docker Postgres, `TestPgbenchStyleMix`, 15s runs, pool of 50,
mean of 3 runs (6 at 100 clients):

| Clients | Off | On | Change |
| --- | --- | --- | --- |
| 1 | 1803 QPS | 3101 QPS | +72% |
| 4 | 5413 QPS | 6386 QPS | +18% |
| 20 | 15152 QPS | 17205 QPS | +14% |
| 100 | 20633 QPS | 21080 QPS | none — run-to-run spread swamps it |

At 100 clients over 50 backends a released connection is taken by a
waiter before its owner can reacquire it, so the skip rarely fires and
the workload is backend-bound anyway.

### Admin UI

`admin_addr` serves a read-mostly dashboard (pool sizes, in-use, idle,
waiters, errors) that updates over SSE, plus endpoints for pool
create/resize/remove, pause/resume/reconnect, session cancel and a
config-reload preview.

It binds to loopback by default. Binding it anywhere else requires
configuring authentication — HTTP Basic (bcrypt), OIDC, or mutual TLS.

The dashboard is four tabs. Three of them — live status, sessions and
recent errors — are server-rendered fragments pushed over the `/events`
SSE stream twice a second, so they follow the proxy without a reload;
the fourth is the management form.

**Live status** — one row per pool with the numbers you need to decide
whether a pool is healthy: in-use against the limit, idle, cumulative
acquire calls and the time spent in them, discards, and dial errors.
`IN USE / LIMIT` climbing to the limit while `ACQUIRE TIME` grows is
back-pressure; `DIAL ERRORS` moving on its own is a backend problem.

![Live status tab: per-pool in-use, idle, acquire and error counters](docs/images/admin-ui-live-status.png)

**Sessions** — every connected client, oldest first, since a stuck
session is usually an old one. `PID` is the fake PID pgman handed the
client rather than a real backend PID, and it doubles as the handle for
cancellation. A session counts as active while it holds a backend
connection, and `TX TIME` says for how long — that is the column that
finds a client sitting in an open transaction on a pool other sessions
are waiting for. Active rows offer a cancel button, which sends a
`CancelRequest` for the query actually running on that backend.

![Sessions tab: client sessions with PID, user, database, state and transaction time](docs/images/admin-ui-sessions.png)

**Manage pools** — resize or remove an existing pool, or add one at
runtime without a restart. Removal and resize let active sessions finish
first and drain the old connections in the background. A new pool needs
both `backend_dsn` and `backend_addr`, the same pair the YAML config
uses. Because this form turns pgman into a dialer for an
operator-supplied address, the address goes through
`validateBackendAddr` first, which rejects link-local and multicast
targets — without that check the panel would be an SSRF primitive
pointed at the cloud metadata service.

![Manage pools tab: resize and remove controls plus the add-pool form](docs/images/admin-ui-manage-pools.png)

**Recent errors** — a bounded ring buffer of pool events (`discard` and
`dial_error`), keeping the backend's own message intact rather than a
summarised count, because the counters on the status tab tell you *that*
dialling failed and only the text tells you why. The screenshot is a
pool pointed at a Postgres that refuses TLS — the common first-run
mistake, and one that reads very differently from a wrong password or a
missing database.

![Recent errors tab: recent discard and dial_error events per pool with the backend's message](docs/images/admin-ui-recent-errors.png)

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
| `SIGHUP` | Reload the config file: add pools that appeared, drain pools that disappeared, and rebuild pools whose settings changed. Listener, TLS and auth wiring still need a restart. |
| `SIGTERM` / `SIGINT` | Graceful drain: stop accepting connections, let in-flight transactions finish, close sessions that are between transactions with `57P01`, then exit. Bounded by `shutdown_timeout`. |

## Known limitations

Honest list, so nobody discovers these in an incident:

- **The session timeouts are ceilings, not policy.** `query_timeout`
  (15m), `client_idle_timeout` (30m), `idle_transaction_timeout` (5m)
  and `client_write_timeout` (60s) now ship enabled, but they are set
  where a healthy workload never reaches them — they bound a leak, they
  do not enforce an SLO. Tighten them to your workload (`config.yaml`
  ships 60s / 30m / 5m), or set a negative value to opt out explicitly.
- **`max_prepared_statements` is a per-backend LRU, not a client
  quota.** 200 statements stay prepared on each backend connection;
  beyond that the least recently used one is closed on the backend and
  re-prepared from the session's own record the next time it is used.
  The separate ceiling on how many a session may hold at once is 4× the
  setting, and a client past it is disconnected with `54000` rather
  than silently losing a statement.
- **`server_reset_query_skip_same_session` trades determinism for two
  round trips per transaction.** With it on, a session-level `SET` in
  transaction pooling survives whenever the pool hands back the same
  connection and is lost when it doesn't, so an app can appear to get
  away with session state until load starts moving connections between
  clients. Isolation between different clients is unaffected either
  way. Off by default; see above for what it buys.
- **SCRAM pass-through keeps a ClientKey per user for the life of the
  process.** The per-user *pools* are now reclaimed after
  `scram_passthrough_idle_timeout`, but the recovered credential is
  not: `backendIdentityFor` consults it to decide whether a user gets
  its own identity on the backend at all, and forgetting it could route
  a session that has authenticated but not yet routed to the shared
  `backend_dsn` role instead. Bounded by your role count.
- **SCRAM pass-through dials through its own connector,** not `pgconn`,
  because `pgconn` offers no way to sign with a recovered `ClientKey`.
  It reuses `pgconn.ParseConfig` for TLS, but the handshake is ours and
  has far less mileage on it than `pgconn`'s.
- **A reload rebuilds a changed pool rather than mutating it.** New
  sessions get the new settings; sessions already routed to the old
  pool finish on it and it drains in the background. The config file is
  the source of truth, so a limit changed through the admin UI and not
  written back to the YAML is reverted by the next `SIGHUP`.
- **No online restart (`-R`).** This is deliberate: in Kubernetes,
  Nomad or systemd-with-socket-activation the same guarantee comes more
  cleanly from `PAUSE` on the old instance, a rolling update of the
  Service, and the graceful drain on `SIGTERM`. Handing listen file
  descriptors between two processes buys nothing there, and the
  coordination is the expensive part.
- **`SHOW POOLS` reports `cl_active` as `0`** — per-database client
  counts are not tracked yet. The `pgman_client_conn_active` metric and
  the admin UI's session list both have the real numbers.
- **No release binaries** — container images only; build from source if
  you need a bare binary. `SHOW VERSION` also still reports a hardcoded
  string; the release version a container is running is in its startup
  log line, not in admin SQL.

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

Contributions are expected to match the surrounding code: comments
explain why a thing is the way it is rather than restating what the
line does, and anything on the hot path comes with a number.

### Releases

Releasing is automatic and driven by the commit log. A push to `main`
runs `ci`; if it passes, `release` asks
[semantic-release](https://semantic-release.gitbook.io/) what the commits
since the last tag imply, and — when they imply anything — tags the
commit, writes `CHANGELOG.md`, publishes a GitHub release, and pushes the
image to Docker Hub and GHCR for `linux/amd64` and `linux/arm64`.

Which means the commit subject decides the version, so it has to follow
[Conventional Commits](https://www.conventionalcommits.org/):

| Subject | Effect |
| --- | --- |
| `fix: release a backend on client Terminate` | patch — `1.4.2` → `1.4.3` |
| `feat: add statement pooling mode` | minor — `1.4.2` → `1.5.0` |
| `perf:` / `refactor:` / `revert:` | patch |
| `docs:` / `test:` / `ci:` / `chore:` | no release |
| any type plus `!`, or a `BREAKING CHANGE:` footer | major — `1.4.2` → `2.0.0` |

A commit that does not parse as a Conventional Commit is treated as
`no release`, which fails quietly: the work lands on `main` and simply
never ships. If a release should have happened and did not, the commit
subject is the first place to look.

Two things have to exist for the publish half to work, and both are set
outside this repository:

- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` as repository secrets, the
  token being a Docker Hub access token with Read/Write scope — not the
  account password. GHCR needs nothing; it authenticates with the
  workflow's own `GITHUB_TOKEN`.
- `main` must accept a push from `GITHUB_TOKEN`, because
  `@semantic-release/git` commits the changelog. If `main` is protected,
  either allow the GitHub Actions app to bypass it or drop the
  `@semantic-release/git` plugin from `.releaserc.json` and let the tag
  and the release notes be the record.

The version is stamped into the binary at link time and appears in the
`pgman up` log line, so a running container can be identified without
guessing which digest it came from.

## License

[MIT](LICENSE).
