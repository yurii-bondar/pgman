# Operating pgman: the edges

The README documents what each setting does. This documents what
happens when you change it, and the places where the right answer
depends on your workload rather than on pgman.

Everything here is measured on this repository's own harness. Where a
number appears, [`benchmarks.md`](benchmarks.md) has the run it came
from and `scripts/bench-vs-pgbouncer.sh` reproduces it.

---

## `server_reset_query`: safe default or high performance

`server_reset_query` runs on a backend connection before it is handed
to a *different* session. Its job is to make sure no client can observe
anything a previous client left behind.

pgman ships `DISCARD ALL`, and runs it. This is the single most
important difference from a default PgBouncer install, so it is worth
being precise about what it costs and what turning it off gives away.

### What `DISCARD ALL` actually clears

Postgres defines it as the combination of:

| Statement | What it drops |
| --- | --- |
| `SET SESSION AUTHORIZATION` reset | An identity change made with `SET ROLE` or `SET SESSION AUTHORIZATION` |
| `RESET ALL` | Every session-level GUC: `work_mem`, `search_path`, `statement_timeout`, `application_name`, timezone… |
| `DEALLOCATE ALL` | Every named prepared statement |
| `CLOSE ALL` | Every open cursor |
| `UNLISTEN *` | Every `LISTEN` registration |
| `SELECT pg_advisory_unlock_all()` | Every session-level advisory lock |
| `DISCARD PLANS` / `DISCARD TEMP` | Cached plans and temporary tables |

Read that list as the answer to "what leaks if I turn this off". The
expensive ones are rarely the ones people think about: `search_path`
changes which table a query reads, `SET ROLE` changes who it runs as,
and `pg_advisory_unlock_all()` is what stops one client's forgotten lock
from deadlocking the next one that gets that connection.

### The three configurations

| Setting | Isolation between different clients | Cost |
| --- | --- | --- |
| `server_reset_query: "DISCARD ALL"` (default) | Complete | One round trip per handover, plus a second to replay tracked parameters |
| `server_reset_query_skip_same_session: true` | Complete between *different* clients; a session may see its own leftovers | Both round trips skipped whenever the pool hands a session its own connection back |
| `server_reset_query: " "` | **None** — `SET work_mem` from one client is in effect for the next | Nothing |

The middle row is the one worth understanding, because it is the one
that is safe and is still off by default. It never weakens isolation
between two different clients: `adoptBackend` keys the decision on which
session last owned the connection. What it costs is *determinism*. With
it on, a session-level `SET` survives into the next transaction whenever
the LIFO pool happens to return the same connection, and is lost when it
does not. An application can then appear to get away with session state
in transaction pooling right up to the load level at which connections
start moving between clients — which is the worst possible shape for a
bug, because it appears in production and not in staging.

Turn it on when your clients genuinely treat each transaction as
independent, which is what transaction pooling asks of them anyway. The
measured win is large at low concurrency and disappears at high:

| Clients | Off | On |
| ---: | ---: | ---: |
| 1 | 1 803 QPS | 3 101 QPS (+72%) |
| 4 | 5 413 QPS | 6 386 QPS (+18%) |
| 20 | 15 152 QPS | 17 205 QPS (+14%) |
| 100 | 20 633 QPS | 21 080 QPS (within noise) |

At 100 clients over 50 backends a released connection is taken by a
waiter before its owner can reacquire it, so the skip almost never
fires and the workload is backend-bound regardless.

### If you are migrating from PgBouncer

PgBouncer does **not** run `server_reset_query` in transaction mode
unless `server_reset_query_always = 1`. Verified against 1.25.2: with
the stock configuration, `SET work_mem = '77MB'` in one client is still
in effect for the next client that lands on the same backend.

So a workload that "worked fine on PgBouncer" may be quietly relying on
that. Moving it to pgman makes the leak stop, which is correct and can
still look like a regression if some query was depending on an inherited
`search_path`. If you hit that, the fix is in the application; the
config knob that reproduces the old behaviour also reproduces the bug.

---

## How many client connections can it actually hold

`max_client_conn` defaults to 10 000. That is a ceiling pgman enforces,
not a promise your host can reach.

Measured on this repository's harness (transaction pooling, pool of 50,
simple protocol, macOS with Docker Desktop, 6 CPUs):

| Requested clients | Connections established | pgman QPS | pgman p99 | pgman RSS |
| ---: | ---: | ---: | ---: | ---: |
| 2 000 | 2 000 | 21 841 | 200 ms | 84 MiB |
| 5 000 | 5 000 | 21 805 | 441 ms | 193 MiB |
| 10 000 | **6 905** | 9 343 | 1 795 ms | 233 MiB |

The 10 000 row did not fail because of pgman. PgBouncer, measured in the
same session on the same host, also topped out — at 6 938 connections.
Two different poolers hitting the same wall within 0.5% of each other is
the host, not the software: Docker Desktop's network stack on macOS.

What this does and does not tell you:

- **Up to ~5 000 client connections is demonstrated**, with pgman's
  latency holding up better than PgBouncer's at that level.
- **10 000 and beyond is untested here**, and the review question about
  50k and 100k cannot be answered on a laptop at all. It needs a Linux
  host with raised `fs.file-max`, a widened ephemeral port range, and a
  load generator that is not competing with the pooler for cores.
- **Memory is the thing to plan for.** Roughly 3–4× PgBouncer at the
  same connection count, and it grows with connections rather than with
  throughput. Budget by peak client count, not peak QPS.

If you need a number for capacity planning today, use 5 000 connections
per instance and watch `pgman_pool_acquire_wait_seconds`.

---

## pgman needs CPU headroom

This is the least obvious operational property and the one most likely
to surprise.

PgBouncer is a single-threaded event loop. It uses one core well and is
almost indifferent to what else is on the machine. pgman is Go: it
spreads across every core it is given, which is why it is faster at
100+ clients — and it means CPU contention hurts it disproportionately.

The same benchmark matrix, run twice on the same machine:

| Condition | PgBouncer | pgman |
| --- | ---: | ---: |
| Quiet host, 100 clients | 18 181 QPS | 33 721 QPS |
| One neighbouring container burning a core | 16 926 QPS | 8 980 QPS |

pgman went from 1.9× faster to 0.53× as fast. PgBouncer barely moved.

Practical consequences:

- Do not co-schedule pgman with a CPU-hungry neighbour and expect the
  benchmark numbers.
- In Kubernetes, give it a CPU *request*, not just a limit, so the
  scheduler reserves what it needs.
- If you must run it somewhere contended, set `GOMAXPROCS` to match the
  CPU you are actually guaranteed. Go does not read cgroup CPU limits on
  its own, so a container limited to 2 CPUs on a 64-core node will
  otherwise start 64 scheduler threads and spend its quota on context
  switching.

---

## Cancellation

A client pressing Ctrl+C turns into a `CancelRequest`, which Postgres
requires be delivered on a **second, unauthenticated connection** naming
the backend's PID and secret. pgman keeps that mapping per session and
opens the connection on demand, bounded by `cancel_dial_timeout` (5s).

Two things follow that are worth knowing before an incident:

- **A cancel can outlive the query it was meant for.** The race is
  inherent to the protocol, not to pgman: by the time the second
  connection is open, the statement may have finished and the backend
  may have been released. pgman will not deliver a cancel to a backend
  the session no longer holds — a cancel landing in someone else's
  transaction would be far worse than a cancel that missed.
- **`cancel_dial_timeout` bounds a side channel.** The session being
  cancelled is busy, so nothing else limits the goroutine delivering the
  cancel. A backend that accepts the connection and then says nothing
  would otherwise pin it indefinitely.

`TestCancellationStorm` in the integration suite runs 24 clients
cancelling each other's queries in a loop and asserts the pool is fully
usable afterwards.

---

## When the database goes away

Behaviour is covered end to end by
`TestBackendOutageFailsCleanlyAndRecovers`, which cuts the network
between pgman and Postgres and then restores it. What an operator sees:

1. In-flight queries fail. Connections are gone; there is no hiding it.
2. After `circuit_breaker_threshold` (5) consecutive dial failures the
   breaker opens, and clients get `08006 backend unavailable: circuit
   breaker open` **immediately** instead of each paying a dial timeout.
   This is the difference between a database outage and a thundering
   herd aimed at a database that is already unwell.
3. `GET /ready` returns 503 with a body naming the affected pool:

   ```json
   {"status":"unready",
    "reason":"no pool can reach its backend: every circuit breaker is open",
    "pools":[{"name":"shop","circuit_open":true,"in_use":0,"idle":0,"waiting":0}]}
   ```

4. Every `circuit_breaker_cooldown` (5s) exactly one probe connection is
   allowed through — the half-open state is taken with a compare-and-swap,
   so a recovering database sees one attempt, not one per waiting client.
5. When the probe succeeds the breaker closes and traffic resumes. **No
   restart is required**, and the readiness probe flips back to 200.

The thing to configure here is your orchestrator, not pgman: point the
readiness probe at `/ready` so a pooler that cannot reach its database
stops receiving traffic.

---

## Going back to PgBouncer

Worth writing down before you need it.

pgman deliberately speaks PgBouncer's operational vocabulary — the
`SHOW` commands, `PAUSE`/`RESUME`/`RECONNECT`, and the `pgbouncer_*`
metric names — so the rollback is a configuration change rather than a
migration:

1. Translate `config.yaml` back to `pgbouncer.ini`. The pool settings
   map one to one: `limit` → `default_pool_size`, `pool_mode` →
   `pool_mode`, `max_client_conn` → `max_client_conn`,
   `server_idle_timeout`/`server_lifetime`/`server_check_delay` keep
   their names.
2. Set `server_reset_query_always = 1` if you want to keep the isolation
   pgman was giving you. Leaving it unset is PgBouncer's default and is
   weaker; see above.
3. Point PgBouncer at the same port pgman was listening on. Clients need
   no change: both speak the Postgres wire protocol, and nothing about a
   client connection is pgman-specific.
4. Your Grafana dashboards keep working — that is what the `pgbouncer_*`
   metric names are for — though the `pgman_*` series stop.

What does not survive the trip: the acquire-wait histogram, the admin
UI, per-user backend identities (`backend_users` has no PgBouncer
equivalent beyond one `user=` per database), and SCRAM pass-through
behaves differently.
