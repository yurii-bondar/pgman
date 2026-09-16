#!/usr/bin/env bash
#
# Compare pgman against PgBouncer on the same Postgres, under the same
# load, with the same pool settings.
#
# The point of this script is not to produce a number that flatters
# pgman. It is to produce a number somebody else can reproduce and
# argue with, because "why would I use this instead of PgBouncer" has
# no honest answer that is only about YAML and a dashboard.
#
# ---- What is held equal --------------------------------------------
#
# Both poolers run as containers on the same Docker network, against the
# same Postgres container, publishing to loopback. That symmetry is
# deliberate: running one natively and one in Docker would measure
# Docker's network stack on one side only, and on macOS that difference
# is larger than the difference between the poolers.
#
# Equal on both sides: pool size, pool mode, max_client_conn, the query,
# the client library, the client count, warm-up and measurement windows.
#
# ---- The one setting that cannot be defaulted -----------------------
#
# PgBouncer in transaction mode does NOT run server_reset_query unless
# server_reset_query_always is set; pgman runs it always. Verified on
# PgBouncer 1.25.2: with the default, `SET work_mem='77MB'` in one
# client is still in effect for the next client on the same backend.
#
# So "defaults vs defaults" compares a pooler that scrubs session state
# against one that does not, and the one doing less work wins a race it
# was not running. Hence --reset:
#
#   matched  (default) both scrub. Measures proxy overhead.
#   off      neither scrubs. Measures the floor, and is what PgBouncer
#            gives you out of the box.
#
# Run both if you want the full picture; the difference between them is
# what DISCARD ALL costs.
#
# ---- Usage ----------------------------------------------------------
#
#   docker compose up -d postgres
#   scripts/bench-vs-pgbouncer.sh                       # core matrix
#   scripts/bench-vs-pgbouncer.sh --duration 30s        # longer runs
#   scripts/bench-vs-pgbouncer.sh --reset off
#   scripts/bench-vs-pgbouncer.sh --targets "pgman" --modes transaction
#
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)

# ---- Defaults -------------------------------------------------------

DURATION=15s
WARMUP=3s
POOL_SIZE=50
CLIENTS="10 100 1000"
PROTOCOLS="simple extended prepared"
MODES="transaction session"
TARGETS="direct pgbouncer pgman"
RESET=matched
MAX_CLIENT_CONN=2000
OUT=docs/benchmarks.md
RENDER_ONLY=0
NETWORK=pgman_default
PG_CONTAINER=pgman-postgres-1
PGBOUNCER_IMAGE=edoburu/pgbouncer:latest
PGMAN_IMAGE=pgman-bench:local
POOLER_CONTAINER=bench-pooler
POOLER_PORT=""
KEEP=0

while [ $# -gt 0 ]; do
	case "$1" in
	--duration) DURATION=$2; shift 2 ;;
	--warmup) WARMUP=$2; shift 2 ;;
	--pool-size) POOL_SIZE=$2; shift 2 ;;
	--clients) CLIENTS=$2; shift 2 ;;
	--protocols) PROTOCOLS=$2; shift 2 ;;
	--modes) MODES=$2; shift 2 ;;
	--targets) TARGETS=$2; shift 2 ;;
	--reset) RESET=$2; shift 2 ;;
	--max-client-conn) MAX_CLIENT_CONN=$2; shift 2 ;;
	--out) OUT=$2; shift 2 ;;
	--network) NETWORK=$2; shift 2 ;;
	--render-only) RENDER_ONLY=1; shift ;;
	--keep) KEEP=1; shift ;;
	-h | --help) sed -n '2,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

case "$RESET" in
matched | off) ;;
*) echo "--reset must be 'matched' or 'off', got '$RESET'" >&2; exit 2 ;;
esac

WORKDIR=$(mktemp -d)
RESULTS="$WORKDIR/results.txt"
NOTES="$WORKDIR/notes.txt"
: >"$RESULTS"
: >"$NOTES"

# Inlined rather than calling stop_pooler, which is defined further
# down: a trap that fires during preflight would otherwise die on an
# undefined function instead of cleaning up.
cleanup() {
	docker rm -f "$POOLER_CONTAINER" >/dev/null 2>&1 || true
	[ "$KEEP" = 1 ] || rm -rf "$WORKDIR"
}
trap cleanup EXIT

say() { printf '\033[1;36m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m!!!\033[0m %s\n' "$*" >&2; }
die() {
	printf '\033[1;31mxxx\033[0m %s\n' "$*" >&2
	exit 1
}

# ---- Preflight ------------------------------------------------------

command -v docker >/dev/null || die "docker is not on PATH"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable"

docker network inspect "$NETWORK" >/dev/null 2>&1 ||
	die "docker network '$NETWORK' does not exist — run 'docker compose up -d postgres' first"

docker inspect "$PG_CONTAINER" >/dev/null 2>&1 ||
	die "container '$PG_CONTAINER' is not running — run 'docker compose up -d postgres' first"

# The host port Postgres is published on: the direct baseline connects
# through it, so it is measured over the same loopback hop the poolers
# are, not over a unix socket they do not get to use.
PG_HOST_PORT=$(docker port "$PG_CONTAINER" 5432/tcp | head -1 | sed 's/.*://')
[ -n "$PG_HOST_PORT" ] || die "could not determine the published port of $PG_CONTAINER"

PG_MAX_CONN=$(docker exec "$PG_CONTAINER" psql -U pgman_test -d pgman_test -tAc 'show max_connections' | tr -d '[:space:]')
say "Postgres on host port $PG_HOST_PORT, max_connections=$PG_MAX_CONN"

# Anything else busy on this machine is competing for the cores the
# pooler needs, and it does not compete evenly: a neighbour that wakes
# up for two seconds lands in one cell's p99 and not another's. That
# turns run-to-run noise into what looks like a difference between
# poolers, which is the single easiest way to publish a wrong number.
#
# The `|| true` is load-bearing: with nothing else running, grep matches
# nothing and exits 1, and under `set -o pipefail` that would abort the
# run — the check would break precisely when the machine is clean.
NOISE=$(docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' 2>/dev/null |
	grep -v "^$PG_CONTAINER " | grep -v "^$POOLER_CONTAINER " |
	awk '{ gsub("%","",$2); if ($2+0 > 5) printf "%s(%.0f%%) ", $1, $2 }' || true)
if [ -n "$NOISE" ]; then
	warn "other containers are using CPU: $NOISE"
	warn "these numbers will be noisy — stop them, or treat the results as indicative only"
fi

if [ "$POOL_SIZE" -ge "$PG_MAX_CONN" ]; then
	die "pool size $POOL_SIZE is at or above Postgres max_connections $PG_MAX_CONN"
fi

# ---- Config generation ----------------------------------------------

# pgbouncer_ini writes the config for one (mode, reset) combination.
#
# max_prepared_statements is set explicitly because PgBouncer defaults
# it to 0 — statements would not be tracked at all and the "prepared"
# row would measure a fallback path rather than the feature. 200 is
# pgman's default, so both track the same number.
pgbouncer_ini() {
	local mode=$1 always=0
	[ "$RESET" = matched ] && always=1
	cat >"$WORKDIR/pgbouncer.ini" <<EOF
[databases]
pgman_test = host=postgres port=5432 dbname=pgman_test user=pgman_test password=pgman_test

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = trust
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = $mode
max_client_conn = $MAX_CLIENT_CONN
default_pool_size = $POOL_SIZE
server_reset_query = DISCARD ALL
server_reset_query_always = $always
max_prepared_statements = 200
query_wait_timeout = 30
ignore_startup_parameters = extra_float_digits,options,search_path,application_name
EOF
	printf '"pgman_test" "pgman_test"\n' >"$WORKDIR/userlist.txt"
	chmod 644 "$WORKDIR/pgbouncer.ini" "$WORKDIR/userlist.txt"
}

# pgman_config mirrors pgbouncer_ini knob for knob. An empty
# server_reset_query is how pgman spells "do not scrub", which is what
# PgBouncer's transaction-mode default amounts to.
pgman_config() {
	local mode=$1 reset='"DISCARD ALL"'
	[ "$RESET" = off ] && reset='" "'
	cat >"$WORKDIR/pgman.yaml" <<EOF
listen_addr: ":6432"
metrics_addr: ":8080"
admin_addr: "0.0.0.0:8081"
max_client_conn: $MAX_CLIENT_CONN
client_login_timeout: 30s
query_wait_timeout: 30s
server_reset_query: $reset
max_prepared_statements: 200
server_idle_timeout: 5m
server_lifetime: 30m
min_pool_size: 1
log_format: text
log_level: warn
allow_insecure_trust_auth: true
pools:
  pgman_test:
    backend_dsn: "postgres://pgman_test:pgman_test@postgres:5432/pgman_test?sslmode=disable"
    backend_addr: "postgres:5432"
    pool_mode: $mode
    limit: $POOL_SIZE
EOF
	chmod 644 "$WORKDIR/pgman.yaml"
}

# ---- Pooler lifecycle -----------------------------------------------

stop_pooler() {
	docker rm -f "$POOLER_CONTAINER" >/dev/null 2>&1 || true
}

# free_port asks the kernel for an unused port rather than guessing, so
# two runs on the same machine cannot collide.
free_port() {
	python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'
}

start_pooler() {
	local target=$1 mode=$2
	stop_pooler
	POOLER_PORT=$(free_port)

	case "$target" in
	pgbouncer)
		pgbouncer_ini "$mode"
		docker run -d --name "$POOLER_CONTAINER" --network "$NETWORK" \
			-p "127.0.0.1:$POOLER_PORT:6432" \
			-v "$WORKDIR/pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro" \
			-v "$WORKDIR/userlist.txt:/etc/pgbouncer/userlist.txt:ro" \
			--entrypoint pgbouncer "$PGBOUNCER_IMAGE" /etc/pgbouncer/pgbouncer.ini >/dev/null
		;;
	pgman)
		pgman_config "$mode"
		docker run -d --name "$POOLER_CONTAINER" --network "$NETWORK" \
			-p "127.0.0.1:$POOLER_PORT:6432" \
			-v "$WORKDIR/pgman.yaml:/etc/pgman/config.yaml:ro" \
			"$PGMAN_IMAGE" -config /etc/pgman/config.yaml >/dev/null
		;;
	*) die "unknown target '$target'" ;;
	esac

	# Wait for the port to answer rather than sleeping a guess: a slow
	# image pull or a config error should fail loudly here, not show up
	# later as a run with a suspiciously low op count.
	local deadline=$((SECONDS + 30))
	while [ $SECONDS -lt $deadline ]; do
		if (exec 3<>/dev/tcp/127.0.0.1/"$POOLER_PORT") 2>/dev/null; then
			exec 3<&- 3>&-
			return 0
		fi
		if ! docker ps --filter "name=$POOLER_CONTAINER" --filter status=running -q | grep -q .; then
			docker logs "$POOLER_CONTAINER" 2>&1 | tail -20 >&2
			die "$target exited during startup"
		fi
		sleep 0.3
	done
	docker logs "$POOLER_CONTAINER" 2>&1 | tail -20 >&2
	die "$target never accepted connections on port $POOLER_PORT"
}

# ---- Memory sampling ------------------------------------------------
#
# Sampled from outside the process for both poolers, by the same
# command, so the number means the same thing on both sides. A pooler's
# own reporting would not be comparable: pgman would report Go heap and
# PgBouncer would report nothing.

RSS_SAMPLER_PID=""

start_rss_sampler() {
	local file=$1
	: >"$file"
	(
		while :; do
			docker stats --no-stream --format '{{.MemUsage}}' "$POOLER_CONTAINER" 2>/dev/null |
				awk '{print $1}' >>"$file"
			sleep 0.5
		done
	) &
	RSS_SAMPLER_PID=$!
}

stop_rss_sampler() {
	[ -n "$RSS_SAMPLER_PID" ] || return 0
	kill "$RSS_SAMPLER_PID" 2>/dev/null || true
	wait "$RSS_SAMPLER_PID" 2>/dev/null || true
	RSS_SAMPLER_PID=""
}

# peak_rss_mib turns docker's human-readable sizes into one number.
peak_rss_mib() {
	local file=$1
	[ -s "$file" ] || { echo "-"; return; }
	awk '
		/MiB$/ { v = $0; sub("MiB","",v); n = v + 0 }
		/GiB$/ { v = $0; sub("GiB","",v); n = (v + 0) * 1024 }
		/KiB$/ { v = $0; sub("KiB","",v); n = (v + 0) / 1024 }
		n > max { max = n }
		END { if (max > 0) printf "%.1f", max; else print "-" }
	' "$file"
}

# ---- One cell of the matrix -----------------------------------------

run_cell() {
	local target=$1 mode=$2 protocol=$3 clients=$4 dsn=$5
	local rssfile="$WORKDIR/rss.txt" rss="-"

	if [ "$target" != direct ]; then
		start_rss_sampler "$rssfile"
	fi

	# tests/integration is its own module, so the test has to be run
	# from inside it — `go test ./tests/integration` from the repo root
	# fails with "main module does not contain package".
	local log="$WORKDIR/run.log"
	set +e
	env \
		PGMAN_BENCH_DSN="$dsn" \
		PGMAN_BENCH_LABEL="$target/$mode" \
		PGMAN_BENCH_PROTOCOL="$protocol" \
		PGMAN_BENCH_CLIENTS="$clients" \
		PGMAN_BENCH_DURATION="$DURATION" \
		PGMAN_BENCH_WARMUP="$WARMUP" \
		go test -C "$REPO_ROOT/tests/integration" \
		-tags integration -count=1 -timeout 20m \
		-run '^TestBenchTarget$' -v . >"$log" 2>&1
	local rc=$?
	set -e

	if [ "$target" != direct ]; then
		stop_rss_sampler
		rss=$(peak_rss_mib "$rssfile")
	fi

	local line
	line=$(grep -o "BENCHRESULT .*" "$log" | tail -1 || true)
	if [ -z "$line" ]; then
		warn "$target/$mode $protocol $clients clients: no result (exit $rc)"
		tail -15 "$log" >&2
		echo "target=$target mode=$mode protocol=$protocol clients=$clients conns=0 qps=0 p50_ms=0 p95_ms=0 p99_ms=0 max_ms=0 ops=0 fails=0 rss_mib=$rss status=failed" >>"$RESULTS"
		return 0
	fi

	echo "${line#BENCHRESULT } mode=$mode rss_mib=$rss status=ok" |
		sed "s#target=$target/$mode#target=$target#" >>"$RESULTS"

	# A cell with failures is only readable with the reason attached, so
	# the reason is kept next to the row it belongs to.
	local why
	why=$(grep -o "BENCHERR .*" "$log" | tail -1 || true)
	if [ -n "$why" ]; then
		echo "$target | $mode | $protocol | $clients | ${why#BENCHERR }" >>"$NOTES"
	fi

	printf '    %-18s %-9s %5s clients  %8s QPS  p99 %7s ms  rss %6s MiB\n' \
		"$target/$mode" "$protocol" "$clients" \
		"$(field qps "$line")" "$(field p99_ms "$line")" "$rss" >&2
}

field() {
	# shellcheck disable=SC2001
	echo "$2" | sed "s/.*$1=\([^ ]*\).*/\1/"
}

# ---- Raw measurements ------------------------------------------------
#
# Every measured row is kept next to the report, and the report can be
# regenerated from it with --render-only.
#
# This exists so that improving the prose around the numbers never means
# either re-measuring for twenty minutes or hand-editing a file whose
# header says not to. Measurement and presentation are separate jobs and
# only one of them is expensive.
DATA="${OUT%.*}.data"

load_data() {
	[ -f "$DATA" ] || die "$DATA does not exist — run without --render-only first"
	grep -v '^NOTE ' "$DATA" | grep -v '^META ' >"$RESULTS" || true
	sed -n 's/^NOTE //p' "$DATA" >"$NOTES" || true
	# Metadata is restored as shell variables so the header renders the
	# conditions the numbers were taken under, not today's.
	while IFS= read -r m; do
		case "$m" in
		"META host="*) HOST_DESC=${m#META host=} ;;
		"META pg="*) PG_VERSION=${m#META pg=} ;;
		"META pgbouncer="*) PGB_VERSION=${m#META pgbouncer=} ;;
		"META pool_size="*) POOL_SIZE=${m#META pool_size=} ;;
		"META duration="*) DURATION=${m#META duration=} ;;
		"META warmup="*) WARMUP=${m#META warmup=} ;;
		"META reset="*) RESET=${m#META reset=} ;;
		"META measured_at="*) MEASURED_AT=${m#META measured_at=} ;;
		esac
	done < <(grep '^META ' "$DATA" || true)
}

save_data() {
	{
		echo "META host=$HOST_DESC"
		echo "META pg=$PG_VERSION"
		echo "META pgbouncer=$PGB_VERSION"
		echo "META pool_size=$POOL_SIZE"
		echo "META duration=$DURATION"
		echo "META warmup=$WARMUP"
		echo "META reset=$RESET"
		echo "META measured_at=$MEASURED_AT"
		cat "$RESULTS"
		sed 's/^/NOTE /' "$NOTES"
	} >"$DATA"
}

MEASURED_AT=$(date -u '+%Y-%m-%d %H:%M UTC')

if [ "$RENDER_ONLY" = 1 ]; then
	say "Re-rendering $OUT from $DATA without measuring"
	load_data
fi

# ---- Build ----------------------------------------------------------

if [ "$RENDER_ONLY" = 0 ] && echo "$TARGETS" | grep -qw pgman; then
	say "Building $PGMAN_IMAGE"
	docker build -q -t "$PGMAN_IMAGE" "$REPO_ROOT" >/dev/null
fi

# ---- Matrix ---------------------------------------------------------

if [ "$RENDER_ONLY" = 0 ]; then
say "Matrix: targets=[$TARGETS] modes=[$MODES] protocols=[$PROTOCOLS] clients=[$CLIENTS]"
say "Pool size $POOL_SIZE, ${DURATION} per cell (+${WARMUP} warm-up), reset=$RESET"

for target in $TARGETS; do
	if [ "$target" = direct ]; then
		# Postgres itself has no pool mode; running it once under the
		# transaction label keeps it one row rather than two identical
		# ones. It is a reference line, not a competitor: past
		# max_connections it simply refuses clients.
		dsn="postgres://pgman_test:pgman_test@127.0.0.1:$PG_HOST_PORT/pgman_test?sslmode=disable"
		for protocol in $PROTOCOLS; do
			for clients in $CLIENTS; do
				if [ "$clients" -ge "$PG_MAX_CONN" ]; then
					warn "direct $protocol $clients clients: skipped, above max_connections=$PG_MAX_CONN"
					continue
				fi
				run_cell direct none "$protocol" "$clients" "$dsn"
			done
		done
		continue
	fi

	for mode in $MODES; do
		say "$target, $mode pooling"
		start_pooler "$target" "$mode"
		dsn="postgres://pgman_test:pgman_test@127.0.0.1:$POOLER_PORT/pgman_test?sslmode=disable"
		for protocol in $PROTOCOLS; do
			for clients in $CLIENTS; do
				run_cell "$target" "$mode" "$protocol" "$clients" "$dsn"
			done
		done
		stop_pooler
	done
done

HOST_DESC="$(uname -s) $(uname -m), $(docker run --rm alpine nproc 2>/dev/null || echo '?') CPUs available to Docker"
# Captured whole and trimmed afterwards. Piping straight into `head -1`
# makes pgbouncer die of SIGPIPE, and under `set -o pipefail` the `||`
# fallback then fires *as well*, producing a two-line version string.
PGB_RAW=$(docker run --rm --entrypoint pgbouncer "$PGBOUNCER_IMAGE" --version 2>/dev/null || echo "PgBouncer")
PGB_VERSION=${PGB_RAW%%$'\n'*}
PG_VERSION=$(docker exec "$PG_CONTAINER" psql -U pgman_test -d pgman_test -tAc 'select version()' | cut -d, -f1)

mkdir -p "$(dirname "$OUT")"
save_data
fi

# ---- Report ---------------------------------------------------------

say "Writing $OUT"
mkdir -p "$(dirname "$OUT")"

{
	echo "<!-- Generated by scripts/bench-vs-pgbouncer.sh. Do not edit by hand. -->"
	echo
	echo "# pgman vs PgBouncer"
	echo
	echo "Measured $MEASURED_AT. Raw rows: [\`$(basename "$DATA")\`]($(basename "$DATA"))."
	echo
	echo "| Setting | Value |"
	echo "| --- | --- |"
	echo "| Host | $HOST_DESC |"
	echo "| Postgres | $PG_VERSION |"
	echo "| PgBouncer | $PGB_VERSION |"
	echo "| Pool size | $POOL_SIZE |"
	echo "| Per cell | $DURATION measured, $WARMUP warm-up discarded |"
	echo "| Reset query | $RESET |"
	echo
	cat <<'PREAMBLE'
## How to read this

Both poolers run as containers on the same Docker network, against the
same Postgres, with the same pool size, pool mode, client count, query
and client library. The load generator runs on the host and reaches
each of them over the same published-port hop.

`Reset query: matched` means both scrub session state between clients.
That is not the out-of-the-box comparison: PgBouncer skips
`server_reset_query` in transaction mode unless `server_reset_query_always`
is set, so its default leaks a `SET` from one client to the next, while
pgman always scrubs. Matching them compares proxy overhead rather than
rewarding the one doing less work.

`Conns` is how many client connections were actually established. Where
it is below `Clients`, the pooler could not give every client a usable
connection, and the row measures the ones that got through.

`direct` is Postgres with no pooler, as a reference ceiling. It has no
rows past `max_connections`, which is the entire reason poolers exist.

What this does NOT show: durability, correctness under failure, or
behaviour over hours. It is a throughput and latency snapshot on one
machine.

PREAMBLE
	echo '| Target | Mode | Protocol | Clients | Conns | QPS | p50 ms | p95 ms | p99 ms | max ms | Failed | Peak RSS MiB |'
	echo '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |'
	while read -r l; do
		[ -n "$l" ] || continue
		# shellcheck disable=SC2046
		eval $(echo "$l" | tr ' ' '\n' | sed 's/^/R_/')
		printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
			"$R_target" "$R_mode" "$R_protocol" "$R_clients" "$R_conns" "$R_qps" \
			"$R_p50_ms" "$R_p95_ms" "$R_p99_ms" "$R_max_ms" "$R_fails" "$R_rss_mib"
	done <"$RESULTS"

	if [ -s "$NOTES" ]; then
		echo
		echo '## Why the failing cells failed'
		echo
		echo 'A failure count without its cause is not a result. These are the'
		echo 'dominant error per cell, verbatim from the client.'
		echo
		echo '| Target | Mode | Protocol | Clients | Dominant error |'
		echo '| --- | --- | --- | ---: | --- |'
		sed 's/^/| /; s/$/ |/' "$NOTES"
	fi
} >"$OUT"

say "Done. $(grep -c . "$RESULTS") rows in $OUT"
