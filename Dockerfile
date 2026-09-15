# ---- Build stage -----------------------------------------------------
#
# Pinned to BUILDPLATFORM, not TARGETPLATFORM: the compiler runs natively
# on the runner and cross-compiles instead of running under QEMU. For a
# multi-arch build that is the difference between a Go toolchain running
# at native speed and one emulated instruction by instruction — minutes
# per architecture, for a binary that needs no emulation to produce.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# TARGETOS/TARGETARCH are supplied by buildx for each platform in the
# manifest list; they default to the build host when building plainly.
ARG TARGETOS
ARG TARGETARCH
# CGO_ENABLED=0 for a fully static binary that runs on distroless/scratch.
# -trimpath removes local filesystem paths from the binary (security).
# -ldflags shrinks the binary and embeds version info.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /pgman .

# ---- Runtime stage ---------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /pgman /pgman

# Default ports:
#   6435  Postgres wire (data plane)
#   8080  Prometheus /metrics
#   8081  Admin UI + API
EXPOSE 6435 8080 8081

# Run as nonroot (UID 65534) — distroless/static already sets this via
# the :nonroot tag, but being explicit documents the intent.
USER nonroot:nonroot

# The binary probes itself, because there is no shell, curl or wget in a
# distroless image to write this with — and adding one would put a
# package manager's worth of attack surface next to a process that
# terminates database credentials.
#
# It asks /ready, so the check follows readiness: a container draining on
# SIGTERM reports unhealthy, which is what stops Swarm or Compose from
# sending it new work. Kubernetes ignores this and uses its own probes
# against the same endpoint.
#
# start-period is generous because readiness waits on the first backend
# dial, and a Postgres coming up alongside it can take a while.
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD ["/pgman", "-config", "/etc/pgman/config.yaml", "-health-check"]

ENTRYPOINT ["/pgman"]
CMD ["-config", "/etc/pgman/config.yaml"]
