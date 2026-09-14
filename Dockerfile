# ---- Build stage -----------------------------------------------------
FROM golang:1.27.0-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 for a fully static binary that runs on distroless/scratch.
# -trimpath removes local filesystem paths from the binary (security).
# -ldflags shrinks the binary and embeds version info.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
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

ENTRYPOINT ["/pgman"]
CMD ["-config", "/etc/pgman/config.yaml"]
