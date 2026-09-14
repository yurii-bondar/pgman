// Package main — Unix-domain socket listener.
//
// Local clients (co-located apps, cron jobs, ad-hoc psql) benefit from
// a Unix socket instead of TCP: no localhost round trip, no TCP
// handshake overhead, and — critically — filesystem permissions +
// SO_PEERCRED identity binding replace the whole password exchange
// when combined with HBA METHOD=peer.
//
// Path convention matches libpq: <unix_socket_dir>/.s.PGSQL.<port>.
// psql -h /tmp finds this automatically.
package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// openUnixSocket binds a Unix-domain listener at the libpq-style path
// under socketDir and returns it. modeStr is an octal string ("0777",
// "0770", …) — parsed here so the config layer stays dumb-string.
//
// If the socket file already exists (leftover from a crashed prior
// process), it's removed first. This mirrors PgBouncer's behavior
// and is safe because bind(2) on Unix sockets fails if the path is
// occupied — leaving the stale file would prevent restart.
func openUnixSocket(socketDir, listenAddr, modeStr string) (net.Listener, string, error) {
	// Derive the port from the TCP listen addr so both listeners use
	// the same key. Fallback to 5432 if listenAddr is host-only or empty.
	port := 5432
	if _, portStr, err := net.SplitHostPort(listenAddr); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	// Ensure the directory exists.
	if err := os.MkdirAll(socketDir, 0o755); err != nil {
		return nil, "", fmt.Errorf("mkdir %s: %w", socketDir, err)
	}
	sockPath := filepath.Join(socketDir, fmt.Sprintf(".s.PGSQL.%d", port))

	// Remove stale socket. Ignore not-exist; propagate other errors so
	// the operator sees a permission problem instead of a mysterious
	// "address already in use" from Listen.
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		return nil, "", fmt.Errorf("remove stale socket %s: %w", sockPath, err)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, "", fmt.Errorf("listen unix %s: %w", sockPath, err)
	}

	// Apply the requested filesystem mode. Default to 0777 (broadest —
	// matches PgBouncer default) if empty or unparseable.
	mode := os.FileMode(0o777)
	if s := strings.TrimSpace(modeStr); s != "" {
		if v, err := strconv.ParseUint(s, 8, 32); err == nil {
			mode = os.FileMode(v)
		}
	}
	if err := os.Chmod(sockPath, mode); err != nil {
		// Best-effort cleanup on a path we're already failing out of.
		// Logged rather than dropped: a socket file left behind makes
		// the next start fail with a confusing EADDRINUSE.
		if cerr := ln.Close(); cerr != nil {
			slog.Warn("unix socket: close after failed chmod", "path", sockPath, "err", cerr)
		}
		if rerr := os.Remove(sockPath); rerr != nil {
			slog.Warn("unix socket: remove after failed chmod", "path", sockPath, "err", rerr)
		}
		return nil, "", fmt.Errorf("chmod %s: %w", sockPath, err)
	}

	return ln, sockPath, nil
}
