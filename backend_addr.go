package main

import (
	"fmt"
	"net"
	"strings"
)

// validateBackendAddr rejects backend addresses that a pool must never
// be pointed at from the admin API.
//
// The admin UI lets an operator create a pool by typing a host and port,
// which turns pgman into a dialer that speaks from inside the cluster.
// Without this check that is a server-side request forgery primitive:
// the classic target is the cloud instance-metadata service at
// 169.254.169.254, whose response is temporary credentials for the node
// the proxy runs on.
//
// Scope is deliberately narrow. This is not an allowlist and does not
// try to decide which of your databases are legitimate — it blocks the
// address families that are never a Postgres backend and are the known
// pivot targets:
//
//   - link-local (169.254.0.0/16, fe80::/10) — cloud metadata
//   - multicast and unspecified (0.0.0.0, ::)
//
// Loopback is deliberately allowed: running pgman next to Postgres on
// the same host or in the same Pod is a normal deployment.
//
// Operators who need a real allowlist should not expose the admin API's
// pool-creation endpoint at all; pools defined in YAML skip this path.
func validateBackendAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("backend_addr is required")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("backend_addr %q must be host:port: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("backend_addr %q has no host", addr)
	}
	if port == "" {
		return fmt.Errorf("backend_addr %q has no port", addr)
	}

	// A literal IP can be judged directly. A hostname cannot: resolving
	// it here would be a TOCTOU check anyway, since DNS can return a
	// different answer by the time the pool dials. We check what we can
	// and rely on the addresses below being unroutable names in
	// practice.
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return nil
	}
	return checkBackendIP(ip, addr)
}

func checkBackendIP(ip net.IP, addr string) error {
	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("backend_addr %q: refusing the unspecified address", addr)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return fmt.Errorf("backend_addr %q: link-local addresses are refused "+
			"(this range hosts cloud instance metadata, not databases)", addr)
	case ip.IsMulticast():
		return fmt.Errorf("backend_addr %q: refusing a multicast address", addr)
	}
	return nil
}
