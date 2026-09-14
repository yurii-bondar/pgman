// Package main — HBA (Host-Based Authentication) rules, PgBouncer-
// compatible auth_hba_file format.
//
// Line format (whitespace-separated, one rule per line):
//
//	TYPE  DATABASE  USER  ADDRESS  METHOD
//
// Where:
//
//	TYPE     — one of host, hostssl, hostnossl
//	DATABASE — exact name, "all", or comma-separated list
//	USER     — exact name, "all", or comma-separated list
//	ADDRESS  — CIDR (e.g. 10.0.0.0/8, 2001:db8::/32), "all", or "samehost"
//	METHOD   — one of trust, reject, scram-sha-256
//
// Lines beginning with `#` and blank lines are ignored. Rules are
// evaluated in order; the first match wins.
//
// This is a strict subset of Postgres/PgBouncer's grammar — no md5,
// no password, no cert, no ldap, no user maps. Extend later if needed.
package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// lookupUsernameByUID resolves an OS UID to its login name via os/user.
// Extracted for testability (we can shim it in unit tests) and to keep
// the auth path readable.
var lookupUsernameByUID = func(uid uint32) (string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// HBAConnType constrains a rule to a matching connection type. Values
// mirror pg_hba.conf.
type HBAConnType int

const (
	HBAHostAny   HBAConnType = iota // host — matches both TLS and plain TCP
	HBAHostSSL                      // hostssl — TCP + TLS only
	HBAHostNoSSL                    // hostnossl — TCP + plain only
	HBALocal                        // local — Unix-domain socket only
)

// HBAMethod selects the auth exchange after a rule matches.
type HBAMethod string

const (
	HBAMethodTrust  HBAMethod = "trust"
	HBAMethodReject HBAMethod = "reject"
	HBAMethodSCRAM  HBAMethod = "scram-sha-256"
	// HBAMethodPeer: for Unix-socket clients only. Reads SO_PEERCRED
	// off the connecting process and verifies its OS username matches
	// the startup's `user` param. Same semantics as Postgres's own
	// `peer` method — the classic Unix "your uid is your identity"
	// trust model.
	HBAMethodPeer HBAMethod = "peer"
	// HBAMethodCert: mTLS-based identity. The client MUST have
	// presented a certificate during the TLS handshake, verified
	// against tls_client_ca_file. The cert's Common Name must equal
	// the startup's `user` param. No password exchange happens.
	HBAMethodCert HBAMethod = "cert"
)

// HBARule is one parsed line from the auth_hba_file.
type HBARule struct {
	Type      HBAConnType
	Databases []string   // exact names or "all"
	Users     []string   // exact names or "all"
	Net       *net.IPNet // nil means "all"
	Samehost  bool       // "samehost" — allow only loopback

	Method HBAMethod

	// LineNum is the 1-based line number in the source file, kept for
	// error messages / audit logs.
	LineNum int
}

// LoadHBAFile parses an auth_hba_file. Empty path returns (nil, nil).
func LoadHBAFile(path string) ([]HBARule, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("hba: open %s: %w", path, err)
	}
	defer f.Close()

	var rules []HBARule
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		rule, err := parseHBALine(raw)
		if err != nil {
			return nil, fmt.Errorf("hba: line %d: %w", line, err)
		}
		rule.LineNum = line
		rules = append(rules, rule)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("hba: scan: %w", err)
	}
	return rules, nil
}

func parseHBALine(raw string) (HBARule, error) {
	fields := strings.Fields(raw)
	if len(fields) < 5 {
		return HBARule{}, errors.New("expected 5 fields: TYPE DATABASE USER ADDRESS METHOD")
	}

	var rule HBARule
	switch strings.ToLower(fields[0]) {
	case "host":
		rule.Type = HBAHostAny
	case "hostssl":
		rule.Type = HBAHostSSL
	case "hostnossl":
		rule.Type = HBAHostNoSSL
	case "local":
		rule.Type = HBALocal
	default:
		return HBARule{}, fmt.Errorf("unknown connection type %q (want host / hostssl / hostnossl / local)", fields[0])
	}

	rule.Databases = splitCSV(fields[1])
	rule.Users = splitCSV(fields[2])

	switch strings.ToLower(fields[3]) {
	case "all":
		// leave rule.Net nil, samehost false — matches any address
	case "samehost":
		rule.Samehost = true
	default:
		_, ipnet, err := net.ParseCIDR(fields[3])
		if err != nil {
			return HBARule{}, fmt.Errorf("invalid ADDRESS %q: %w", fields[3], err)
		}
		rule.Net = ipnet
	}

	switch strings.ToLower(fields[4]) {
	case "trust":
		rule.Method = HBAMethodTrust
	case "reject":
		rule.Method = HBAMethodReject
	case "scram-sha-256":
		rule.Method = HBAMethodSCRAM
	case "peer":
		rule.Method = HBAMethodPeer
	case "cert":
		rule.Method = HBAMethodCert
	default:
		return HBARule{}, fmt.Errorf("unsupported METHOD %q (want trust / reject / scram-sha-256 / peer / cert)", fields[4])
	}

	return rule, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// MatchHBA walks rules in order and returns the first rule that matches
// the connection triple (tls state, remote IP, user, database). Returns
// (nil, false) if nothing matched — callers decide whether that's a
// hard deny or a fallback. isUnix flags whether the connection came
// in over a Unix-domain socket — needed to correctly gate TYPE=local
// rules (which match ONLY those) vs host/hostssl/hostnossl (which
// don't match Unix sockets at all).
func MatchHBA(rules []HBARule, tls, isUnix bool, remoteIP net.IP, user, database string) (*HBARule, bool) {
	for i := range rules {
		r := &rules[i]
		if !matchHBAType(r.Type, tls, isUnix) {
			continue
		}
		if !matchHBAList(r.Databases, database) {
			continue
		}
		if !matchHBAList(r.Users, user) {
			continue
		}
		if !matchHBAAddr(r, remoteIP) {
			continue
		}
		return r, true
	}
	return nil, false
}

func matchHBAType(t HBAConnType, tls, isUnix bool) bool {
	switch t {
	case HBALocal:
		return isUnix
	case HBAHostAny:
		return !isUnix // host/hostssl/hostnossl only match TCP, mirrors PG semantics
	case HBAHostSSL:
		return !isUnix && tls
	case HBAHostNoSSL:
		return !isUnix && !tls
	}
	return false
}

func matchHBAList(list []string, val string) bool {
	for _, x := range list {
		if x == "all" || strings.EqualFold(x, val) {
			return true
		}
	}
	return false
}

func matchHBAAddr(r *HBARule, ip net.IP) bool {
	if r.Samehost {
		return ip != nil && ip.IsLoopback()
	}
	if r.Net == nil {
		return true
	}
	return ip != nil && r.Net.Contains(ip)
}

// HBAAuth wraps an inner AuthBackend (typically SCRAMAuth) and gates
// every incoming connection through an HBA rule set first. Rules
// determine the effective method:
//
//	trust           → skip inner auth, accept
//	reject          → immediately fail with a FATAL ErrorResponse
//	scram-sha-256   → delegate to inner (which must speak SCRAM)
//
// If no rule matches, the connection is rejected — matches PgBouncer's
// pg_hba.conf semantics ("if the client passes no HBA rule, connection
// is refused").
type HBAAuth struct {
	Rules []HBARule
	Inner AuthBackend // used for METHOD=scram-sha-256
}

// NewHBAAuth builds an HBA-gated auth backend. If rules is empty,
// returns inner unchanged — no HBA, no gating.
func NewHBAAuth(rules []HBARule, inner AuthBackend) AuthBackend {
	if len(rules) == 0 {
		return inner
	}
	return &HBAAuth{Rules: rules, Inner: inner}
}

func (h *HBAAuth) Authenticate(pg *pgproto3.Backend, conn net.Conn, startup *pgproto3.StartupMessage) error {
	_, isTLS := conn.(*tls.Conn)
	_, isUnix := conn.(*net.UnixConn)
	remoteIP := remoteAddrIP(conn)
	user := startup.Parameters["user"]
	database := startup.Parameters["database"]

	rule, ok := MatchHBA(h.Rules, isTLS, isUnix, remoteIP, user, database)
	if !ok {
		slog.Info("hba: no rule matched", "user", user, "database", database, "remote_ip", remoteIP, "tls", isTLS, "unix", isUnix)
		hbaReject(pg, "no pg_hba.conf entry for host \""+remoteIP.String()+"\", user \""+user+"\", database \""+database+"\"")
		return fmt.Errorf("hba: no matching rule")
	}

	switch rule.Method {
	case HBAMethodTrust:
		slog.Debug("hba: trust", "line", rule.LineNum, "user", user, "database", database, "remote_ip", remoteIP)
		return nil
	case HBAMethodReject:
		slog.Info("hba: reject", "line", rule.LineNum, "user", user, "database", database, "remote_ip", remoteIP)
		auditLog("hba_reject",
			"line", rule.LineNum,
			"user", user,
			"database", database,
			"remote_ip", remoteIP.String())
		hbaReject(pg, fmt.Sprintf("pg_hba.conf rejects connection for host %q, user %q, database %q", remoteIP, user, database))
		return fmt.Errorf("hba: rejected by rule at line %d", rule.LineNum)
	case HBAMethodSCRAM:
		// Delegate to the SCRAM backend. It handles all the exchange
		// and returns an error if the client fails to prove the
		// password — the outer startup loop translates that into the
		// FATAL 28P01 response, same as without HBA.
		return h.Inner.Authenticate(pg, conn, startup)
	case HBAMethodPeer:
		return h.authenticatePeer(pg, conn, user, isUnix, rule.LineNum)
	case HBAMethodCert:
		return h.authenticateCert(pg, conn, user, isTLS, rule.LineNum)
	}
	return fmt.Errorf("hba: unhandled method %q", rule.Method)
}

// authenticateCert enforces mTLS identity: the client MUST have
// presented a certificate during the TLS handshake, and that cert's
// Common Name MUST equal the startup's `user` param. Anything else is
// a hard reject with FATAL 28000.
func (h *HBAAuth) authenticateCert(pg *pgproto3.Backend, conn net.Conn, requestedUser string, isTLS bool, ruleLine int) error {
	if !isTLS {
		hbaReject(pg, "METHOD=cert requires a TLS connection")
		return fmt.Errorf("hba: cert method matched a non-TLS connection at line %d", ruleLine)
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		hbaReject(pg, "METHOD=cert: not a TLS connection")
		return fmt.Errorf("hba: cert method — conn is %T, not *tls.Conn (line %d)", conn, ruleLine)
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		hbaReject(pg, "METHOD=cert requires a client certificate")
		return fmt.Errorf("hba: cert method — no client cert presented (line %d)", ruleLine)
	}
	cn := state.PeerCertificates[0].Subject.CommonName
	if cn != requestedUser {
		slog.Info("hba: cert CN mismatch",
			"line", ruleLine, "cn", cn, "requested_user", requestedUser)
		auditLog("cert_auth_fail",
			"line", ruleLine, "cn", cn, "requested_user", requestedUser)
		hbaReject(pg, fmt.Sprintf("certificate CN %q does not match requested user %q", cn, requestedUser))
		return fmt.Errorf("hba: cert CN %q != user %q at line %d", cn, requestedUser, ruleLine)
	}
	slog.Debug("hba: cert accepted", "line", ruleLine, "cn", cn)
	return nil
}

// authenticatePeer reads SO_PEERCRED off the Unix socket, resolves the
// UID to an OS username, and requires exact match with startup's user.
// Any mismatch (or platform without SO_PEERCRED) is a hard reject.
func (h *HBAAuth) authenticatePeer(pg *pgproto3.Backend, conn net.Conn, requestedUser string, isUnix bool, ruleLine int) error {
	if !isUnix {
		hbaReject(pg, "METHOD=peer requires a Unix-domain socket")
		return fmt.Errorf("hba: peer method matched a non-unix connection at line %d", ruleLine)
	}
	if !peerCredSupported {
		hbaReject(pg, "METHOD=peer is not supported on this platform")
		return fmt.Errorf("hba: peer method requested but SO_PEERCRED unsupported (line %d)", ruleLine)
	}
	uid, _, pid, err := getPeerCred(conn)
	if err != nil {
		hbaReject(pg, "cannot read peer credentials")
		return fmt.Errorf("hba: getPeerCred: %w", err)
	}
	osUser, err := lookupUsernameByUID(uid)
	if err != nil {
		hbaReject(pg, fmt.Sprintf("cannot resolve OS user for uid=%d", uid))
		return fmt.Errorf("hba: lookup uid %d: %w", uid, err)
	}
	if osUser != requestedUser {
		slog.Info("hba: peer identity mismatch",
			"line", ruleLine, "os_user", osUser, "requested_user", requestedUser,
			"uid", uid, "pid", pid)
		hbaReject(pg, fmt.Sprintf("peer authentication failed for user %q (OS user %q)", requestedUser, osUser))
		return fmt.Errorf("hba: peer identity mismatch at line %d", ruleLine)
	}
	slog.Debug("hba: peer accepted", "line", ruleLine, "user", requestedUser, "uid", uid, "pid", pid)
	return nil
}

// remoteAddrIP extracts the net.IP from conn.RemoteAddr(); returns nil
// for pipe-connected test conns (they have no meaningful address).
func remoteAddrIP(conn net.Conn) net.IP {
	if conn == nil {
		return nil
	}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP
	}
	return nil
}

// hbaReject emits a FATAL ErrorResponse with SQLSTATE 28000
// (invalid_authorization_specification) — same code Postgres itself
// uses for HBA denials, so clients that key off SQLSTATE get the
// familiar signal.
func hbaReject(pg *pgproto3.Backend, msg string) {
	pg.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     "28000",
		Message:  msg,
	})
	_ = pg.Flush()
}
