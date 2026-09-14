package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// adminAuth is the middleware wrapping every admin-plane handler
// (dashboard, SSE, pool CRUD, session cancel). It offers three
// mutually-optional authentication modes and always applies CSRF
// checks on state-mutating methods:
//
//  1. mTLS (highest priority when configured). A client whose TLS
//     certificate was verified by the pool's ClientCAs (see
//     buildAdminTLSConfig) AND whose CN is in AdminMTLSAllowedCNs
//     (or the allowlist is empty) is authenticated as the CN.
//
//  2. OIDC Bearer token (when AdminOIDCIssuerURL is set). The
//     Authorization: Bearer <id_token> header is verified against
//     the issuer's JWKS, and the token's email/sub claim must be in
//     the AllowedEmails/AllowedSubjects allowlists.
//
//  3. HTTP Basic auth with a bcrypt-verified password — the
//     fallback that mirrors the previous single-mode behavior.
//     Constant-time username compare + bcrypt on the password
//     defeats timing attacks against username enumeration and
//     short-circuits a stolen-hash offline attack.
//
// If none of the three is configured, the middleware serves only
// loopback callers — the safe "dev" default from DEV_PLAN.
//
// CSRF (Origin/Referer strict same-host match on non-safe methods)
// runs unconditionally. Even a valid mTLS identity or OIDC token
// wouldn't stop a rogue same-machine site from firing state-mutating
// requests if the operator's browser has a cached session.
func adminAuth(cfg *Config, oidcVerifier *oidcAuth, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSafeMethod(r.Method) {
			if err := checkOrigin(r); err != nil {
				slog.Warn("admin: CSRF check failed",
					"method", r.Method, "path", r.URL.Path,
					"origin", r.Header.Get("Origin"),
					"referer", r.Header.Get("Referer"),
					"err", err)
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		}

		// 1. mTLS: if the connection has a verified client cert and it
		// passes the CN allowlist, accept without touching Basic/OIDC.
		// This is the highest-privilege path (short-circuit on success).
		if cn, ok := verifiedMTLSIdentity(r, cfg.AdminMTLSAllowedCNs); ok {
			slog.Debug("admin: authenticated via mTLS", "cn", cn, "path", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		// 2. OIDC Bearer token: if configured, and an Authorization
		// header is present, try to verify. A malformed or unsigned
		// token is a hard 401 — don't silently fall through to Basic
		// auth, because that would let an attacker use OIDC failure as
		// an oracle for whether Basic is configured.
		if oidcVerifier != nil {
			if raw := extractBearerToken(r); raw != "" {
				if err := oidcVerifier.Verify(r.Context(), raw); err != nil {
					slog.Warn("admin: OIDC verification failed",
						"path", r.URL.Path, "err", err)
					http.Error(w, "invalid bearer token", http.StatusUnauthorized)
					return
				}
				slog.Debug("admin: authenticated via OIDC", "path", r.URL.Path)
				next.ServeHTTP(w, r)
				return
			}
		}

		// 3. Basic auth (or loopback fallback when nothing is set).
		if cfg.AdminBasicAuthUser == "" {
			// No credentials configured. If OIDC or mTLS is also
			// off, allow only loopback callers.
			if oidcVerifier == nil && cfg.AdminTLSClientCAFile == "" {
				if !isLoopback(r.RemoteAddr) || hasForwardingHeaders(r) {
					slog.Warn("admin: unauthenticated non-loopback access rejected",
						"remote", r.RemoteAddr, "path", r.URL.Path,
						"forwarded", hasForwardingHeaders(r))
					http.Error(w, "admin auth not configured for remote access", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Auth backends are configured (OIDC / mTLS) but neither
			// matched — reject rather than fall through to loopback,
			// because that would defeat the point of configuring them.
			writeAuthChallenges(w, oidcVerifier)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok {
			writeAuthChallenges(w, oidcVerifier)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		// Constant-time user compare — the timing of a length-mismatch
		// or a per-byte diff on the username shouldn't hint at whether
		// the account exists.
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(cfg.AdminBasicAuthUser)) == 1
		passErr := bcrypt.CompareHashAndPassword([]byte(cfg.AdminBasicAuthPasswordHash), []byte(pass))

		if !userOK || passErr != nil {
			// Same 401 either way — never distinguish "unknown user"
			// from "wrong password" in the response body or code.
			writeAuthChallenges(w, oidcVerifier)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// verifiedMTLSIdentity returns the client certificate's CN if the TLS
// handshake presented at least one verified peer certificate AND
// (allowedCNs is empty OR the CN is in the allowlist). Returns "", false
// otherwise. Reads *only* VerifiedChains — a chain that failed
// verification lands in PeerCertificates but not VerifiedChains, so we
// don't have to re-verify anything here.
func verifiedMTLSIdentity(r *http.Request, allowedCNs []string) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		return "", false
	}
	leaf := r.TLS.VerifiedChains[0][0] // leaf of the first successfully verified chain
	cn := leaf.Subject.CommonName
	if len(allowedCNs) == 0 {
		return cn, true
	}
	for _, allowed := range allowedCNs {
		// Constant-time compare so a giant CN allowlist can't be side-
		// channel probed by measuring authorization latency.
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(cn)) == 1 {
			return cn, true
		}
	}
	return "", false
}

// extractBearerToken returns the raw token from an Authorization: Bearer
// <token> header, or "" if the header is missing or malformed. Uses
// EqualFold on the scheme so "bearer" (lowercase, as some clients send)
// still works.
func extractBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// writeAuthChallenges lists all configured authentication mechanisms in
// WWW-Authenticate so a browser-side or CLI-side client can pick one.
// Only advertises Bearer when OIDC is actually enabled (RFC 6750 §3).
func writeAuthChallenges(w http.ResponseWriter, oidcVerifier *oidcAuth) {
	w.Header().Add("WWW-Authenticate", `Basic realm="pgman-admin", charset="UTF-8"`)
	if oidcVerifier != nil {
		w.Header().Add("WWW-Authenticate", `Bearer realm="pgman-admin"`)
	}
}

// isSafeMethod matches HTTP's own definition of "safe" methods — GET,
// HEAD, OPTIONS. Only unsafe methods need CSRF checking; safe methods
// can't mutate server state by definition.
func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// checkOrigin verifies that a state-mutating request originated from
// the admin server's own origin. Modern browsers always send Origin (or
// at least Referer) on POSTs from a page — that's the whole CSRF attack
// surface. Non-browser callers (curl, CI/CD scripts, k8s probes) omit
// both, and we recognize that as "definitely not a cross-origin browser
// attack" and let them through. This keeps the check strict against
// its intended threat model without breaking scripted automation.
func checkOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	referer := r.Header.Get("Referer")
	if origin == "" && referer == "" {
		// Non-browser client — no CSRF risk (browsers can't be coerced
		// into omitting both). Basic auth still gates the request.
		return nil
	}
	src := origin
	if src == "" {
		src = referer
	}
	u, err := url.Parse(src)
	if err != nil {
		return errCSRFBadOrigin
	}
	// Compare host (with port) — Host carries the port for
	// non-standard admin listeners like :8081.
	if u.Host != r.Host {
		return errCSRFOriginMismatch
	}
	return nil
}

// Sentinel CSRF errors — kept as vars for cheap == checks in tests.
var (
	errCSRFBadOrigin      = &csrfError{"unparseable Origin/Referer"}
	errCSRFOriginMismatch = &csrfError{"Origin/Referer host does not match request Host"}
)

type csrfError struct{ msg string }

func (e *csrfError) Error() string { return e.msg }

// isLoopback reports whether remoteAddr (from *http.Request.RemoteAddr)
// looks like a loopback client. Used to gate the "no admin auth
// configured" fallback so it can never accidentally accept traffic from
// the network.
func isLoopback(remoteAddr string) bool {
	// RemoteAddr is host:port; strip the port with the last colon —
	// avoids importing net just for SplitHostPort here.
	host := remoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) is what a dual-stack listener
	// reports for a v4 loopback client, so it has to be recognised too.
	if lower := strings.ToLower(host); strings.HasPrefix(lower, "::ffff:") {
		return strings.HasPrefix(lower[len("::ffff:"):], "127.")
	}
	return strings.HasPrefix(host, "127.")
}

// forwardingHeaders are the headers a reverse proxy adds when it relays
// someone else's request.
var forwardingHeaders = []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "X-Forwarded-Host"}

// hasForwardingHeaders reports whether the request looks like it came
// through a reverse proxy.
//
// This closes the hole in the loopback fallback. Behind nginx, Traefik
// or a Kubernetes ingress running on the same host, RemoteAddr is the
// proxy's address — 127.0.0.1 — for every request on the internet, so
// "is the peer loopback?" stops meaning "is the caller local?". The
// presence of a forwarding header is direct evidence that the peer is
// relaying for someone else, and no genuinely local admin client sends
// one.
//
// The failure mode is a false positive: a local caller who sets the
// header by hand gets a 403 telling them to configure admin auth. That
// is the right direction to be wrong in.
func hasForwardingHeaders(r *http.Request) bool {
	for _, h := range forwardingHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	return false
}

// generateAdminPasswordHash is the operator-facing helper for
// provisioning AdminBasicAuthPasswordHash — bcrypt cost 12 is the modern
// default (Go's bcrypt.DefaultCost has been 10 since Go 1.0, which is
// too weak for a fresh install in 2026).
func generateAdminPasswordHash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// errAdminAuthNotConfigured is a sentinel returned by loadOIDCVerifier
// (and similar future helpers) so main.go can distinguish "operator
// didn't configure this backend" (skip silently) from "operator
// configured it but it doesn't work" (fatal at startup).
var errAdminAuthNotConfigured = errors.New("admin auth backend not configured")

// buildOIDCVerifier is a thin factory main.go calls at startup so the
// heavy `oidc.NewProvider(ctx, issuer)` network round-trip only fires
// when OIDC is actually enabled. Returns nil,nil when disabled, so the
// caller can just plumb the returned *oidcAuth (or nil) into adminAuth.
func buildOIDCVerifier(ctx context.Context, cfg *Config) (*oidcAuth, error) {
	if cfg.AdminOIDCIssuerURL == "" {
		return nil, nil
	}
	return newOIDCAuth(ctx, oidcAuthConfig{
		IssuerURL:         cfg.AdminOIDCIssuerURL,
		ClientID:          cfg.AdminOIDCClientID,
		AllowedEmails:     cfg.AdminOIDCAllowedEmails,
		AllowedSubjects:   cfg.AdminOIDCAllowedSubjects,
		SkipEmailVerified: cfg.AdminOIDCSkipEmailVerified,
	})
}
