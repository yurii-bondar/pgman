package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// oidcAuthConfig captures everything the OIDC verifier needs. Kept as
// its own struct (not the whole *Config) so the OIDC unit tests can
// build a verifier without a full config object.
type oidcAuthConfig struct {
	IssuerURL         string
	ClientID          string
	AllowedEmails     []string
	AllowedSubjects   []string
	SkipEmailVerified bool
}

// oidcAuth verifies bearer tokens issued by a specific OIDC provider
// against the provider's own JWKS (fetched via discovery from the
// issuer URL). Safe for concurrent use — go-oidc's Provider/Verifier
// are goroutine-safe.
type oidcAuth struct {
	verifier          *oidc.IDTokenVerifier
	allowedEmails     map[string]struct{}
	allowedSubjects   map[string]struct{}
	skipEmailVerified bool
}

// newOIDCAuth performs OIDC discovery (a single HTTPS GET to
// <issuer>/.well-known/openid-configuration) and constructs a verifier
// bound to cfg.ClientID as the expected audience. The discovery call
// blocks — pass a ctx with a sane timeout at startup.
//
// Verification uses go-oidc's default Config: signature check via JWKS,
// issuer match, audience match, expiry, not-before. We add the email
// allowlist / subject allowlist checks on top.
func newOIDCAuth(ctx context.Context, cfg oidcAuthConfig) (*oidcAuth, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("oidc: issuer URL is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oidc: client_id is required (used as expected audience)")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
		// SkipClientIDCheck stays false — we always require exact audience.
		// SupportedSigningAlgs stays nil ⇒ go-oidc picks per JWKS.
	})

	// Set lookups are O(1) — allowlists can grow to hundreds of users
	// without any linear scanning in the hot path.
	emails := make(map[string]struct{}, len(cfg.AllowedEmails))
	for _, e := range cfg.AllowedEmails {
		emails[e] = struct{}{}
	}
	subs := make(map[string]struct{}, len(cfg.AllowedSubjects))
	for _, s := range cfg.AllowedSubjects {
		subs[s] = struct{}{}
	}

	return &oidcAuth{
		verifier:          verifier,
		allowedEmails:     emails,
		allowedSubjects:   subs,
		skipEmailVerified: cfg.SkipEmailVerified,
	}, nil
}

// Verify checks a raw id_token string: signature (via cached JWKS),
// standard claims (iss/aud/exp/nbf), the email_verified claim (unless
// SkipEmailVerified), and finally the email/subject allowlists.
// Returns nil on success; on failure returns a descriptive error that
// the caller MUST NOT reflect back to the client — an attacker
// probing the failure reason is an oracle.
func (a *oidcAuth) Verify(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return errors.New("empty token")
	}

	idToken, err := a.verifier.Verify(ctx, rawToken)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	// Extract only what we need — no more. Anything more risks leaking
	// custom claims into logs later without an audit review.
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return fmt.Errorf("parse claims: %w", err)
	}

	// If we require email_verified and the IDP said false, refuse —
	// otherwise an attacker who convinces a corporate IDP to mint a
	// token for arbitrary_email@example.com without proof-of-ownership
	// walks in.
	if !a.skipEmailVerified && claims.Email != "" && !claims.EmailVerified {
		return errors.New("email not verified by issuer")
	}

	// Constant-time membership check — the timing of a match/miss
	// should NOT reveal which particular email/sub is allowed.
	if a.checkAllowlist(claims.Email, a.allowedEmails) {
		return nil
	}
	if a.checkAllowlist(claims.Sub, a.allowedSubjects) {
		return nil
	}

	return errors.New("subject not in admin allowlist")
}

// checkAllowlist does a constant-time membership scan. Slower than a
// direct map hit, but the input space is bounded (a handful of
// operators), so this is fine and it removes the timing side-channel
// that map iteration order can expose.
func (a *oidcAuth) checkAllowlist(candidate string, allowed map[string]struct{}) bool {
	if candidate == "" || len(allowed) == 0 {
		return false
	}
	// subtle.ConstantTimeCompare short-circuits on length mismatch;
	// wrap in a for-loop across the allowlist so total time depends
	// on |allowed|, not on which entry matched.
	found := 0
	for k := range allowed {
		if subtle.ConstantTimeCompare([]byte(k), []byte(candidate)) == 1 {
			found = 1 // don't break — keep constant iteration count
		}
	}
	return found == 1
}
