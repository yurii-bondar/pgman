package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// The OIDC tests stand up a minimal but fully-functional OIDC provider
// backed by an in-memory RSA key: discovery document, JWKS endpoint,
// and a helper that mints signed id_tokens. That's enough for
// go-oidc's Provider/Verifier to work without any real network
// dependency — and lets us cover the allowlist matrix (email allowed
// / email denied / signature broken / audience wrong / email not
// verified) without ever leaving the test binary.

// mockIDP is a self-contained OIDC identity provider that lives for
// the duration of a single test. Serves /.well-known/openid-configuration
// and /jwks; ready-made SignID() mints tokens signed with its own RSA
// key. Never talks to the outside network.
type mockIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	m := &mockIDP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	m.server = httptest.NewServer(mux) // handlers registered below reference m.server.URL, which is now stable

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"issuer":                                m.server.URL,
			"jwks_uri":                              m.server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			// authorization/token endpoints unused by verifier, but
			// including them keeps the doc structurally valid.
			"authorization_endpoint":   m.server.URL + "/authorize",
			"token_endpoint":           m.server.URL + "/token",
			"subject_types_supported":  []string{"public"},
			"response_types_supported": []string{"id_token"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		// Serve the public half of the RSA key as a JWKS document.
		jwk := jose.JSONWebKey{
			Key:       &m.key.PublicKey,
			KeyID:     m.kid,
			Algorithm: "RS256",
			Use:       "sig",
		}
		set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	t.Cleanup(func() { m.server.Close() })
	return m
}

// SignID mints an id_token with the given claims, signed with the
// IDP's RSA key. Missing standard claims (iss/exp) are filled in by
// this helper so tests only need to name the fields they care about.
func (m *mockIDP) SignID(t *testing.T, claims map[string]any) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.server.URL
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := sig.CompactSerialize()
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	return compact
}

func TestOIDCAcceptsAllowedEmail(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "alice-subject-id",
		"aud":            "pgman-admin",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	if err := oa.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: got error, want nil: %v", err)
	}
}

func TestOIDCRejectsUnknownEmail(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "eve-subject-id",
		"aud":            "pgman-admin",
		"email":          "eve@example.com", // NOT allowed
		"email_verified": true,
	})
	if err := oa.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify: expected an error for email not in allowlist")
	}
}

func TestOIDCRejectsWrongAudience(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "alice",
		"aud":            "some-other-app", // NOT pgman-admin
		"email":          "alice@example.com",
		"email_verified": true,
	})
	if err := oa.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify: expected an error for wrong audience")
	}
}

func TestOIDCRejectsUnverifiedEmailByDefault(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "alice",
		"aud":            "pgman-admin",
		"email":          "alice@example.com",
		"email_verified": false, // MUST be rejected
	})
	if err := oa.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify: unverified email must fail")
	}
}

func TestOIDCAcceptsUnverifiedEmailWhenSkipConfigured(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:         idp.server.URL,
		ClientID:          "pgman-admin",
		AllowedEmails:     []string{"alice@example.com"},
		SkipEmailVerified: true,
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "alice",
		"aud":            "pgman-admin",
		"email":          "alice@example.com",
		"email_verified": false, // now tolerated
	})
	if err := oa.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: got error with SkipEmailVerified=true: %v", err)
	}
}

func TestOIDCAllowsSubjectFallback(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:       idp.server.URL,
		ClientID:        "pgman-admin",
		AllowedSubjects: []string{"machine-account-42"},
		AllowedEmails:   nil, // token has no email
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub": "machine-account-42",
		"aud": "pgman-admin",
		// no email at all — machine-to-machine flow
	})
	if err := oa.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: sub-based auth failed: %v", err)
	}
}

func TestOIDCRejectsBrokenSignature(t *testing.T) {
	idp := newMockIDP(t)

	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{"alice@example.com"},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}

	token := idp.SignID(t, map[string]any{
		"sub":            "alice",
		"aud":            "pgman-admin",
		"email":          "alice@example.com",
		"email_verified": true,
	})
	// Corrupt the token: flip a byte in the signature portion (after
	// the last '.'). That guarantees the JWKS signature check fails.
	i := strings.LastIndex(token, ".")
	broken := token[:i+1] + flipOneByte(t, token[i+1:])
	if err := oa.Verify(context.Background(), broken); err == nil {
		t.Fatal("Verify: broken signature must fail")
	}
}

// TestOIDCConfigValidation makes sure required-field validation still
// works even before any network round-trip is attempted.
func TestOIDCConfigValidation(t *testing.T) {
	if _, err := newOIDCAuth(context.Background(), oidcAuthConfig{}); err == nil {
		t.Fatal("empty issuer must fail")
	}
	if _, err := newOIDCAuth(context.Background(), oidcAuthConfig{IssuerURL: "https://x"}); err == nil {
		t.Fatal("missing client_id must fail")
	}
}

// TestBuildOIDCVerifierRequiresValidIssuer just proves the factory
// exercises discovery: a bogus issuer URL should fail cleanly (not
// panic, not hang) at buildOIDCVerifier time.
func TestBuildOIDCVerifierRequiresValidIssuer(t *testing.T) {
	// Point at a port that's guaranteed to be closed. Bound with a
	// short ctx so a broken DNS/routing doesn't stall the test suite.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := buildOIDCVerifier(ctx, &Config{
		AdminOIDCIssuerURL: "http://127.0.0.1:1", // reserved, refuses TCP
		AdminOIDCClientID:  "x",
	})
	if err == nil {
		t.Fatal("expected discovery error for unreachable issuer")
	}
}

// flipOneByte is a tiny helper to change one character in a base64url
// payload while keeping it a valid base64url length. Enough to break
// any RSA signature.
func flipOneByte(t *testing.T, s string) string {
	t.Helper()
	if s == "" {
		return "AAAA" // trivial replacement to guarantee non-empty
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Not a strict base64 payload — fall back to naive text flip.
		return string([]byte(s)[:1]) + "X" + s[2:]
	}
	if len(b) == 0 {
		b = []byte{0x01}
	} else {
		b[0] ^= 0xFF
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// _ silences the unused import warning if a future refactor drops
// math/big before this test does — keeps the import list stable.
var _ = big.NewInt

// _ silences unused fmt import for the same reason.
var _ = fmt.Sprintf
