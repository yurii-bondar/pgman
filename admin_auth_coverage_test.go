package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// admin_auth_test.go covers Basic auth and the loopback fallback, and
// admin_mtls_test.go covers the certificate path over a real TLS
// listener. What was left untested is the OIDC branch of the middleware
// and the small parsers it leans on — the places where a wrong answer
// is not a broken dashboard but an open one.

// adminOIDCVerifier builds a verifier against a throwaway in-process
// identity provider, so the OIDC branch of the middleware can be driven
// without a network dependency or a real IDP.
func adminOIDCVerifier(t *testing.T, allowedEmail string) (*oidcAuth, *mockIDP) {
	t.Helper()
	idp := newMockIDP(t)
	oa, err := newOIDCAuth(context.Background(), oidcAuthConfig{
		IssuerURL:     idp.server.URL,
		ClientID:      "pgman-admin",
		AllowedEmails: []string{allowedEmail},
	})
	if err != nil {
		t.Fatalf("newOIDCAuth: %v", err)
	}
	return oa, idp
}

// TestExtractBearerTokenToleratesRealWorldHeaders: the scheme is
// case-insensitive per RFC 7235 and clients do send "bearer", while a
// header that is not a Bearer credential at all must yield "" so the
// middleware falls through to Basic instead of rejecting a request that
// was never trying to use OIDC.
func TestExtractBearerTokenToleratesRealWorldHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"absent", "", ""},
		{"canonical scheme", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"lowercase scheme", "bearer abc.def.ghi", "abc.def.ghi"},
		{"padded token", "Bearer   abc.def.ghi  ", "abc.def.ghi"},
		{"a different scheme", "Basic dXNlcjpwYXNz", ""},
		{"too short to be a scheme", "Bear", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if got := extractBearerToken(req); got != tc.want {
				t.Errorf("extractBearerToken = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestAdminAuthAcceptsAValidBearerToken is the OIDC path working: an
// operator who signs in through the company IDP reaches the admin plane
// without a shared password existing anywhere. If this regresses, the
// only way back in is the Basic-auth fallback nobody provisioned.
func TestAdminAuthAcceptsAValidBearerToken(t *testing.T) {
	verifier, idp := adminOIDCVerifier(t, "alice@example.com")
	cfg := newAdminTestConfig(t, "") // OIDC only; no Basic credentials
	h := adminAuth(cfg, verifier, newOK())

	token := idp.SignID(t, map[string]any{
		"sub":            "alice-subject-id",
		"aud":            "pgman-admin",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:44321" // deliberately remote: the token is the credential
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("a valid id_token was rejected with %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminAuthDoesNotFallBackToBasicAfterAFailedToken keeps OIDC from
// becoming an oracle. A request carries one Authorization header, so a
// failed token cannot be rescued by credentials in the same request —
// what must not happen is the middleware continuing to the Basic branch
// and answering with its generic challenge, because the difference
// between the two rejections tells an attacker whether Basic is
// configured at all.
func TestAdminAuthDoesNotFallBackToBasicAfterAFailedToken(t *testing.T) {
	verifier, idp := adminOIDCVerifier(t, "alice@example.com")
	cfg := newAdminTestConfig(t, "hunter2") // Basic *is* configured
	h := adminAuth(cfg, verifier, newOK())

	// A correctly signed token for the wrong audience: it fails
	// verification for a reason that has nothing to do with Basic auth.
	token := idp.SignID(t, map[string]any{
		"sub":            "alice-subject-id",
		"aud":            "some-other-app",
		"email":          "alice@example.com",
		"email_verified": true,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a rejected token was not a hard 401 (status %d)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "bearer token") {
		t.Errorf("body = %q, want the token to be rejected on its own terms", rec.Body.String())
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("a failed token produced a Basic challenge, revealing that Basic is configured")
	}
}

// TestAdminAuthWithOIDCConfiguredRejectsAnAnonymousLoopbackCaller: the
// loopback fallback exists only for a machine with no admin auth at
// all. Once an operator configures OIDC, a local process — a
// compromised browser extension, another container in the same pod —
// must not inherit admin rights just for being on the same host.
func TestAdminAuthWithOIDCConfiguredRejectsAnAnonymousLoopbackCaller(t *testing.T) {
	verifier, _ := adminOIDCVerifier(t, "alice@example.com")
	cfg := newAdminTestConfig(t, "")
	h := adminAuth(cfg, verifier, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("loopback bypassed a configured OIDC backend (status %d)", rec.Code)
	}
	// Both mechanisms have to be advertised, or a CLI client cannot tell
	// which credential to present.
	challenges := strings.Join(rec.Header().Values("WWW-Authenticate"), " ")
	if !strings.Contains(challenges, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want it to advertise Bearer", challenges)
	}
	if !strings.Contains(challenges, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want it to advertise Basic", challenges)
	}
}

// TestAdminAuthWithMTLSConfiguredRejectsAnAnonymousLoopbackCaller is
// the same rule for the certificate path, and it is the one an operator
// is most likely to get wrong: configuring client CAs without a Basic
// password looks like the most locked-down setup available, so falling
// back to "any local caller" there would be the worst place to do it.
func TestAdminAuthWithMTLSConfiguredRejectsAnAnonymousLoopbackCaller(t *testing.T) {
	cfg := newAdminTestConfig(t, "")
	cfg.AdminTLSClientCAFile = "/nonexistent/ca.crt" // presence is what enables the mode
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("loopback bypassed a configured mTLS backend (status %d)", rec.Code)
	}
	if challenges := rec.Header().Values("WWW-Authenticate"); len(challenges) != 1 {
		t.Errorf("WWW-Authenticate = %v, want Basic only when OIDC is off", challenges)
	}
}

// TestAdminAuthCSRFRejectsAnUnparseableOrigin fails closed on a header
// it cannot understand. A header that does not parse cannot be compared
// to the request's host, and treating "cannot tell" as "same origin"
// would hand every state-mutating endpoint to whatever produced it.
func TestAdminAuthCSRFRejectsAnUnparseableOrigin(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodPost, "/pools", nil)
	req.SetBasicAuth("admin", "hunter2")
	req.Host = "pgman.local:8081"
	// A DEL byte makes net/url refuse the string outright.
	req.Header.Set("Origin", "https://pgman.local:8081/\x7f")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("an Origin that does not parse was allowed through (status %d)", rec.Code)
	}
}

// TestAdminAuthCSRFFallsBackToReferer covers the browsers and privacy
// settings that send Referer but no Origin. Ignoring Referer would make
// the CSRF check silently inert for those clients — the failure mode
// nobody notices, because everything keeps working.
func TestAdminAuthCSRFFallsBackToReferer(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	t.Run("matching host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pools", nil)
		req.SetBasicAuth("admin", "hunter2")
		req.Host = "pgman.local:8081"
		req.Header.Set("Referer", "https://pgman.local:8081/pools")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("a same-origin Referer was rejected with %d", rec.Code)
		}
	})

	t.Run("foreign host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/pools", nil)
		req.SetBasicAuth("admin", "hunter2")
		req.Host = "pgman.local:8081"
		req.Header.Set("Referer", "https://evil.example.com/attack")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("a cross-origin Referer was allowed through (status %d)", rec.Code)
		}
	})
}

// TestGenerateAdminPasswordHashRejectsAnOverlongPassword: bcrypt caps
// its input at 72 bytes, and older versions of it silently truncated
// instead of refusing. A helper that swallowed the error would hand the
// operator a hash for the first 72 bytes of their passphrase while they
// believe the rest counts.
func TestGenerateAdminPasswordHashRejectsAnOverlongPassword(t *testing.T) {
	long := strings.Repeat("a", 73)
	if _, err := generateAdminPasswordHash(long); err == nil {
		t.Fatal("a password longer than bcrypt's 72-byte limit was hashed anyway")
	}
}
