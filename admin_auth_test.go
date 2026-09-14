package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newAdminTestConfig(t *testing.T, password string) *Config {
	t.Helper()
	cfg := &Config{}
	cfg.applyDefaults()
	if password != "" {
		hash, err := generateAdminPasswordHash(password)
		if err != nil {
			t.Fatalf("generate hash: %v", err)
		}
		cfg.AdminBasicAuthUser = "admin"
		cfg.AdminBasicAuthPasswordHash = hash
	}
	return cfg
}

func newOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAdminAuthRejectsMissingCredentials(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
		t.Errorf("expected WWW-Authenticate: Basic header, got %q", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAdminAuthRejectsWrongPassword(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", rec.Code)
	}
}

func TestAdminAuthRejectsWrongUser(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("attacker", "hunter2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong user, got %d", rec.Code)
	}
}

func TestAdminAuthAcceptsValidCredentials(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "hunter2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid credentials, got %d", rec.Code)
	}
}

func TestAdminAuthLoopbackFallbackWhenUnconfigured(t *testing.T) {
	cfg := newAdminTestConfig(t, "") // no admin auth
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected loopback to pass when admin auth is unconfigured, got %d", rec.Code)
	}
}

func TestAdminAuthLoopbackFallbackRejectsRemote(t *testing.T) {
	cfg := newAdminTestConfig(t, "")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.42:12345"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-loopback when unauthenticated, got %d", rec.Code)
	}
}

func TestAdminAuthCSRFAllowsNonBrowserClient(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	// No Origin, no Referer — curl / CI/CD / kubernetes probe. Not a
	// CSRF risk (browsers can't be coerced into omitting both), so
	// this must be allowed through as long as Basic auth checks out.
	req := httptest.NewRequest(http.MethodPost, "/pools", nil)
	req.SetBasicAuth("admin", "hunter2")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for non-browser POST (no Origin/Referer), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminAuthCSRFRejectsForeignOrigin(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodPost, "/pools", nil)
	req.SetBasicAuth("admin", "hunter2")
	req.Host = "pgman.local:8081"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for foreign Origin, got %d", rec.Code)
	}
}

func TestAdminAuthCSRFAcceptsMatchingOrigin(t *testing.T) {
	cfg := newAdminTestConfig(t, "hunter2")
	h := adminAuth(cfg, nil, newOK())

	req := httptest.NewRequest(http.MethodPost, "/pools", nil)
	req.SetBasicAuth("admin", "hunter2")
	req.Host = "pgman.local:8081"
	req.Header.Set("Origin", "https://pgman.local:8081")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for matching Origin, got %d", rec.Code)
	}
}

func TestGenerateAdminPasswordHashIsBcrypt(t *testing.T) {
	h, err := generateAdminPasswordHash("hunter2")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(h, "$2") {
		t.Errorf("expected bcrypt $2-prefixed hash, got %q", h)
	}
}
