package main

// newAdminServer had no test at all, which is how `enable_pprof: true`
// shipped as a config option that panics the process at startup.
//
// Go 1.22's ServeMux rejects two patterns when neither is strictly more
// specific than the other. The dashboard registers "GET /" and pprof
// registered "/debug/pprof/": the first is narrower by method, the
// second by path, so neither wins and the registration panics. Nothing
// caught it because config_validation_test.go only proves the YAML key
// parses — it never builds the server the key controls.
//
// These tests build the thing, which is the only way that class of bug
// is ever visible.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func adminServerForTest(t *testing.T, cfg *Config) *http.Server {
	t.Helper()
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))

	srv, err := newAdminServer(context.Background(), cfg, "config.yaml", registry, NewEventLog(10))
	if err != nil {
		t.Fatalf("newAdminServer: %v", err)
	}
	return srv
}

// TestAdminServerBuildsWithPprofEnabled is the regression: constructing
// the admin server with pprof on must not panic.
func TestAdminServerBuildsWithPprofEnabled(t *testing.T) {
	srv := adminServerForTest(t, &Config{EnablePprof: true})
	if srv == nil || srv.Handler == nil {
		t.Fatal("admin server built without a handler")
	}
}

// TestPprofIsReachableOnlyWhenEnabled pins both halves of the switch.
// The "off" half matters as much as the "on" half: pprof behind the
// admin listener is a live heap dump, and a default that quietly served
// it would be a disclosure bug rather than a missing feature.
func TestPprofIsReachableOnlyWhenEnabled(t *testing.T) {
	// Every pprof route the server registers, so a future edit that
	// drops the method prefix from one of them is caught by name.
	paths := []string{
		"/debug/pprof/",
		"/debug/pprof/cmdline",
		"/debug/pprof/symbol",
	}

	t.Run("enabled", func(t *testing.T) {
		srv := adminServerForTest(t, &Config{EnablePprof: true})
		for _, p := range paths {
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, loopbackGet(p))
			if rec.Code != http.StatusOK {
				t.Errorf("GET %s returned %d, want 200 with pprof enabled", p, rec.Code)
			}
		}
	})

	t.Run("disabled", func(t *testing.T) {
		srv := adminServerForTest(t, &Config{})
		for _, p := range paths {
			rec := httptest.NewRecorder()
			srv.Handler.ServeHTTP(rec, loopbackGet(p))
			// The dashboard's catch-all "GET /" answers unknown paths,
			// so the assertion is that pprof's own output is absent,
			// not that the status is 404.
			if rec.Code == http.StatusOK && rec.Body.Len() > 0 &&
				containsAny(rec.Body.String(), "Types of profiles available", "profile-name") {
				t.Errorf("GET %s served pprof content with enable_pprof unset", p)
			}
		}
	})
}

// loopbackGet builds a request the admin plane will accept. Its default
// posture is loopback-only when no authentication is configured, and
// httptest.NewRequest's synthetic 192.0.2.1 is not that.
func loopbackGet(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:54321"
	return req
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
