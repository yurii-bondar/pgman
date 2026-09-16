package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestValidateBackendAddrRejectsPivotTargets covers the SSRF surface the
// admin pool-creation form opens: an operator-supplied host:port that
// pgman will then dial from inside the cluster.
//
// 169.254.169.254 is the one that matters — on AWS, GCP and Azure it
// answers with credentials for the node pgman is running on.
func TestValidateBackendAddrRejectsPivotTargets(t *testing.T) {
	rejected := []struct {
		addr string
		why  string
	}{
		{"169.254.169.254:80", "AWS/GCP/Azure instance metadata"},
		{"169.254.169.254:5432", "metadata service on a plausible-looking port"},
		{"[fe80::1]:5432", "IPv6 link-local"},
		{"0.0.0.0:5432", "unspecified address"},
		{"[::]:5432", "IPv6 unspecified"},
		{"224.0.0.1:5432", "multicast"},
		{"", "empty"},
		{"nohostport", "missing port"},
		{":5432", "missing host"},
	}
	for _, tc := range rejected {
		t.Run(tc.addr, func(t *testing.T) {
			if err := validateBackendAddr(tc.addr); err == nil {
				t.Errorf("validateBackendAddr(%q) = nil, want an error (%s)", tc.addr, tc.why)
			}
		})
	}
}

// TestValidateBackendAddrAcceptsRealBackends guards against the check
// being too aggressive. Loopback in particular must stay allowed:
// pgman next to Postgres on one host, or as a sidecar in one Pod, is a
// normal deployment.
func TestValidateBackendAddrAcceptsRealBackends(t *testing.T) {
	accepted := []string{
		"127.0.0.1:5432",
		"[::1]:5432",
		"10.0.3.17:5432",
		"192.168.1.20:5432",
		"postgres:5432",
		"db.internal.example.com:5432",
		"my-rds.abc123.eu-central-1.rds.amazonaws.com:5432",
	}
	for _, addr := range accepted {
		t.Run(addr, func(t *testing.T) {
			if err := validateBackendAddr(addr); err != nil {
				t.Errorf("validateBackendAddr(%q) = %v, want nil", addr, err)
			}
		})
	}
}

// TestRegistryAddRejectsMetadataAddress checks the validator is actually
// wired into the admin path, not just present. Pools from YAML do not
// go through Add, so this is the only entry point that needs it.
func TestRegistryAddRejectsMetadataAddress(t *testing.T) {
	r := NewPoolRegistry(nil, NewEventLog(10))
	err := r.Add("evil", PoolConfig{
		BackendDSN:  "postgres://u:p@169.254.169.254/db",
		BackendAddr: "169.254.169.254:80",
		Limit:       1,
	})
	if err == nil {
		t.Fatal("registry.Add accepted a link-local backend address")
	}
	if !strings.Contains(err.Error(), "link-local") {
		t.Errorf("error = %q, want it to name the reason", err)
	}
	if _, ok := r.Get("evil"); ok {
		t.Error("the rejected pool was registered anyway")
	}
}

// TestIsLoopbackHandlesIPv4MappedIPv6: a dual-stack listener reports a
// v4 loopback client as ::ffff:127.0.0.1, which the original check did
// not recognise.
func TestIsLoopbackHandlesIPv4MappedIPv6(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:5000":          true,
		"127.0.0.53:5000":         true,
		"[::1]:5000":              true,
		"[::ffff:127.0.0.1]:5000": true,
		"[::ffff:10.0.0.5]:5000":  false,
		"10.0.0.5:5000":           false,
		"[fe80::1]:5000":          false,
	}
	for addr, want := range cases {
		t.Run(addr, func(t *testing.T) {
			if got := isLoopback(addr); got != want {
				t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
			}
		})
	}
}

// TestHasForwardingHeaders covers the reverse-proxy detection that
// closes the loopback-fallback hole.
//
// Behind an ingress on the same host, every request on the internet
// arrives with RemoteAddr 127.0.0.1, so "peer is loopback" stops meaning
// "caller is local" and the unauthenticated admin fallback opens to the
// world. A forwarding header is direct evidence the peer is relaying.
func TestHasForwardingHeaders(t *testing.T) {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "X-Forwarded-Host"} {
		t.Run(h, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set(h, "203.0.113.9")
			if !hasForwardingHeaders(r) {
				t.Errorf("%s was not treated as evidence of a reverse proxy", h)
			}
		})
	}

	t.Run("no headers", func(t *testing.T) {
		if hasForwardingHeaders(httptest.NewRequest(http.MethodGet, "/", nil)) {
			t.Error("a plain local request must not look forwarded")
		}
	})
}

// TestAdminLoopbackFallbackRejectsForwardedRequests is the end-to-end
// version: with no admin credentials configured, a loopback request is
// allowed, but the same request carrying a forwarding header is not.
func TestAdminLoopbackFallbackRejectsForwardedRequests(t *testing.T) {
	cfg := &Config{} // no basic auth, no OIDC, no mTLS — loopback fallback
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // distinctive "reached the handler"
	})
	handler := adminAuth(cfg, nil, next)

	t.Run("plain loopback is allowed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:5000"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusTeapot {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusTeapot)
		}
	})

	t.Run("forwarded loopback is rejected", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:5000" // the ingress, not the caller
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: a request relayed by a local reverse "+
				"proxy must not inherit the loopback exemption", rec.Code)
		}
	})
}

// TestBackendConnRecordsTheHostItActuallyReached is the regression for a
// cancel that silently stops working.
//
// backend_dsn goes to pgconn, which accepts several hosts and tries them
// in order — so `postgres://u@pg-1:5432,pg-2:5432/db` is a working
// failover configuration today. backend_addr, meanwhile, is a single
// host:port, and it was what every backendConn recorded.
//
// The two disagree the moment the first host is down. cancelSession
// sends the CancelRequest to the recorded address, so it arrives at
// pg-1 carrying a PID and secret that only pg-2 issued. Postgres
// validates the pair and ignores it, which means Ctrl+C does nothing,
// reports nothing, and looks like the query is simply slow.
//
// The address a connection records has to be the one it is connected
// to, not the one the config nominated.
func TestBackendConnRecordsTheHostItActuallyReached(t *testing.T) {
	alive := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})

	// A port nothing listens on, so pgconn has to fall through to the
	// second host. Taken and released so it is genuinely free.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a dead port: %v", err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	deadHost, deadPort, _ := net.SplitHostPort(deadAddr)
	aliveHost, alivePort, _ := net.SplitHostPort(alive.addr())

	dsn := fmt.Sprintf("postgres://app@%s:%s,%s:%s/db1?sslmode=disable",
		deadHost, deadPort, aliveHost, alivePort)

	// backend_addr names the first host, exactly as an operator would
	// write it: it is a single field and the DSN has two hosts.
	dial := newDialBackend(dsn, deadAddr, false)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := dial(ctx)
	if err != nil {
		t.Fatalf("dial across the fallback: %v", err)
	}
	defer conn.Close()

	bc, ok := conn.(*backendConn)
	if !ok {
		t.Fatalf("dialler returned %T, want *backendConn", conn)
	}
	if bc.addr == deadAddr {
		t.Fatalf("the connection recorded %s, the host it failed to reach — "+
			"a CancelRequest would go there instead of to %s", bc.addr, alive.addr())
	}
	if bc.addr != alive.addr() {
		t.Errorf("recorded address %s, want %s (the host actually connected to)",
			bc.addr, alive.addr())
	}
}
