package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// `pgman -health-check` is the container health check, so its verdict is
// what Compose and Swarm act on. Two ways it can be wrong, and both are
// worse than having no check at all: reporting healthy while the proxy
// refuses traffic, and reporting unhealthy while it serves it.

// readyServerAddr starts the real readiness handler on loopback and
// returns its address.
func readyServerAddr(t *testing.T, draining bool) string {
	t.Helper()
	registry := NewPoolRegistry(map[string]PoolConfig{"db1": dummyPoolConfig(2)}, NewEventLog(10))
	var flag atomic.Bool
	flag.Store(draining)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", readyHandler(registry, &flag))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestProbeReadyAcceptsAReadyProxy(t *testing.T) {
	if err := probeReady(readyServerAddr(t, false)); err != nil {
		t.Errorf("probe of a ready proxy failed: %v", err)
	}
}

// TestProbeReadyRejectsADrainingProxy: a container draining on SIGTERM
// must report unhealthy, since that is what stops an orchestrator from
// sending it new work while it finishes the sessions it has.
func TestProbeReadyRejectsADrainingProxy(t *testing.T) {
	err := probeReady(readyServerAddr(t, true))
	if err == nil {
		t.Fatal("probe reported a draining proxy as healthy")
	}
	// The reason /ready gave has to survive into the error, or the
	// container logs become the only place to find out why.
	if !strings.Contains(err.Error(), "draining") {
		t.Errorf("error = %v, want it to carry the reason from /ready", err)
	}
}

// TestProbeReadyNormalisesTheListenAddress: metrics_addr is usually a
// bare port or a wildcard, and neither is something a client can dial. A
// probe that passed the address through unchanged would fail on every
// normal configuration.
func TestProbeReadyNormalisesTheListenAddress(t *testing.T) {
	addr := readyServerAddr(t, false)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}

	for _, form := range []string{":" + port, "0.0.0.0:" + port, "[::]:" + port} {
		if err := probeReady(form); err != nil {
			t.Errorf("probe of %q failed: %v", form, err)
		}
	}
}

func TestProbeReadyReportsAnUnusableAddress(t *testing.T) {
	if err := probeReady("not-an-address"); err == nil {
		t.Error("an address with no port was accepted")
	}
	// Port 1 on loopback: nothing listens, and connecting fails at once
	// rather than waiting out the timeout.
	if err := probeReady("127.0.0.1:1"); err == nil {
		t.Error("a probe of a port nothing listens on reported success")
	}
}

// TestCLIHealthCheckExitCodes: Docker keys the container's health purely
// off the exit code, so these two numbers are the whole contract.
func TestCLIHealthCheckExitCodes(t *testing.T) {
	backend := startFakePG(t, fakePGOptions{auth: fakeAuthTrust})
	addr := readyServerAddr(t, false)

	dir := t.TempDir()
	path := dir + "/config.yaml"
	writeConfigFile(t, path, map[string]string{"db1": backend.dsn("app", "db1")}, backend.addr())
	// Point the config's metrics_addr at the readiness server above, the
	// way it would point at the proxy's own listener in a container.
	appendToConfigFile(t, path, "metrics_addr: \""+addr+"\"\n")

	var out, errOut strings.Builder
	if code := cli([]string{"-config", path, "-health-check"}, &out, &errOut); code != 0 {
		t.Errorf("exit code = %d, want 0 against a ready proxy; stderr = %q", code, errOut.String())
	}

	// A config that cannot be read is a failed check, not a crash: the
	// health check runs in a container whose config may not be mounted.
	out.Reset()
	errOut.Reset()
	if code := cli([]string{"-config", dir + "/nope.yaml", "-health-check"}, &out, &errOut); code != 1 {
		t.Errorf("exit code = %d with no config file, want 1", code)
	}
}
