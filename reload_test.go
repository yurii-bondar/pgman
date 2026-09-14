package main

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// writeReloadConfig writes a minimal valid config listing the named
// pools and returns its path.
func writeReloadConfig(t *testing.T, pools ...string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("allow_insecure_trust_auth: true\npools:\n")
	for i, name := range pools {
		port := 5432 + i
		sb.WriteString("  " + name + ":\n")
		sb.WriteString("    backend_dsn: \"postgres://u:p@localhost:" + strconv.Itoa(port) + "/" + name + "\"\n")
		sb.WriteString("    backend_addr: \"localhost:" + strconv.Itoa(port) + "\"\n")
		sb.WriteString("    limit: 2\n")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestApplyConfigReloadAddsAndRemovesPools covers the whole point of
// SIGHUP: reconcile the live registry with the file.
func TestApplyConfigReloadAddsAndRemovesPools(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{
		"keep": dummyPoolConfig(2),
		"gone": dummyPoolConfig(2),
	}, NewEventLog(10))

	path := writeReloadConfig(t, "keep", "fresh")

	result, err := applyConfigReload(path, registry)
	if err != nil {
		t.Fatalf("applyConfigReload: %v", err)
	}

	if !slices.Equal(result.Added, []string{"fresh"}) {
		t.Errorf("Added = %v, want [fresh]", result.Added)
	}
	if !slices.Equal(result.Removed, []string{"gone"}) {
		t.Errorf("Removed = %v, want [gone]", result.Removed)
	}
	if !slices.Equal(result.Unchanged, []string{"keep"}) {
		t.Errorf("Unchanged = %v, want [keep]", result.Unchanged)
	}

	if _, ok := registry.Get("fresh"); !ok {
		t.Error("pool from the file was not added to the registry")
	}
	if _, ok := registry.Get("gone"); ok {
		t.Error("pool absent from the file was not removed")
	}
}

// TestApplyConfigReloadLeavesExistingPoolsAlone pins a deliberate
// limitation, which is worth a test precisely because it surprises
// people: SIGHUP reconciles the *set* of pools, never their settings.
//
// Hot-resizing or re-pointing a live pool needs the same drain care as
// a removal, so it stays opt-in through the admin API. A test here
// means nobody "fixes" that by accident.
func TestApplyConfigReloadLeavesExistingPoolsAlone(t *testing.T) {
	original := dummyPoolConfig(2)
	registry := NewPoolRegistry(map[string]PoolConfig{"db": original}, NewEventLog(10))
	before, _ := registry.Get("db")

	// The file says limit 2 and a different backend than dummyPoolConfig.
	path := writeReloadConfig(t, "db")

	result, err := applyConfigReload(path, registry)
	if err != nil {
		t.Fatalf("applyConfigReload: %v", err)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("expected a no-op reload, got %+v", result)
	}

	after, _ := registry.Get("db")
	if before != after {
		t.Error("the live pool was replaced; SIGHUP must not re-create existing pools")
	}
	if got, _ := registry.PoolConfig("db"); got.BackendAddr != original.BackendAddr {
		t.Errorf("backend_addr changed to %q; SIGHUP must not re-point a live pool",
			got.BackendAddr)
	}
}

// TestApplyConfigReloadRejectsInvalidFileWithoutTouchingRegistry is the
// safety property that matters most: a typo in the config of a running
// proxy must be a no-op, not a partially-applied reconfiguration.
func TestApplyConfigReloadRejectsInvalidFileWithoutTouchingRegistry(t *testing.T) {
	registry := NewPoolRegistry(map[string]PoolConfig{"db": dummyPoolConfig(2)}, NewEventLog(10))

	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("pools: [this is not a map\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := applyConfigReload(path, registry); err == nil {
		t.Fatal("expected an error for malformed YAML")
	}
	if _, ok := registry.Get("db"); !ok {
		t.Error("a failed reload removed a live pool")
	}
	if n := len(registry.Names()); n != 1 {
		t.Errorf("registry has %d pools after a failed reload, want 1", n)
	}
}

func TestApplyConfigReloadMissingFileIsAnError(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))
	if _, err := applyConfigReload(filepath.Join(t.TempDir(), "absent.yaml"), registry); err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// TestApplyConfigReloadContinuesPastOneBadPool: a configmap flip can
// carry many changes at once, and one bad entry must not blackhole the
// rest of the delta.
func TestApplyConfigReloadContinuesPastOneBadPool(t *testing.T) {
	registry := NewPoolRegistry(nil, NewEventLog(10))

	// "bad" points at the cloud metadata address, which registry.Add
	// refuses; "good" is ordinary. Names are chosen so the rejected one
	// is processed first (the add loop sorts).
	body := `allow_insecure_trust_auth: true
pools:
  bad:
    backend_dsn: "postgres://u:p@169.254.169.254/x"
    backend_addr: "169.254.169.254:80"
    limit: 1
  good:
    backend_dsn: "postgres://u:p@localhost:5432/good"
    backend_addr: "localhost:5432"
    limit: 1
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	result, err := applyConfigReload(path, registry)
	if err == nil {
		t.Fatal("expected the bad pool to be reported as an error")
	}
	// The partial result must still come back so the caller can log
	// what actually happened.
	if !slices.Equal(result.Added, []string{"good"}) {
		t.Errorf("Added = %v, want [good] — one bad entry must not abort the reload",
			result.Added)
	}
	if _, ok := registry.Get("bad"); ok {
		t.Error("the rejected pool was registered anyway")
	}
}
