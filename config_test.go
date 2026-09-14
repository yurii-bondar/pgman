package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfigMinimalValid(t *testing.T) {
	path := writeConfig(t, `
allow_insecure_trust_auth: true
pools:
  db1:
    backend_dsn: "postgres://u:p@localhost:5432/db1"
    backend_addr: "localhost:5432"
    limit: 2
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ListenAddr != ":6435" {
		t.Errorf("expected default listen_addr :6435, got %q", cfg.ListenAddr)
	}
	if cfg.MetricsAddr != ":8080" {
		t.Errorf("expected default metrics_addr :8080, got %q", cfg.MetricsAddr)
	}
	if len(cfg.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(cfg.Pools))
	}
}

func TestLoadConfigExplicitAddressesOverrideDefaults(t *testing.T) {
	path := writeConfig(t, `
listen_addr: ":9999"
metrics_addr: ":9998"
allow_insecure_trust_auth: true
pools:
  db1:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 1
`)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ListenAddr != ":9999" || cfg.MetricsAddr != ":9998" {
		t.Errorf("explicit addresses were not honored: %+v", cfg)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for a missing config file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	path := writeConfig(t, "not: valid: yaml: [[[")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

func TestLoadConfigRequiresAtLeastOnePool(t *testing.T) {
	path := writeConfig(t, `allow_insecure_trust_auth: true`)
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error when no pools are configured")
	}
}

func TestLoadConfigRejectsPartialTLSConfig(t *testing.T) {
	path := writeConfig(t, `
allow_insecure_trust_auth: true
tls_cert_file: "cert.pem"
pools:
  db1:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 1
`)
	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected error when only tls_cert_file is set without tls_key_file")
	}
	if !strings.Contains(err.Error(), "tls_cert_file") {
		t.Errorf("error should mention the missing TLS field, got: %v", err)
	}
}

func TestLoadConfigRequiresAuthUsersOrExplicitTrust(t *testing.T) {
	path := writeConfig(t, `
pools:
  db1:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 1
`)
	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected error: no auth_users and allow_insecure_trust_auth not set")
	}
}

func TestLoadConfigAuthUsersWithoutExplicitTrustIsFine(t *testing.T) {
	path := writeConfig(t, `
auth_users:
  rgs: "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy"
pools:
  db1:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 1
`)
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("expected success with auth_users configured, got: %v", err)
	}
}

func TestLoadConfigValidatesEachPool(t *testing.T) {
	cases := []string{
		`
allow_insecure_trust_auth: true
pools:
  db1:
    backend_addr: "y"
    limit: 1
`,
		`
allow_insecure_trust_auth: true
pools:
  db1:
    backend_dsn: "x"
    limit: 1
`,
		`
allow_insecure_trust_auth: true
pools:
  db1:
    backend_dsn: "x"
    backend_addr: "y"
    limit: 0
`,
	}
	for i, c := range cases {
		path := writeConfig(t, c)
		if _, err := loadConfig(path); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}
