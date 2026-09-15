package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every rejection loadConfig performs exists because the alternative is
// a proxy that starts and then behaves in a way the operator did not
// ask for: an admin listener on plain HTTP where TLS was expected, an
// OIDC issuer trusted with no allowlist, two pools colliding on one
// registry key. These are the checks that turn "silently wrong" into
// "does not start", so each one is worth a test.

// writeRawConfig writes YAML verbatim and returns its path, so a test
// can express a broken file rather than a broken struct.
func writeRawConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const validPoolYAML = `
pools:
  db1:
    backend_dsn: "postgres://u:p@localhost:5432/db1?sslmode=disable"
    backend_addr: "localhost:5432"
    limit: 2
`

func TestLoadConfigRejectsBrokenAdminSurfaces(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "basic auth user without a password hash",
			yaml: "allow_insecure_trust_auth: true\nadmin_basic_auth_user: ops\n" + validPoolYAML,
			want: "admin_basic_auth_user and admin_basic_auth_password_hash",
		},
		{
			name: "password hash that is not bcrypt",
			yaml: "allow_insecure_trust_auth: true\nadmin_basic_auth_user: ops\n" +
				"admin_basic_auth_password_hash: \"plaintext-oops\"\n" + validPoolYAML,
			want: "does not look like a bcrypt hash",
		},
		{
			name: "admin TLS certificate without a key",
			yaml: "allow_insecure_trust_auth: true\nadmin_tls_cert_file: /tmp/a.crt\n" + validPoolYAML,
			want: "admin_tls_cert_file and admin_tls_key_file",
		},
		{
			name: "client CA without a server certificate",
			yaml: "allow_insecure_trust_auth: true\nadmin_tls_client_ca_file: /tmp/ca.crt\n" + validPoolYAML,
			want: "admin_tls_client_ca_file requires",
		},
		{
			name: "OIDC issuer without a client id",
			yaml: "allow_insecure_trust_auth: true\nadmin_oidc_issuer_url: https://idp.example\n" + validPoolYAML,
			want: "admin_oidc_client_id must be set",
		},
		{
			name: "OIDC without an allowlist",
			yaml: "allow_insecure_trust_auth: true\nadmin_oidc_issuer_url: https://idp.example\n" +
				"admin_oidc_client_id: pgman\n" + validPoolYAML,
			want: "admin_oidc_allowed_emails or admin_oidc_allowed_subjects",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeRawConfig(t, tc.yaml))
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestLoadConfigRejectsCollidingPoolKeys: registry keys are
// "<pool>/<backend user>", so a slash in either half can make two
// different pools resolve to one key — and a routing collision means a
// client reaching the wrong database, which is the worst outcome in this
// codebase.
func TestLoadConfigRejectsCollidingPoolKeys(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "slash in the pool name",
			yaml: `allow_insecure_trust_auth: true
pools:
  "shop/alice":
    backend_dsn: "postgres://u:p@localhost:5432/db?sslmode=disable"
    backend_addr: "localhost:5432"
    limit: 2
`,
			want: "must not contain",
		},
		{
			name: "slash in a backend_users key",
			yaml: `allow_insecure_trust_auth: true
pools:
  shop:
    backend_dsn: "postgres://u:p@localhost:5432/db?sslmode=disable"
    backend_addr: "localhost:5432"
    limit: 2
    backend_users:
      "alice/admin": "postgres://alice@localhost:5432/db?sslmode=disable"
`,
			want: "must not contain",
		},
		{
			name: "empty backend_users username",
			yaml: `allow_insecure_trust_auth: true
pools:
  shop:
    backend_dsn: "postgres://u:p@localhost:5432/db?sslmode=disable"
    backend_addr: "localhost:5432"
    limit: 2
    backend_users:
      "": "postgres://alice@localhost:5432/db?sslmode=disable"
`,
			want: "empty username",
		},
		{
			name: "empty backend_users DSN",
			yaml: `allow_insecure_trust_auth: true
pools:
  shop:
    backend_dsn: "postgres://u:p@localhost:5432/db?sslmode=disable"
    backend_addr: "localhost:5432"
    limit: 2
    backend_users:
      alice: ""
`,
			want: "empty DSN",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfig(writeRawConfig(t, tc.yaml))
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestLoadConfigAcceptsAFullyPopulatedFile walks the paths that only run
// when a setting is present: the warnings about weak backend TLS and an
// empty admin_users list, and the fields that carry per-pool overrides.
// A config this shape is what a real deployment looks like, and it must
// not trip any of the checks above.
func TestLoadConfigAcceptsAFullyPopulatedFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "admin")

	yaml := `
listen_addr: "127.0.0.1:6435"
allow_insecure_trust_auth: true
admin_users: [ops]
admin_tls_cert_file: "` + certFile + `"
admin_tls_key_file: "` + keyFile + `"
admin_tls_client_ca_file: "` + certFile + `"
admin_mtls_allowed_cns: [ops-laptop]
enable_pprof: true
max_db_connections: 50
max_user_connections: 10
max_sessions_per_sec_per_user: 5
max_sessions_burst_per_user: 10
track_extra_parameters: ["application_name", "TimeZone"]
pools:
  shop:
    backend_dsn: "postgres://u:p@localhost:5432/shop?sslmode=verify-full"
    backend_addr: "localhost:5432"
    limit: 20
    pool_mode: session
    aliases: [shop_ro]
    min_idle: 2
    idle_timeout: "5m"
    max_lifetime: "1h"
    health_check_delay: "30s"
    login_retry: 2
    login_backoff: "100ms"
    backend_users:
      alice: "postgres://alice@localhost:5432/shop?sslmode=verify-full"
`
	cfg, err := loadConfig(writeRawConfig(t, yaml))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	pc := cfg.Pools["shop"]
	if pc.PoolMode != "session" {
		t.Errorf("pool_mode = %q, want session", pc.PoolMode)
	}
	if len(pc.Aliases) != 1 || pc.Aliases[0] != "shop_ro" {
		t.Errorf("aliases = %v, want [shop_ro]", pc.Aliases)
	}
	if pc.BackendUsers["alice"] == "" {
		t.Error("backend_users was not parsed")
	}
	// The per-pool overrides have to survive the merge with the
	// top-level defaults, or an operator's careful tuning is silently
	// replaced by the generic value.
	lifecycle := poolLifecycleDefaults(cfg, pc)
	if lifecycle.MinIdle != 2 || lifecycle.DialRetry != 2 {
		t.Errorf("per-pool overrides were lost: %+v", lifecycle)
	}
}

// TestDsnSSLModeReadsBothDSNForms: pgman warns about weak backend TLS by
// reading the DSN itself, and DSNs arrive in two syntaxes. Missing one of
// them would make the warning — the only thing standing between a
// deployment and plain-text credentials on the wire — silently
// selective.
func TestDsnSSLModeReadsBothDSNForms(t *testing.T) {
	cases := map[string]string{
		"postgres://u:p@h:5432/db?sslmode=verify-full":   "verify-full",
		"postgres://u:p@h:5432/db?sslmode=require&x=1":   "require",
		"host=h port=5432 user=u sslmode=disable":        "disable",
		"host=h port=5432 user=u sslmode=prefer other=1": "prefer",
		"postgres://u:p@h:5432/db":                       "prefer (unset)",
		"":                                               "",
	}
	for dsn, want := range cases {
		if got := dsnSSLMode(dsn); got != want {
			t.Errorf("dsnSSLMode(%q) = %q, want %q", dsn, got, want)
		}
	}

	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		if !strictSSLMode(mode) {
			t.Errorf("strictSSLMode(%q) = false, want true", mode)
		}
	}
	for _, mode := range []string{"disable", "allow", "prefer", "prefer (unset)", ""} {
		if strictSSLMode(mode) {
			t.Errorf("strictSSLMode(%q) = true — this mode can fall back to plain text", mode)
		}
	}
}
