package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildAdminTLSConfigRejectsHalfConfiguredKeypair: a cert without
// its key (or the reverse) is a typo in the config, and the only safe
// reading of it is "the operator meant to encrypt the admin plane".
// Starting anyway would serve the admin API — pools, PAUSE/RESUME,
// credentials — over plaintext HTTP while the operator believes it is
// on HTTPS.
func TestBuildAdminTLSConfigRejectsHalfConfiguredKeypair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "admin")

	cases := map[string]Config{
		"cert without key": {AdminTLSCertFile: certFile},
		"key without cert": {AdminTLSKeyFile: keyFile},
		"client ca only":   {AdminTLSClientCAFile: certFile},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			tlsCfg, err := buildAdminTLSConfig(&cfg)
			if err == nil {
				t.Fatal("a half-configured keypair was accepted")
			}
			if tlsCfg != nil {
				t.Error("an error was returned together with a usable config")
			}
		})
	}
}

// TestBuildAdminTLSConfigRejectsUnloadableKeypair keeps the failure at
// startup, where an operator is watching, instead of at the first
// admin request hours later.
func TestBuildAdminTLSConfigRejectsUnloadableKeypair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "admin")
	other := filepath.Join(dir, "other.key")
	if err := os.WriteFile(other, []byte("not a private key\n"), 0o600); err != nil {
		t.Fatalf("write bogus key: %v", err)
	}

	cfg := Config{AdminTLSCertFile: certFile, AdminTLSKeyFile: other}
	if _, err := buildAdminTLSConfig(&cfg); err == nil {
		t.Fatal("a certificate whose key does not parse was accepted")
	}

	// The mirror case: the paths are valid config, the files are not
	// there at all.
	cfg = Config{AdminTLSCertFile: filepath.Join(dir, "missing.crt"), AdminTLSKeyFile: keyFile}
	if _, err := buildAdminTLSConfig(&cfg); err == nil {
		t.Fatal("a missing certificate file was accepted")
	}
}

// TestBuildAdminTLSConfigWithoutClientCAWantsNoClientCert pins the
// plain-HTTPS shape. Asking for a client certificate when no client CA
// is configured would make browsers prompt for one and would break
// every curl and Prometheus scrape of the admin listener, while
// verifying nothing.
func TestBuildAdminTLSConfigWithoutClientCAWantsNoClientCert(t *testing.T) {
	certFile, keyFile := writeCertPair(t, t.TempDir(), "admin")

	cfg := Config{AdminTLSCertFile: certFile, AdminTLSKeyFile: keyFile}
	tlsCfg, err := buildAdminTLSConfig(&cfg)
	if err != nil {
		t.Fatalf("buildAdminTLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("TLS was configured but no config came back")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Errorf("got %d certificates, want the one that was configured", len(tlsCfg.Certificates))
	}
	// TLS 1.0/1.1 and their cipher suites are the downgrade the admin
	// plane must not accept — it carries the credentials that control
	// every pool.
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", tlsCfg.MinVersion)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs != nil {
		t.Error("a client CA pool was installed without a client CA file")
	}
}

// TestBuildAdminTLSConfigVerifiesClientCertIfGiven guards a deliberate
// asymmetry that is easy to "fix" into a regression. RequireAndVerify
// would lock out every operator who authenticates with Basic or OIDC
// and holds no client certificate; accepting an unverified certificate
// would let anyone claim a CN that admin_mtls_allowed_cns trusts.
// VerifyClientCertIfGiven is the only setting that does both jobs.
func TestBuildAdminTLSConfigVerifiesClientCertIfGiven(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "admin")
	caFile, _ := writeCertPair(t, dir, "clientca")

	cfg := Config{
		AdminTLSCertFile:     certFile,
		AdminTLSKeyFile:      keyFile,
		AdminTLSClientCAFile: caFile,
	}
	tlsCfg, err := buildAdminTLSConfig(&cfg)
	if err != nil {
		t.Fatalf("buildAdminTLSConfig: %v", err)
	}
	if tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("no client CA pool was built, so a presented certificate would go unverified")
	}
}

// TestBuildAdminTLSConfigRejectsUnusableClientCA: an empty trust pool
// verifies nothing, so every client certificate would fail and mTLS
// would be silently unusable. Worse, with admin_mtls_allowed_cns as the
// only configured authentication, the listener would reject everyone.
func TestBuildAdminTLSConfigRejectsUnusableClientCA(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "admin")

	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("# a comment and nothing else\n"), 0o600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	cases := map[string]string{
		"missing file": filepath.Join(dir, "absent.pem"),
		"no pem block": notPEM,
	}
	for name, caFile := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				AdminTLSCertFile:     certFile,
				AdminTLSKeyFile:      keyFile,
				AdminTLSClientCAFile: caFile,
			}
			tlsCfg, err := buildAdminTLSConfig(&cfg)
			if err == nil {
				t.Fatal("an unusable client CA file was accepted")
			}
			if tlsCfg != nil {
				t.Error("an error was returned together with a usable config")
			}
		})
	}
}
