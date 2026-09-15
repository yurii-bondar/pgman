package main

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretBytes builds a big-endian 4-byte SecretKey for tests. Post-v5
// migration SecretKey is []byte across the code, but existing tests
// wrote small uint32 literals like 6 or 42 — this helper preserves the
// same intent without spelling `[]byte{0,0,0,X}` on every line.
func secretBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// writeCertPair writes a throwaway certificate and key to dir as PEM
// files and returns their paths. For the config paths that take
// filenames rather than a tls.Certificate — the data-plane and admin
// listeners both load from disk, so testing them means having files.
func writeCertPair(t *testing.T, dir, name string) (certFile, keyFile string) {
	t.Helper()
	cert := generateTestCert(t)

	certFile = filepath.Join(dir, name+".crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyFile = filepath.Join(dir, name+".key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}

// writeConfigFile writes a minimal valid config listing the given pools,
// all pointed at one backend address. For the paths that re-read the
// file at runtime — the SIGHUP reload and the admin dry-run diff — where
// what matters is the file's content changing under a running process.
func writeConfigFile(t *testing.T, path string, pools map[string]string, backendAddr string) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("allow_insecure_trust_auth: true\npools:\n")
	for name, dsn := range pools {
		fmt.Fprintf(&sb, "  %s:\n    backend_dsn: %q\n    backend_addr: %q\n    limit: 2\n",
			name, dsn, backendAddr)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// appendToConfigFile adds lines to a config written by
// writeConfigFile — for the settings a test needs on top of the pools,
// where writing the whole file again would bury what it is varying.
func appendToConfigFile(t *testing.T, path, extra string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open config: %v", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(extra); err != nil {
		t.Fatalf("append to config: %v", err)
	}
}
