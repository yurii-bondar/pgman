package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The tests in this file cover the mTLS branch of adminAuth: an
// end-to-end HTTPS handshake with a client certificate, plus the
// pure-unit checks of verifiedMTLSIdentity for the CN allowlist logic
// (no real handshake needed for those).

// generateCA returns a self-signed root CA and its private key,
// suitable for signing both server and client certificates in the
// tests below.
func generateCA(t *testing.T, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("gen ca cert: %v", err)
	}
	crt, _ := x509.ParseCertificate(der)
	return crt, key
}

// issueCert issues a leaf certificate signed by the given CA. usage
// lets the caller decide whether it's a server cert (ExtKeyUsageServerAuth
// + DNSName) or a client cert (ExtKeyUsageClientAuth + no SAN).
func issueCert(t *testing.T, caCrt *x509.Certificate, caKey *rsa.PrivateKey, cn string, usage x509.ExtKeyUsage, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	// Split textual SANs into DNS names and IP addresses so a cert
	// meant for "127.0.0.1" is valid for TLS ServerName verification.
	for _, name := range dnsNames {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCrt, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	crt, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: crt}
}

// TestMTLSAdminAuthAcceptsVerifiedClientCert stands up a full HTTPS
// server with mTLS, connects with a client cert signed by the trusted
// CA, and verifies the handler is reached. This is the "everything is
// configured correctly" happy path.
func TestMTLSAdminAuthAcceptsVerifiedClientCert(t *testing.T) {
	caCrt, caKey := generateCA(t, "test-root")
	serverCert := issueCert(t, caCrt, caKey, "127.0.0.1", x509.ExtKeyUsageServerAuth, []string{"127.0.0.1"})
	clientCert := issueCert(t, caCrt, caKey, "ops-alice", x509.ExtKeyUsageClientAuth, nil)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCrt)

	// Configure adminAuth to accept any CN issued by our CA (empty
	// allowlist ⇒ any verified cert is fine). No Basic user, no OIDC.
	cfg := &Config{
		AdminTLSClientCAFile: "not-used-in-this-test", // just so middleware knows mTLS is configured
	}
	ts := httptest.NewUnstartedServer(adminAuth(cfg, nil, newOK()))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	defer ts.Close()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCrt)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      rootCAs,
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS12,
		},
	}}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (mTLS should have authenticated)", resp.StatusCode)
	}
}

// TestMTLSAdminAuthRejectsWrongCN sets an allowlist that does NOT
// contain the client cert's CN. The middleware must fall through past
// mTLS (verifiedMTLSIdentity returns false) and, with no Basic/OIDC
// configured, deny the request.
func TestMTLSAdminAuthRejectsWrongCN(t *testing.T) {
	caCrt, caKey := generateCA(t, "test-root")
	serverCert := issueCert(t, caCrt, caKey, "127.0.0.1", x509.ExtKeyUsageServerAuth, []string{"127.0.0.1"})
	clientCert := issueCert(t, caCrt, caKey, "bad-actor", x509.ExtKeyUsageClientAuth, nil)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCrt)

	cfg := &Config{
		AdminTLSClientCAFile: "not-used-in-this-test",
		AdminMTLSAllowedCNs:  []string{"ops-alice", "ops-bob"}, // bad-actor is NOT here
	}
	ts := httptest.NewUnstartedServer(adminAuth(cfg, nil, newOK()))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	defer ts.Close()

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCrt)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      rootCAs,
			ServerName:   "127.0.0.1",
			MinVersion:   tls.VersionTLS12,
		},
	}}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	defer resp.Body.Close()
	// No Basic / OIDC ⇒ 403 (not 401), because the loopback fallback
	// is disabled once TLS/OIDC config is present (see adminAuth logic).
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status: got 200, want 4xx — bad CN must not authenticate")
	}
}

// TestVerifiedMTLSIdentityAllowlistUnit is a table-driven unit test of
// verifiedMTLSIdentity that doesn't need a real handshake. Skips the
// integration overhead when a future refactor of the CN allowlist just
// needs to verify a decision matrix.
func TestVerifiedMTLSIdentityAllowlistUnit(t *testing.T) {
	// Fake a verified leaf with CN "ops-alice".
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "ops-alice"}}
	verifiedR := &http.Request{TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}}
	unverifiedR := &http.Request{TLS: nil}

	cases := []struct {
		name    string
		req     *http.Request
		allowed []string
		wantOK  bool
	}{
		{"no TLS at all", unverifiedR, nil, false},
		{"verified, empty allowlist ⇒ accept", verifiedR, nil, true},
		{"verified, CN in allowlist", verifiedR, []string{"ops-alice", "ops-bob"}, true},
		{"verified, CN NOT in allowlist", verifiedR, []string{"ops-bob"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := verifiedMTLSIdentity(c.req, c.allowed)
			if ok != c.wantOK {
				t.Errorf("got ok=%v, want %v", ok, c.wantOK)
			}
		})
	}
}
