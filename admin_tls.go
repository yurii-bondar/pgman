package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// buildAdminTLSConfig loads the admin listener's TLS material from
// configuration. Returns nil,nil if HTTPS is not configured (admin will
// run on plain HTTP behind whatever reverse proxy the operator has).
//
// Behaviour:
//
//   - AdminTLSCertFile+AdminTLSKeyFile only: plain HTTPS. No client
//     certificate expected. Basic auth / OIDC still gate every request.
//
//   - + AdminTLSClientCAFile: mutual TLS. ClientAuth is set to
//     VerifyClientCertIfGiven, NOT RequireAndVerify. That choice is
//     deliberate — an operator MAY still want to reach admin over
//     OIDC/Basic without a client cert, and blanket-rejecting
//     cert-less handshakes at the TLS layer would defeat that. When a
//     cert IS presented, it MUST verify against ClientCAs; the admin
//     middleware then decides whether to trust it (verifiedMTLSIdentity).
func buildAdminTLSConfig(cfg *Config) (*tls.Config, error) {
	if cfg.AdminTLSCertFile == "" && cfg.AdminTLSKeyFile == "" && cfg.AdminTLSClientCAFile == "" {
		return nil, nil
	}
	if cfg.AdminTLSCertFile == "" || cfg.AdminTLSKeyFile == "" {
		return nil, errors.New("admin_tls_cert_file and admin_tls_key_file must both be set to enable TLS on the admin listener")
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.AdminTLSCertFile, cfg.AdminTLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("admin_tls_cert_file/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// TLS 1.2 minimum for the admin plane too — matches the data
		// plane and rules out downgrade to insecure suites.
		MinVersion: tls.VersionTLS12,
	}

	if cfg.AdminTLSClientCAFile == "" {
		return tlsCfg, nil
	}

	caBundle, err := os.ReadFile(cfg.AdminTLSClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("admin_tls_client_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBundle) {
		return nil, fmt.Errorf("admin_tls_client_ca_file %q contains no PEM certificates", cfg.AdminTLSClientCAFile)
	}

	tlsCfg.ClientCAs = pool
	// VerifyClientCertIfGiven — see the doc comment above for why not
	// RequireAndVerify. The admin middleware still refuses non-mTLS
	// callers when Basic/OIDC are both unset, so the "no cert AND no
	// Basic AND no OIDC" path is not a security hole.
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
	return tlsCfg, nil
}
