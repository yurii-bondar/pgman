package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// TestSCRAMVerifierRoundTrip proves the whole SCRAM machinery end to end
// without touching the network: generate a verifier from a password, parse
// it back, run a full client+server conversation, and confirm both the
// right and the wrong password produce the expected outcome. This is the
// empirical check for exactly how failure surfaces in xdg-go/scram (Step's
// own error vs. Valid()) before trusting that in the live proxy.
func TestSCRAMVerifierRoundTrip(t *testing.T) {
	verifier, err := GenerateSCRAMVerifier("correct-horse-battery-staple", 4096)
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	t.Logf("verifier: %s", verifier)

	creds, err := ParseSCRAMVerifier(verifier)
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}

	runConversation := func(t *testing.T, password string) (converged bool, err error) {
		t.Helper()
		server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
			return creds, nil
		})
		if err != nil {
			t.Fatalf("new server: %v", err)
		}
		serverConv := server.NewConversation()

		client, err := scram.SHA256.NewClient("someuser", password, "")
		if err != nil {
			t.Fatalf("new client: %v", err)
		}
		clientConv := client.NewConversation()

		// client-first
		clientFirst, err := clientConv.Step("")
		if err != nil {
			return false, err
		}
		// server-first
		serverFirst, err := serverConv.Step(clientFirst)
		if err != nil {
			return false, err
		}
		// client-final (this is where a wrong password produces a bad proof)
		clientFinal, err := clientConv.Step(serverFirst)
		if err != nil {
			return false, err
		}
		// server-final: server verifies the client's proof here
		serverFinal, err := serverConv.Step(clientFinal)
		if err != nil {
			return false, err
		}
		if !serverConv.Valid() {
			return false, nil
		}
		// client verifies the server's proof back, closing the loop
		if _, err := clientConv.Step(serverFinal); err != nil {
			return false, err
		}
		if !clientConv.Valid() {
			return false, nil
		}
		return true, nil
	}

	t.Run("correct password", func(t *testing.T) {
		ok, err := runConversation(t, "correct-horse-battery-staple")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected conversation to converge with the correct password")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		ok, err := runConversation(t, "wrong-password")
		if ok {
			t.Fatal("wrong password must not authenticate")
		}
		t.Logf("wrong password rejected via: ok=%v err=%v", ok, err)
	})
}

// scramClientConversation drives the client side of the wire exchange
// against a live pgproto3.Frontend/Backend pair — the same sequence a real
// libpq would produce, just built with the scram package's client role
// instead of an actual Postgres driver.
func scramClientConversation(t *testing.T, fe *pgproto3.Frontend, user, password string, cb *scram.ChannelBinding) error {
	t.Helper()

	msg, err := fe.Receive()
	if err != nil {
		return err
	}
	sasl, ok := msg.(*pgproto3.AuthenticationSASL)
	if !ok {
		t.Fatalf("expected AuthenticationSASL, got %T", msg)
	}

	client, err := scram.SHA256.NewClient(user, password, "")
	if err != nil {
		t.Fatalf("new scram client: %v", err)
	}

	var mechanism string
	var conv *scram.ClientConversation
	if cb != nil {
		mechanism = "SCRAM-SHA-256-PLUS"
		conv = client.NewConversationWithChannelBinding(*cb)
	} else {
		mechanism = "SCRAM-SHA-256"
		conv = client.NewConversation()
	}
	found := false
	for _, m := range sasl.AuthMechanisms {
		found = found || m == mechanism
	}
	if !found {
		t.Fatalf("server did not offer %q, offered %v", mechanism, sasl.AuthMechanisms)
	}

	first, err := conv.Step("")
	if err != nil {
		return err
	}
	fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: mechanism, Data: []byte(first)})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		t.Fatalf("expected AuthenticationSASLContinue, got %T", msg)
	}

	final, err := conv.Step(string(cont.Data))
	if err != nil {
		return err
	}
	fe.Send(&pgproto3.SASLResponse{Data: []byte(final)})
	if err := fe.Flush(); err != nil {
		return err
	}

	msg, err = fe.Receive()
	if err != nil {
		return err
	}
	finalMsg, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		t.Fatalf("expected AuthenticationSASLFinal, got %T", msg)
	}

	if _, err := conv.Step(string(finalMsg.Data)); err != nil {
		return err
	}
	if !conv.Valid() {
		t.Fatal("client conversation did not validate the server's proof")
	}
	return nil
}

func TestSCRAMAuthenticate(t *testing.T) {
	verifier, err := GenerateSCRAMVerifier("s3cret", 4096)
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}

	runServer := func(user, password string) error {
		serverConn, clientConn := net.Pipe()
		pg := pgproto3.NewBackend(serverConn, serverConn)
		startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": user}}

		serverErr := make(chan error, 1)
		go func() {
			err := auth.Authenticate(pg, serverConn, startup)
			serverErr <- err
			// If auth failed before the exchange finished (e.g. bad
			// password), the client's Receive for the next message would
			// otherwise block forever — closing unblocks it with an error.
			serverConn.Close()
		}()

		fe := pgproto3.NewFrontend(clientConn, clientConn)
		clientErr := scramClientConversation(t, fe, user, password, nil)
		clientConn.Close()

		err := <-serverErr
		if err == nil {
			err = clientErr
		}
		return err
	}

	t.Run("correct password", func(t *testing.T) {
		if err := runServer("alice", "s3cret"); err != nil {
			t.Fatalf("expected success, got: %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		if err := runServer("alice", "wrong"); err == nil {
			t.Fatal("expected auth failure for wrong password")
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		serverConn, _ := net.Pipe()
		defer serverConn.Close()
		pg := pgproto3.NewBackend(serverConn, serverConn)
		startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": "bob"}}
		err := auth.Authenticate(pg, serverConn, startup)
		if err == nil {
			t.Fatal("expected error for unknown user")
		}
	})
}

// generateTestCert makes a throwaway self-signed certificate for TLS tests
// — never touches the filesystem, never reuses certs/server.crt.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		SignatureAlgorithm:    x509.SHA256WithRSA,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestSCRAMAuthenticateChannelBinding proves the two sides actually agree:
// SCRAMAuth computes tls-server-end-point from *our own* certificate
// (tlsServerEndpointBinding, since we're the TLS server and have no peer
// cert to read), while the client side here computes it the "normal" way —
// scram.NewTLSServerEndpointBinding reading PeerCertificates, which from a
// client's view *is* the server's cert. If those two derivations ever
// diverge, SCRAM-SHA-256-PLUS breaks for every real libpq client, silently,
// until someone tries it live — exactly what happened once already this
// session before this test existed.
func TestSCRAMAuthenticateChannelBinding(t *testing.T) {
	cert := generateTestCert(t)
	verifier, err := GenerateSCRAMVerifier("s3cret", 4096)
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, &cert)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}

	rawServer, rawClient := net.Pipe()
	tlsServer := tls.Server(rawServer, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	tlsClient := tls.Client(rawClient, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})

	handshakeErr := make(chan error, 1)
	go func() { handshakeErr <- tlsServer.Handshake() }()
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-handshakeErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	defer tlsServer.Close()
	defer tlsClient.Close()

	clientState := tlsClient.ConnectionState()
	clientCB, err := scram.NewTLSServerEndpointBinding(&clientState)
	if err != nil {
		t.Fatalf("client-side channel binding: %v", err)
	}

	pg := pgproto3.NewBackend(tlsServer, tlsServer)
	startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": "alice"}}

	serverErr := make(chan error, 1)
	go func() { serverErr <- auth.Authenticate(pg, tlsServer, startup) }()

	fe := pgproto3.NewFrontend(tlsClient, tlsClient)
	if err := scramClientConversation(t, fe, "alice", "s3cret", &clientCB); err != nil {
		t.Fatalf("client conversation: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server authenticate: %v", err)
	}
}

func TestTrustAuthAlwaysSucceeds(t *testing.T) {
	var auth TrustAuth
	serverConn, _ := net.Pipe()
	defer serverConn.Close()
	pg := pgproto3.NewBackend(serverConn, serverConn)
	if err := auth.Authenticate(pg, serverConn, &pgproto3.StartupMessage{}); err != nil {
		t.Fatalf("TrustAuth must never fail, got: %v", err)
	}
}

func TestGenerateSCRAMVerifierProducesUniqueSalts(t *testing.T) {
	v1, err := GenerateSCRAMVerifier("same-password", 4096)
	if err != nil {
		t.Fatalf("generate v1: %v", err)
	}
	v2, err := GenerateSCRAMVerifier("same-password", 4096)
	if err != nil {
		t.Fatalf("generate v2: %v", err)
	}
	if v1 == v2 {
		t.Fatal("two verifiers for the same password must differ (random salt)")
	}
}

func TestParseSCRAMVerifierRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"not-scram-at-all",
		"SCRAM-SHA-256$notanumber:c2FsdA==$c3RvcmVk:c2VydmVy",
		"SCRAM-SHA-256$4096:not-base64!!!$c3RvcmVk:c2VydmVy",
		"SCRAM-SHA-256$4096:c2FsdA==$missing-dollar-separator",
	}
	for _, c := range cases {
		if _, err := ParseSCRAMVerifier(c); err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}
