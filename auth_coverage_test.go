package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// The happy paths of SCRAMAuth are exercised in auth_test.go and, end to
// end, in backend_auth_test.go. What is left here is the refusal
// surface: every way a client, a config file or a certificate can be
// wrong. Those branches are the ones that decide whether a bad input
// becomes a clean rejection or an authenticated session, so they are
// worth more per line than the path that already works.

// startSCRAMServer runs a.Authenticate against one end of an in-memory
// pipe and hands the test the client end, so a test can send exactly the
// bytes it wants to — including the malformed ones a cooperating SCRAM
// client library would refuse to produce.
func startSCRAMServer(t *testing.T, a *SCRAMAuth, user string) (*pgproto3.Frontend, <-chan error, net.Conn) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	// A deadline rather than no deadline: a hung pipe would otherwise
	// take the whole package's timeout with it and name nothing.
	_ = serverConn.SetDeadline(time.Now().Add(20 * time.Second))
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	errCh := make(chan error, 1)
	go func() {
		pg := pgproto3.NewBackend(serverConn, serverConn)
		startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": user}}
		errCh <- a.Authenticate(pg, serverConn, startup)
		// Closing unblocks a client still waiting on a reply the server
		// has already decided not to send.
		_ = serverConn.Close()
	}()
	return pgproto3.NewFrontend(clientConn, clientConn), errCh, clientConn
}

// awaitSASLOffer reads the server's mechanism list, which every client
// must do before it can answer. Returned rather than asserted so a test
// can also check which mechanisms were offered.
func awaitSASLOffer(t *testing.T, fe *pgproto3.Frontend) *pgproto3.AuthenticationSASL {
	t.Helper()
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("await sasl offer: %v", err)
	}
	sasl, ok := msg.(*pgproto3.AuthenticationSASL)
	if !ok {
		t.Fatalf("expected AuthenticationSASL, got %T", msg)
	}
	return sasl
}

// certSignedWith issues a self-signed certificate whose signature uses
// the hash that goes with curve — the input that selects which digest
// tlsServerEndpointBinding has to use.
func certSignedWith(t *testing.T, curve elliptic.Curve) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestNewSCRAMAuthRejectsAMalformedVerifier keeps a typo in auth_users a
// startup failure rather than a runtime one. A verifier that parses to a
// zero-valued credential would accept nobody, so the process would come
// up healthy and lock every user of that entry out until someone read
// the logs — the error has to name the user so the fix is obvious.
func TestNewSCRAMAuthRejectsAMalformedVerifier(t *testing.T) {
	_, err := NewSCRAMAuth(map[string]string{"alice": "md5deadbeef"}, nil)
	if err == nil {
		t.Fatal("a verifier that is not SCRAM-SHA-256 was accepted")
	}
	if !strings.Contains(err.Error(), "alice") {
		t.Errorf("error = %v, want it to name the offending user", err)
	}
}

// TestNewSCRAMAuthRejectsACertificateItCannotParse covers the other
// startup failure: TLS is configured but the leaf cannot be parsed, so
// the tls-server-end-point value cannot be computed. Continuing without
// it would silently drop SCRAM-SHA-256-PLUS from the offer, downgrading
// every channel-bound client to plain SCRAM without anyone noticing.
func TestNewSCRAMAuthRejectsACertificateItCannotParse(t *testing.T) {
	broken := tls.Certificate{Certificate: [][]byte{[]byte("this is not DER")}}
	_, err := NewSCRAMAuth(nil, &broken)
	if err == nil {
		t.Fatal("a certificate with an unparseable leaf was accepted")
	}
	if !strings.Contains(err.Error(), "channel binding") {
		t.Errorf("error = %v, want it to name the channel binding as the failure", err)
	}
}

// TestTLSServerEndpointBindingFollowsTheCertificateHash pins RFC 5929's
// hash-selection rule. The client computes this value independently from
// the same certificate; if the two sides disagree on the digest, every
// SCRAM-SHA-256-PLUS handshake fails with "channel binding check
// failed" and nothing in the logs points at the certificate's signature
// algorithm as the reason.
func TestTLSServerEndpointBindingFollowsTheCertificateHash(t *testing.T) {
	cases := []struct {
		name string
		cert tls.Certificate
		size int
	}{
		{"sha256 signature", generateTestCert(t), 32},
		{"sha384 signature", certSignedWith(t, elliptic.P384()), 48},
		{"sha512 signature", certSignedWith(t, elliptic.P521()), 64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cb, err := tlsServerEndpointBinding(&tc.cert)
			if err != nil {
				t.Fatalf("compute binding: %v", err)
			}
			if len(cb.Data) != tc.size {
				t.Errorf("binding is %d bytes, want %d", len(cb.Data), tc.size)
			}
			if cb.Type != scram.ChannelBindingTLSServerEndpoint {
				t.Errorf("binding type = %q, want tls-server-end-point", cb.Type)
			}
		})
	}
}

// TestTLSServerEndpointBindingUsesAPreparsedLeaf: crypto/tls fills in
// Leaf for certificates loaded through X509KeyPair on recent Go
// versions, and re-parsing DER on that path would be both wasted work
// and a second chance to disagree with what the TLS stack is actually
// serving. The value must come out identical either way.
func TestTLSServerEndpointBindingUsesAPreparsedLeaf(t *testing.T) {
	cert := generateTestCert(t)
	fromDER, err := tlsServerEndpointBinding(&cert)
	if err != nil {
		t.Fatalf("binding from DER: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	cert.Leaf = leaf
	fromLeaf, err := tlsServerEndpointBinding(&cert)
	if err != nil {
		t.Fatalf("binding from Leaf: %v", err)
	}

	if string(fromDER.Data) != string(fromLeaf.Data) {
		t.Error("the binding changes depending on whether Leaf was pre-parsed")
	}
}

// TestSCRAMAuthenticateResolvesAUserThroughDynamicLookup is the
// auth_query escape hatch seen from the authentication side: a user that
// exists in no static map at all still has to be able to log in, or a
// deployment with thousands of roles has to list every one of them in
// YAML and reload on every CREATE ROLE.
func TestSCRAMAuthenticateResolvesAUserThroughDynamicLookup(t *testing.T) {
	creds, err := ParseSCRAMVerifier(scramVerifierFor(t, "dyn-password"))
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}

	auth := &SCRAMAuth{users: map[string]scram.StoredCredentials{}}
	var asked string
	auth.SetDynamicLookup(func(user string) (scram.StoredCredentials, error) {
		asked = user
		return creds, nil
	})

	fe, errCh, _ := startSCRAMServer(t, auth, "dynamic-dave")
	if err := scramClientConversation(t, fe, "dynamic-dave", "dyn-password", nil); err != nil {
		t.Fatalf("client conversation: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if asked != "dynamic-dave" {
		t.Errorf("lookup was asked for %q, want the startup message's user", asked)
	}
}

// TestSCRAMAuthenticateReportsADynamicLookupFailure keeps "the auth
// database is unreachable" distinguishable from "your password is
// wrong". The two have completely different responses — page someone
// versus check your credentials — and collapsing them turns a short
// incident into a long one.
func TestSCRAMAuthenticateReportsADynamicLookupFailure(t *testing.T) {
	auth := &SCRAMAuth{users: map[string]scram.StoredCredentials{}}
	auth.SetDynamicLookup(func(string) (scram.StoredCredentials, error) {
		return scram.StoredCredentials{}, errCSRFBadOrigin // any error; the cause is the caller's
	})

	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()
	defer func() { _ = clientConn.Close() }()

	pg := pgproto3.NewBackend(serverConn, serverConn)
	startup := &pgproto3.StartupMessage{Parameters: map[string]string{"user": "ghost"}}
	err := auth.Authenticate(pg, serverConn, startup)
	if err == nil {
		t.Fatal("a failed lookup authenticated the user")
	}
	if !strings.Contains(err.Error(), "auth_query lookup") {
		t.Errorf("error = %v, want it to name the lookup rather than the password", err)
	}
}

// TestSCRAMAuthenticateRejectsPlusWithoutChannelBinding closes a
// downgrade the other way round: a client that asks for
// SCRAM-SHA-256-PLUS believes the exchange is bound to its TLS
// connection. Answering it on a connection that has no binding to offer
// would give it that belief for free, which is exactly the assurance
// SCRAM-SHA-256-PLUS is chosen for.
func TestSCRAMAuthenticateRejectsPlusWithoutChannelBinding(t *testing.T) {
	auth, err := NewSCRAMAuth(map[string]string{"alice": scramVerifierFor(t, "s3cret")}, nil)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}

	fe, errCh, _ := startSCRAMServer(t, auth, "alice")
	offered := awaitSASLOffer(t, fe)
	for _, m := range offered.AuthMechanisms {
		if m == "SCRAM-SHA-256-PLUS" {
			t.Fatal("a plaintext connection offered SCRAM-SHA-256-PLUS")
		}
	}

	fe.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256-PLUS",
		Data:          []byte("p=tls-server-end-point,,n=,r=clientnonce"),
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send initial response: %v", err)
	}

	authErr := <-errCh
	if authErr == nil {
		t.Fatal("SCRAM-SHA-256-PLUS succeeded without any channel binding")
	}
	if !strings.Contains(authErr.Error(), "channel binding") {
		t.Errorf("error = %v, want it to name the missing channel binding", authErr)
	}
}

// TestSCRAMAuthenticateRejectsAnUnsupportedMechanism is the no-downgrade
// promise in one assertion. pgman deliberately carries neither MD5 nor
// cleartext, and the only thing standing between that decision and a
// client that asks for one anyway is this default arm.
func TestSCRAMAuthenticateRejectsAnUnsupportedMechanism(t *testing.T) {
	auth, err := NewSCRAMAuth(map[string]string{"alice": scramVerifierFor(t, "s3cret")}, nil)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}

	fe, errCh, _ := startSCRAMServer(t, auth, "alice")
	awaitSASLOffer(t, fe)

	fe.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-1",
		Data:          []byte("n,,n=,r=clientnonce"),
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send initial response: %v", err)
	}

	authErr := <-errCh
	if authErr == nil {
		t.Fatal("an unknown SASL mechanism was accepted")
	}
	if !strings.Contains(authErr.Error(), "unsupported SASL mechanism") {
		t.Errorf("error = %v, want it to name the mechanism as unsupported", authErr)
	}
}

// TestSCRAMAuthenticateRejectsAMalformedClientFirst: the first SCRAM
// step is where a client's own message is parsed, and a parse failure
// there must end the connection rather than fall through to the next
// step with a half-initialised conversation.
func TestSCRAMAuthenticateRejectsAMalformedClientFirst(t *testing.T) {
	auth, err := NewSCRAMAuth(map[string]string{"alice": scramVerifierFor(t, "s3cret")}, nil)
	if err != nil {
		t.Fatalf("new scram auth: %v", err)
	}

	fe, errCh, _ := startSCRAMServer(t, auth, "alice")
	awaitSASLOffer(t, fe)

	fe.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte("not a scram message at all"),
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send initial response: %v", err)
	}

	authErr := <-errCh
	if authErr == nil {
		t.Fatal("a client-first message that does not parse was accepted")
	}
	if !strings.Contains(authErr.Error(), "scram step 1") {
		t.Errorf("error = %v, want it to name the failing step", authErr)
	}
}

// TestSCRAMAuthenticateRejectsTheWrongMessageType guards against a
// client — or something pretending to be one — answering an
// authentication request with an ordinary protocol message. Treating
// anything other than the expected SASL message as a failure is what
// stops a query from being executed before the session is authenticated.
func TestSCRAMAuthenticateRejectsTheWrongMessageType(t *testing.T) {
	verifier := scramVerifierFor(t, "s3cret")

	t.Run("instead of the initial response", func(t *testing.T) {
		auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
		if err != nil {
			t.Fatalf("new scram auth: %v", err)
		}
		fe, errCh, _ := startSCRAMServer(t, auth, "alice")
		awaitSASLOffer(t, fe)

		fe.Send(&pgproto3.Query{String: "SELECT 1"})
		if err := fe.Flush(); err != nil {
			t.Fatalf("send query: %v", err)
		}

		authErr := <-errCh
		if authErr == nil || !strings.Contains(authErr.Error(), "expected SASLInitialResponse") {
			t.Fatalf("error = %v, want a refusal naming SASLInitialResponse", authErr)
		}
	})

	t.Run("instead of the final response", func(t *testing.T) {
		auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
		if err != nil {
			t.Fatalf("new scram auth: %v", err)
		}
		fe, errCh, _ := startSCRAMServer(t, auth, "alice")
		awaitSASLOffer(t, fe)

		client, err := scram.SHA256.NewClient("alice", "s3cret", "")
		if err != nil {
			t.Fatalf("new scram client: %v", err)
		}
		conv := client.NewConversation()
		first, err := conv.Step("")
		if err != nil {
			t.Fatalf("client first: %v", err)
		}
		fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte(first)})
		if err := fe.Flush(); err != nil {
			t.Fatalf("send initial response: %v", err)
		}
		if _, err := fe.Receive(); err != nil {
			t.Fatalf("await sasl continue: %v", err)
		}

		fe.Send(&pgproto3.Query{String: "SELECT 1"})
		if err := fe.Flush(); err != nil {
			t.Fatalf("send query: %v", err)
		}

		authErr := <-errCh
		if authErr == nil || !strings.Contains(authErr.Error(), "expected SASLResponse") {
			t.Fatalf("error = %v, want a refusal naming SASLResponse", authErr)
		}
	})
}

// TestSCRAMAuthenticateReportsAClientThatDisappears: a client that
// vanishes mid-handshake is normal traffic — a cancelled connect, a
// timeout, a port scanner. Each step has to return the read or write
// error instead of blocking, because the goroutine and the connection
// slot behind it are not free.
func TestSCRAMAuthenticateReportsAClientThatDisappears(t *testing.T) {
	verifier := scramVerifierFor(t, "s3cret")

	t.Run("before the offer can be sent", func(t *testing.T) {
		auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
		if err != nil {
			t.Fatalf("new scram auth: %v", err)
		}
		_, errCh, clientConn := startSCRAMServer(t, auth, "alice")
		_ = clientConn.Close()

		authErr := <-errCh
		if authErr == nil || !strings.Contains(authErr.Error(), "send sasl mechanisms") {
			t.Fatalf("error = %v, want the failure to be attributed to the write", authErr)
		}
	})

	t.Run("after reading the offer", func(t *testing.T) {
		auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
		if err != nil {
			t.Fatalf("new scram auth: %v", err)
		}
		fe, errCh, clientConn := startSCRAMServer(t, auth, "alice")
		awaitSASLOffer(t, fe)
		_ = clientConn.Close()

		authErr := <-errCh
		if authErr == nil || !strings.Contains(authErr.Error(), "receive sasl initial response") {
			t.Fatalf("error = %v, want the failure to be attributed to the read", authErr)
		}
	})

	// The remaining stages need a client that gets far enough to be
	// mid-conversation, so they walk the real exchange and stop at the
	// step under test.
	stages := []struct {
		name string
		// steps is how many client messages to send before vanishing.
		steps int
		want  string
	}{
		{"while the server answers the first step", 1, "send sasl continue"},
		{"while the server waits for the proof", 2, "receive sasl response"},
		// The last send returns its error unwrapped, unlike every other
		// step, so there is no stage name to match on — only that the
		// write failure is reported at all.
		{"while the server confirms its own signature", 3, ""},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			auth, err := NewSCRAMAuth(map[string]string{"alice": verifier}, nil)
			if err != nil {
				t.Fatalf("new scram auth: %v", err)
			}
			fe, errCh, clientConn := startSCRAMServer(t, auth, "alice")
			awaitSASLOffer(t, fe)

			client, err := scram.SHA256.NewClient("alice", "s3cret", "")
			if err != nil {
				t.Fatalf("new scram client: %v", err)
			}
			conv := client.NewConversation()
			first, err := conv.Step("")
			if err != nil {
				t.Fatalf("client first: %v", err)
			}
			fe.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte(first)})
			if err := fe.Flush(); err != nil {
				t.Fatalf("send initial response: %v", err)
			}

			if stage.steps >= 2 {
				msg, err := fe.Receive()
				if err != nil {
					t.Fatalf("await sasl continue: %v", err)
				}
				cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
				if !ok {
					t.Fatalf("expected AuthenticationSASLContinue, got %T", msg)
				}
				if stage.steps >= 3 {
					final, err := conv.Step(string(cont.Data))
					if err != nil {
						t.Fatalf("client final: %v", err)
					}
					fe.Send(&pgproto3.SASLResponse{Data: []byte(final)})
					if err := fe.Flush(); err != nil {
						t.Fatalf("send final response: %v", err)
					}
				}
			}
			_ = clientConn.Close()

			authErr := <-errCh
			if authErr == nil {
				t.Fatalf("a client that vanished %s produced a successful login", stage.name)
			}
			if !strings.Contains(authErr.Error(), stage.want) {
				t.Fatalf("error = %v, want it attributed to %q", authErr, stage.want)
			}
		})
	}
}

// TestCaptureClientKeyDegradesInsteadOfFailingTheLogin pins a
// deliberate asymmetry: the client has already proved itself, so a
// pass-through bookkeeping failure must not reject it. The user loses
// their own backend identity and runs as the pool's role — the
// behaviour of every pool without pass-through — rather than losing
// their session.
func TestCaptureClientKeyDegradesInsteadOfFailingTheLogin(t *testing.T) {
	creds, err := ParseSCRAMVerifier(scramVerifierFor(t, "s3cret"))
	if err != nil {
		t.Fatalf("parse verifier: %v", err)
	}
	store := newClientKeyStore()
	auth := &SCRAMAuth{}
	auth.SetClientKeyStore(store)

	// A client-final with no ",p=" proof in it: nothing can be recovered
	// from this, which is the shape of every future protocol change that
	// breaks the recovery without breaking authentication.
	auth.captureClientKey("alice", creds, scramExchange{
		ClientFirst: "n,,n=,r=abc",
		ServerFirst: "r=abcdef,s=c2FsdA==,i=4096",
		ClientFinal: "c=biws,r=abcdef",
	})
	if store.has("alice") {
		t.Error("an unrecoverable exchange was stored as usable credentials")
	}
}

// TestCaptureClientKeyIsANoOpWithoutAStore is the opt-in half of the
// same decision: with pass-through disabled no authentication material
// is ever derived, let alone retained, so a memory dump of the process
// yields verifiers and nothing more.
func TestCaptureClientKeyIsANoOpWithoutAStore(t *testing.T) {
	auth := &SCRAMAuth{}
	auth.captureClientKey("alice", scram.StoredCredentials{}, scramExchange{})
}

// TestParseSCRAMVerifierNamesTheMalformedPart: an operator pasting
// rolpassword out of pg_authid gets one shot at this, usually at 3am.
// Each branch has its own message so the error says which field is
// wrong instead of "malformed verifier".
func TestParseSCRAMVerifierNamesTheMalformedPart(t *testing.T) {
	cases := []struct {
		name     string
		verifier string
		want     string
	}{
		{
			name:     "no key section",
			verifier: "SCRAM-SHA-256$4096:c2FsdA==",
			want:     "between iterations/salt and keys",
		},
		{
			name:     "no iterations separator",
			verifier: "SCRAM-SHA-256$4096c2FsdA==$c3RvcmVk:c2VydmVy",
			want:     "between iterations and salt",
		},
		{
			name:     "no key separator",
			verifier: "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVkc2VydmVy",
			want:     "between stored key and server key",
		},
		{
			name:     "stored key is not base64",
			verifier: "SCRAM-SHA-256$4096:c2FsdA==$not base64!:c2VydmVy",
			want:     "invalid stored key",
		},
		{
			name:     "server key is not base64",
			verifier: "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:not base64!",
			want:     "invalid server key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSCRAMVerifier(tc.verifier)
			if err == nil {
				t.Fatalf("%q parsed successfully", tc.verifier)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestGenerateSCRAMVerifierRejectsAnUnusablePassword: the generator is
// the operator-facing provisioning helper, so it has to refuse input it
// cannot turn into a working verifier rather than emit one that fails
// only when the user first tries to log in.
func TestGenerateSCRAMVerifierRejectsAnUnusablePassword(t *testing.T) {
	// SASLprep prohibits control characters, and a password that cannot
	// be normalised cannot be reproduced by a client either.
	if _, err := GenerateSCRAMVerifier("pass\u0007word", 4096); err == nil {
		t.Error("a password with a prohibited control character was accepted")
	}
}
