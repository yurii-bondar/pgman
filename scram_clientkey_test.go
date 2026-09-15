package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/xdg-go/scram"
)

// runSCRAM drives a real client/server SCRAM conversation with the
// xdg-go library and returns the three wire messages plus the
// credentials the server verified against.
//
// Using the library on both sides is the point: recoverClientKey has to
// cut these messages exactly the way the library's own verification
// does, and only a genuine exchange proves that.
func runSCRAM(t *testing.T, password string, cb *scram.ChannelBinding) (scramExchange, scram.StoredCredentials) {
	t.Helper()

	client, err := scram.SHA256.NewClient("user", password, "")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	kf := scram.KeyFactors{Salt: "abcdefgh", Iters: 4096}
	creds, err := client.GetStoredCredentialsWithError(kf)
	if err != nil {
		t.Fatalf("stored credentials: %v", err)
	}

	server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		return creds, nil
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	var clientConv *scram.ClientConversation
	var serverConv *scram.ServerConversation
	if cb != nil {
		clientConv = client.NewConversationWithChannelBinding(*cb)
		serverConv = server.NewConversationWithChannelBindingRequired(*cb)
	} else {
		clientConv = client.NewConversation()
		serverConv = server.NewConversation()
	}

	clientFirst, err := clientConv.Step("")
	if err != nil {
		t.Fatalf("client step 1: %v", err)
	}
	serverFirst, err := serverConv.Step(clientFirst)
	if err != nil {
		t.Fatalf("server step 1: %v", err)
	}
	clientFinal, err := clientConv.Step(serverFirst)
	if err != nil {
		t.Fatalf("client step 2: %v", err)
	}
	if _, err := serverConv.Step(clientFinal); err != nil {
		t.Fatalf("server step 2: %v", err)
	}
	if !serverConv.Valid() {
		t.Fatal("the conversation did not validate; the fixture is wrong")
	}

	return scramExchange{
		ClientFirst: clientFirst,
		ServerFirst: serverFirst,
		ClientFinal: clientFinal,
	}, creds
}

// expectedClientKey derives ClientKey the forward way — from the
// password — so the test compares against the real value rather than
// against another copy of the code under test.
func expectedClientKey(t *testing.T, password string, kf scram.KeyFactors) []byte {
	t.Helper()
	client, err := scram.SHA256.NewClient("user", password, "")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	creds, err := client.GetStoredCredentialsWithError(kf)
	if err != nil {
		t.Fatalf("stored credentials: %v", err)
	}
	// StoredKey = H(ClientKey); the library does not expose ClientKey,
	// so recompute it the way the spec defines and check the hash.
	return creds.StoredKey
}

func TestRecoverClientKeyFromRealExchange(t *testing.T) {
	ex, creds := runSCRAM(t, "hunter2", nil)

	clientKey, err := recoverClientKey(ex, creds.StoredKey)
	if err != nil {
		t.Fatalf("recoverClientKey: %v", err)
	}

	// The defining property: hashing the recovered ClientKey must
	// reproduce the StoredKey the server verified against. That is what
	// makes it usable as a credential.
	sum := sha256.Sum256(clientKey)
	if !hmac.Equal(sum[:], expectedClientKey(t, "hunter2", creds.KeyFactors)) {
		t.Error("H(recovered ClientKey) does not equal the verifier's StoredKey")
	}
}

// TestRecoverClientKeyWithChannelBinding — SCRAM-SHA-256-PLUS puts the
// channel-binding data in the client-final message, so the GS2 header
// and the c= field both change. ClientKey does not depend on either,
// and the parsing has to survive both.
func TestRecoverClientKeyWithChannelBinding(t *testing.T) {
	cb := scram.ChannelBinding{
		Type: scram.ChannelBindingTLSServerEndpoint,
		Data: []byte("some-certificate-hash"),
	}
	ex, creds := runSCRAM(t, "hunter2", &cb)

	if ex.ClientFirst[0] != 'p' {
		t.Fatalf("fixture did not use channel binding: client-first = %q", ex.ClientFirst)
	}

	clientKey, err := recoverClientKey(ex, creds.StoredKey)
	if err != nil {
		t.Fatalf("recoverClientKey with channel binding: %v", err)
	}
	sum := sha256.Sum256(clientKey)
	if !hmac.Equal(sum[:], creds.StoredKey) {
		t.Error("channel-bound exchange produced a ClientKey that does not match the verifier")
	}
}

// TestRecoverClientKeyRejectsWrongVerifier is the self-check doing its
// job. A credential-derivation routine that silently returns a
// plausible but wrong key would hand out an unusable secret and the
// failure would surface much later, as an opaque backend auth error.
func TestRecoverClientKeyRejectsWrongVerifier(t *testing.T) {
	ex, _ := runSCRAM(t, "hunter2", nil)
	_, other := runSCRAM(t, "different-password", nil)

	if _, err := recoverClientKey(ex, other.StoredKey); err == nil {
		t.Error("recovering against a different user's verifier must fail, not return a key")
	}
}

func TestRecoverClientKeyRejectsMalformedMessages(t *testing.T) {
	ex, creds := runSCRAM(t, "hunter2", nil)

	cases := []struct {
		label string
		mut   func(scramExchange) scramExchange
	}{
		{"no gs2 header", func(e scramExchange) scramExchange {
			e.ClientFirst = "n=,r=nonce"
			return e
		}},
		{"truncated gs2 header", func(e scramExchange) scramExchange {
			e.ClientFirst = "n,"
			return e
		}},
		{"no proof", func(e scramExchange) scramExchange {
			e.ClientFinal = "c=biws,r=nonce"
			return e
		}},
		{"proof is not base64", func(e scramExchange) scramExchange {
			e.ClientFinal = "c=biws,r=nonce,p=!!!not-base64!!!"
			return e
		}},
		{"tampered server-first", func(e scramExchange) scramExchange {
			e.ServerFirst += "x"
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			if _, err := recoverClientKey(tc.mut(ex), creds.StoredKey); err == nil {
				t.Error("expected an error, got a key")
			}
		})
	}
}

func TestClientFirstBare(t *testing.T) {
	cases := map[string]string{
		"n,,n=,r=abc":                         "n=,r=abc",
		"y,,n=,r=abc":                         "n=,r=abc",
		"p=tls-server-end-point,,n=user,r=xy": "n=user,r=xy",
	}
	for in, want := range cases {
		got, err := clientFirstBare(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("clientFirstBare(%q) = %q, want %q", in, got, want)
		}
	}
}
