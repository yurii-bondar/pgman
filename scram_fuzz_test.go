package main

// Fuzzing for the two SCRAM surfaces that parse bytes somebody else
// chose: the client's proof (recoverClientKey) and the operator's
// verifier (ParseSCRAMVerifier).
//
// These are fuzzed rather than merely table-tested because they are the
// only places in pgman where a parsing mistake is a *credential* bug
// instead of a connection bug. recoverClientKey turns three strings off
// the wire into a password-equivalent secret; ParseSCRAMVerifier turns
// a config string into the thing every login is checked against. A
// table test proves the cases somebody thought of. A fuzzer is how the
// cases nobody thought of get found.
//
// The properties below are deliberately stronger than "does not panic".
// A credential routine that returns a wrong answer quietly is far worse
// than one that crashes, so each target asserts what a successful
// return is supposed to *mean*.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/xdg-go/scram"
)

// FuzzRecoverClientKey feeds arbitrary SCRAM messages to the routine
// that reconstructs a client's ClientKey from its proof.
//
// The invariant that matters: recoverClientKey must never return a key
// it has not verified. Its contract is H(ClientKey) == StoredKey, and
// that check is the only thing standing between "we parsed the
// messages correctly" and "we derived a secret from nonsense and are
// about to authenticate to Postgres with it". Asserting the property
// here means the check cannot be deleted — or rendered ineffective by a
// refactor of the string surgery around it — without a test going red.
func FuzzRecoverClientKey(f *testing.F) {
	// A genuine exchange, so the fuzzer starts from an input that
	// reaches the end of the function rather than bouncing off the
	// first parse error forever.
	ex, creds := runSCRAM(f, "hunter2", nil)
	f.Add(ex.ClientFirst, ex.ServerFirst, ex.ClientFinal, creds.StoredKey)

	// Channel binding changes the gs2 header and the c= field, which is
	// exactly the shape clientFirstBare has to cut correctly.
	cbEx, cbCreds := runSCRAM(f, "hunter2", &scram.ChannelBinding{
		Type: scram.ChannelBindingTLSServerEndpoint,
		Data: []byte("0123456789abcdef"),
	})
	f.Add(cbEx.ClientFirst, cbEx.ServerFirst, cbEx.ClientFinal, cbCreds.StoredKey)

	// Degenerate shapes worth pinning as corpus entries in their own
	// right: every one of them is a different early return.
	f.Add("", "", "", []byte(nil))
	f.Add("n,,n=user,r=abc", "r=abcdef,s=c2FsdA==,i=4096", "c=biws,r=abcdef,p=", []byte("short"))
	f.Add("n,,", "", ",p=!!!not-base64!!!", make([]byte, sha256.Size))

	f.Fuzz(func(t *testing.T, clientFirst, serverFirst, clientFinal string, storedKey []byte) {
		key, err := recoverClientKey(scramExchange{
			ClientFirst: clientFirst,
			ServerFirst: serverFirst,
			ClientFinal: clientFinal,
		}, storedKey)

		if err != nil {
			if key != nil {
				t.Fatalf("returned a %d-byte key alongside an error (%v) — a caller that only checks err would use it", len(key), err)
			}
			return
		}

		// Success means the function claims this key authenticates as
		// the user the verifier belongs to. That claim has exactly one
		// definition, and it is cheap to re-check.
		sum := sha256.Sum256(key)
		if !hmac.Equal(sum[:], storedKey) {
			t.Fatalf("recoverClientKey accepted a key whose H(ClientKey) does not equal StoredKey\n"+
				"  client-first: %q\n  server-first: %q\n  client-final: %q",
				clientFirst, serverFirst, clientFinal)
		}
		if len(key) != sha256.Size {
			t.Fatalf("recovered key is %d bytes, want %d", len(key), sha256.Size)
		}
	})
}

// FuzzParseSCRAMVerifier fuzzes the config-facing half: the string an
// operator copies out of `SELECT rolpassword FROM pg_authid`.
//
// A verifier that parses into a structurally impossible credential is
// worse than one that fails to parse. The process starts, reports
// healthy, and then rejects every login for that user — with the cause
// sitting in a config file that looked fine. So the property is not
// "does not panic" but "anything accepted here can actually be used".
func FuzzParseSCRAMVerifier(f *testing.F) {
	good, err := GenerateSCRAMVerifier("s3cret", 4096)
	if err != nil {
		f.Fatalf("generate verifier: %v", err)
	}
	f.Add(good)
	f.Add("")
	f.Add("SCRAM-SHA-256$")
	f.Add("SCRAM-SHA-256$4096:c2FsdA==$" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) +
		":" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
	f.Add("SCRAM-SHA-256$0:c2FsdA==$aGk=:aGk=")
	f.Add("SCRAM-SHA-256$-1:c2FsdA==$aGk=:aGk=")
	f.Add("md5deadbeef")

	f.Fuzz(func(t *testing.T, verifier string) {
		creds, err := ParseSCRAMVerifier(verifier)
		if err != nil {
			return
		}

		// An iteration count of zero or less is not a slow verifier, it
		// is a broken one: it feeds straight into PBKDF2 as the work
		// factor. Accepting it turns a credential parser into a silent
		// downgrade.
		if creds.Iters <= 0 {
			t.Fatalf("accepted verifier %q with iteration count %d", verifier, creds.Iters)
		}
		// Both keys are SHA-256 outputs by construction. A verifier
		// carrying anything else can never match a real exchange, so
		// accepting it only defers the failure to every login attempt.
		if len(creds.StoredKey) != sha256.Size {
			t.Fatalf("accepted verifier %q with a %d-byte stored key, want %d",
				verifier, len(creds.StoredKey), sha256.Size)
		}
		if len(creds.ServerKey) != sha256.Size {
			t.Fatalf("accepted verifier %q with a %d-byte server key, want %d",
				verifier, len(creds.ServerKey), sha256.Size)
		}
		if creds.Salt == "" {
			t.Fatalf("accepted verifier %q with an empty salt", verifier)
		}
	})
}

// FuzzSCRAMVerifierRoundTrip closes the loop between the two functions
// an operator touches: the one that prints a verifier
// (-gen-scram-verifier) and the one that reads it back out of the
// config. A password that survives the first and is mangled by the
// second locks a user out, and the shapes that do that are exactly the
// ones nobody types by hand — empty strings, embedded separators,
// invalid UTF-8.
func FuzzSCRAMVerifierRoundTrip(f *testing.F) {
	f.Add("s3cret")
	f.Add("")
	f.Add("pass$word:with$separators")
	f.Add("üñïçødé พาสเวิร์ด")
	f.Add("\x00\xff\xfe")

	f.Fuzz(func(t *testing.T, password string) {
		// The smallest iteration count the parser will accept: this
		// target is about the string format, and PBKDF2 work would make
		// the fuzzer explore a handful of inputs per second.
		verifier, err := GenerateSCRAMVerifier(password, 1)
		if err != nil {
			return // refusing a password outright is a valid answer
		}
		if strings.ContainsAny(verifier, "\n\r") {
			t.Fatalf("verifier for %q contains a newline — it would corrupt the YAML it is pasted into", password)
		}
		creds, err := ParseSCRAMVerifier(verifier)
		if err != nil {
			t.Fatalf("a verifier this binary generated did not parse: %v (password %q)", err, password)
		}
		if len(creds.StoredKey) != sha256.Size {
			t.Fatalf("round-tripped stored key is %d bytes, want %d", len(creds.StoredKey), sha256.Size)
		}
	})
}
