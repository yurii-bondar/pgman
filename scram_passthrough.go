// Package main — SCRAM pass-through: the credential store and the
// client half of the exchange with Postgres.
//
// See scram_clientkey.go for how ClientKey is obtained. This file is
// what uses it: a per-user store filled on every successful client
// login, and a SCRAM client that authenticates with ClientKey in place
// of a password.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// passthroughCreds is everything needed to authenticate to Postgres as
// one user: ClientKey to produce the proof, and the verifier for the
// salt/iteration check and for validating the server's own signature.
type passthroughCreds struct {
	clientKey []byte
	creds     scram.StoredCredentials
}

// clientKeyStore holds recovered ClientKeys, keyed by username.
//
// A ClientKey is password-equivalent for its user against a server with
// the same verifier, so this is the one place pgman keeps authentication
// material rather than a verifier. That is a real trade and the reason
// pass-through is opt-in: a memory dump of this process yields working
// credentials, where before it yielded only verifiers. It is still the
// better half of the bargain, because the alternative — a per-user
// password or passfile on disk — is worse in every respect and is
// readable without a memory dump.
//
// Entries live for the process's lifetime and are overwritten on each
// successful login, so a password rotation takes effect on the next one.
type clientKeyStore struct {
	mu   sync.RWMutex
	keys map[string]passthroughCreds
}

func newClientKeyStore() *clientKeyStore {
	return &clientKeyStore{keys: make(map[string]passthroughCreds)}
}

// remember records the material recovered from a client's successful
// SCRAM exchange. Nil-safe: pass-through disabled means no store.
func (s *clientKeyStore) remember(user string, clientKey []byte, creds scram.StoredCredentials) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.keys[user] = passthroughCreds{clientKey: clientKey, creds: creds}
	s.mu.Unlock()
}

func (s *clientKeyStore) lookup(user string) (passthroughCreds, bool) {
	if s == nil {
		return passthroughCreds{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	pc, ok := s.keys[user]
	return pc, ok
}

// has reports whether a user has authenticated via SCRAM since startup,
// which is what decides whether that user can get a pass-through pool.
func (s *clientKeyStore) has(user string) bool {
	_, ok := s.lookup(user)
	return ok
}

// scramClientAuth performs the client half of SCRAM-SHA-256 against a
// Postgres backend, signing with ClientKey instead of a password.
//
// Channel binding is deliberately not offered. SCRAM-SHA-256-PLUS binds
// the exchange to a specific TLS connection, and the material pgman has
// binds it to the client's connection, not this one — so there is
// nothing honest to bind with here. The backend connection's own
// integrity comes from sslmode=verify-full, which is what
// require_backend_tls is for.
func scramClientAuth(fe *pgproto3.Frontend, user string, pc passthroughCreds, mechanisms []string) error {
	if !slicesContain(mechanisms, "SCRAM-SHA-256") {
		return fmt.Errorf("backend offers %v, none of which is SCRAM-SHA-256", mechanisms)
	}

	nonce, err := scramNonce()
	if err != nil {
		return err
	}
	// Postgres ignores the username inside the SCRAM exchange and
	// authenticates against the startup message's user, so an empty n=
	// avoids having to SASLprep a name that is not consulted anyway.
	const gs2Header = "n,,"
	clientFirstBare := "n=,r=" + nonce

	fe.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(gs2Header + clientFirstBare),
	})
	if err := fe.Flush(); err != nil {
		return fmt.Errorf("send sasl initial response: %w", err)
	}

	msg, err := fe.Receive()
	if err != nil {
		return fmt.Errorf("receive sasl continue: %w", err)
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", msg)
	}
	serverFirst := string(cont.Data)

	serverNonce, salt, iters, err := parseServerFirst(serverFirst)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(serverNonce, nonce) {
		return fmt.Errorf("backend nonce does not extend ours — possible man in the middle")
	}
	// ClientKey is derived from the salt and iteration count, so it is
	// only valid against a verifier built from the same ones. Checking
	// here turns "password authentication failed", which sends an
	// operator hunting for a wrong password that does not exist, into a
	// statement of what is actually wrong.
	if salt != pc.creds.Salt || iters != pc.creds.Iters {
		return fmt.Errorf("pgman's verifier for %q does not match the backend's "+
			"(salt or iteration count differ) — SCRAM pass-through requires the same "+
			"verifier on both sides, so auth_users must hold a copy of the backend's "+
			"rolpassword, or auth_query must read pg_shadow on this backend", user)
	}

	clientFinalWithoutProof := "c=" + base64.StdEncoding.EncodeToString([]byte(gs2Header)) + ",r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	storedKey := sha256.Sum256(pc.clientKey)
	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	proof := make([]byte, len(pc.clientKey))
	for i := range proof {
		proof[i] = pc.clientKey[i] ^ clientSignature[i]
	}

	fe.Send(&pgproto3.SASLResponse{
		Data: []byte(clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(proof)),
	})
	if err := fe.Flush(); err != nil {
		return fmt.Errorf("send sasl response: %w", err)
	}

	msg, err = fe.Receive()
	if err != nil {
		return fmt.Errorf("receive sasl final: %w", err)
	}
	final, ok := msg.(*pgproto3.AuthenticationSASLFinal)
	if !ok {
		return fmt.Errorf("expected AuthenticationSASLFinal, got %T", msg)
	}
	// Mutual authentication: the server proves it knows ServerKey, which
	// is what stops us handing queries to something that merely accepted
	// our proof. Skipping it would leave half of SCRAM unused.
	if err := verifyServerSignature(string(final.Data), pc.creds.ServerKey, authMessage); err != nil {
		return err
	}
	return nil
}

func verifyServerSignature(serverFinal string, serverKey []byte, authMessage string) error {
	if strings.HasPrefix(serverFinal, "e=") {
		return fmt.Errorf("backend rejected the SCRAM proof: %s", serverFinal[2:])
	}
	if !strings.HasPrefix(serverFinal, "v=") {
		return fmt.Errorf("malformed server-final message %q", serverFinal)
	}
	got, err := base64.StdEncoding.DecodeString(serverFinal[2:])
	if err != nil {
		return fmt.Errorf("server signature is not valid base64: %w", err)
	}
	want := hmacSHA256(serverKey, []byte(authMessage))
	if !constantTimeEqual(got, want) {
		return fmt.Errorf("backend server signature is wrong — it does not hold this user's credentials")
	}
	return nil
}

// parseServerFirst splits "r=<nonce>,s=<salt-b64>,i=<iterations>".
func parseServerFirst(s string) (nonce, salt string, iters int, err error) {
	for _, field := range strings.Split(s, ",") {
		if len(field) < 2 || field[1] != '=' {
			continue
		}
		value := field[2:]
		switch field[0] {
		case 'r':
			nonce = value
		case 's':
			raw, decodeErr := base64.StdEncoding.DecodeString(value)
			if decodeErr != nil {
				return "", "", 0, fmt.Errorf("backend salt is not valid base64: %w", decodeErr)
			}
			salt = string(raw)
		case 'i':
			iters, err = strconv.Atoi(value)
			if err != nil {
				return "", "", 0, fmt.Errorf("backend iteration count %q is not a number", value)
			}
		}
	}
	if nonce == "" || salt == "" || iters <= 0 {
		return "", "", 0, fmt.Errorf("incomplete server-first message %q", s)
	}
	return nonce, salt, iters, nil
}

// scramNonce returns a fresh client nonce. Base64 of 18 random bytes
// keeps it inside the printable, comma-free alphabet the grammar
// requires without needing to filter anything out.
func scramNonce() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("scram: generate nonce: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func slicesContain(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// constantTimeEqual compares two byte slices without leaking which byte
// differed. The server signature is attacker-influenceable, so the
// comparison has to be blind to content.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
