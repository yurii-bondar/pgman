// Package main — SCRAM pass-through: recovering the client's ClientKey.
//
// A proxy that wants to open backend connections as the client's own
// role needs credentials for that role. Storing them is the obvious
// answer and a bad one: it puts a password-equivalent on disk for every
// user, which is exactly what SCRAM verifiers exist to avoid.
//
// SCRAM offers a way out. When a client proves itself to a SCRAM
// server, the server recovers ClientKey as part of verification:
//
//	ClientSignature = HMAC(StoredKey, AuthMessage)
//	ClientKey       = ClientProof XOR ClientSignature
//	verified iff H(ClientKey) == StoredKey
//
// ClientKey is what a SCRAM *client* needs to authenticate. So the
// proof a client sends to pgman is enough for pgman to turn around and
// authenticate to Postgres as that same user — without ever holding the
// password, and without the operator configuring anything per user.
// This is how PgBouncer's SCRAM pass-through works too.
//
// The constraint: ClientKey derives from SaltedPassword, which derives
// from the salt and iteration count. It therefore only authenticates
// against a server whose stored verifier is byte-identical to pgman's.
// That is the case when auth_query reads pg_shadow on the same server,
// or when auth_users holds a copy of rolpassword — which is what
// config.yaml already tells operators to do. recoverClientKey's callers
// check for the mismatch and say so plainly rather than letting it
// surface as an opaque authentication failure.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// scramExchange is the wire material of one completed server-side SCRAM
// conversation — exactly the three strings AuthMessage is built from.
type scramExchange struct {
	ClientFirst string // as received in SASLInitialResponse
	ServerFirst string // as produced by the server's first step
	ClientFinal string // as received in SASLResponse
}

// recoverClientKey reconstructs the client's ClientKey from a SCRAM
// exchange it has already passed.
//
// storedKey must be the verifier's StoredKey for that user. The result
// is verified against it — H(ClientKey) == StoredKey is the same check
// that validated the client in the first place, so a parsing mistake
// here cannot produce a plausible-looking wrong key. It fails loudly
// instead, which for a credential-derivation routine is the only
// acceptable way to be wrong.
func recoverClientKey(ex scramExchange, storedKey []byte) ([]byte, error) {
	bare, err := clientFirstBare(ex.ClientFirst)
	if err != nil {
		return nil, err
	}
	withoutProof, proof, err := splitClientFinal(ex.ClientFinal)
	if err != nil {
		return nil, err
	}

	authMessage := bare + "," + ex.ServerFirst + "," + withoutProof
	clientSignature := hmacSHA256(storedKey, []byte(authMessage))
	if len(proof) != len(clientSignature) {
		return nil, fmt.Errorf("scram: client proof is %d bytes, expected %d", len(proof), len(clientSignature))
	}

	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ clientSignature[i]
	}

	// The self-check. Everything above is string surgery on messages
	// another library parsed; this is what proves we cut them the same
	// way it did.
	if sum := sha256.Sum256(clientKey); !hmac.Equal(sum[:], storedKey) {
		return nil, fmt.Errorf("scram: recovered client key does not match the stored verifier")
	}
	return clientKey, nil
}

// clientFirstBare strips the GS2 header from a client-first message.
// The header is everything through the second comma — "n,,", "y,," or
// "p=tls-server-end-point,," — so the cut is the same whether or not
// channel binding was used.
func clientFirstBare(clientFirst string) (string, error) {
	first := strings.IndexByte(clientFirst, ',')
	if first < 0 {
		return "", fmt.Errorf("scram: client-first has no gs2 header")
	}
	rest := clientFirst[first+1:]
	second := strings.IndexByte(rest, ',')
	if second < 0 {
		return "", fmt.Errorf("scram: client-first gs2 header is truncated")
	}
	return rest[second+1:], nil
}

// splitClientFinal separates a client-final message into the part that
// goes into AuthMessage and the decoded proof.
func splitClientFinal(clientFinal string) (withoutProof string, proof []byte, err error) {
	i := strings.LastIndex(clientFinal, ",p=")
	if i < 0 {
		return "", nil, fmt.Errorf("scram: client-final carries no proof")
	}
	withoutProof = clientFinal[:i]
	proof, err = base64.StdEncoding.DecodeString(clientFinal[i+len(",p="):])
	if err != nil {
		return "", nil, fmt.Errorf("scram: client proof is not valid base64: %w", err)
	}
	return withoutProof, proof, nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
