package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// AuthBackend performs the client-facing auth handshake — it owns however
// many round trips its mechanism needs (SCRAM is multi-step, unlike a
// single password check) and returns nil only once the client has proven
// who they claim to be. conn is passed alongside pg because TLS channel
// binding needs the actual *tls.Conn, not just the message stream.
type AuthBackend interface {
	Authenticate(pg *pgproto3.Backend, conn net.Conn, startup *pgproto3.StartupMessage) error
}

// TrustAuth accepts every client unconditionally — kept only as an escape
// hatch for local dev; SCRAMAuth is what a real config should use.
type TrustAuth struct{}

func (TrustAuth) Authenticate(*pgproto3.Backend, net.Conn, *pgproto3.StartupMessage) error {
	return nil
}

// SCRAMAuth authenticates clients with SCRAM-SHA-256 (RFC 5802/7677) only —
// no MD5, no cleartext password fallback. PgBouncer still carries both of
// those for legacy compatibility; this proxy has no legacy deployments to
// support, so there's no reason to keep that downgrade surface open.
//
// When the client connection is over TLS, SCRAM-SHA-256-PLUS is also
// offered with tls-server-end-point channel binding (RFC 5929) — the
// mechanism real Postgres itself uses for channel-bound SCRAM. This
// cryptographically ties the auth exchange to *this specific* TLS
// connection, closing the one gap plain SCRAM has: a MITM that terminates
// TLS and relays the SCRAM bytes through untouched. A default PgBouncer
// setup doesn't offer this.
//
// Credentials are stored as SCRAM verifiers — salt, iteration count,
// StoredKey, ServerKey — in Postgres's own `SCRAM-SHA-256$iters:salt$stored:server`
// format, the exact string `SELECT rolpassword FROM pg_authid` returns.
// The plaintext password itself is never stored anywhere in this process
// past the moment (if ever) an operator used it to generate a verifier.
type SCRAMAuth struct {
	users map[string]scram.StoredCredentials

	// dynamicLookup is an optional resolver hit ONLY when a user isn't
	// found in the static users map above — mirrors PgBouncer's
	// auth_query. Returns an error if the user really doesn't exist or
	// the auth backend can't be reached. Result is not cached here;
	// implementations are expected to do their own caching (see
	// AuthQueryProvider) because eviction / TTL policy is provider-
	// specific and shouldn't leak into the auth path.
	dynamicLookup func(user string) (scram.StoredCredentials, error)

	// keyStore, when set, receives the ClientKey recovered from every
	// successful exchange, for SCRAM pass-through to authenticate to
	// Postgres as this same user. Nil when pass-through is disabled,
	// and then nothing is ever recovered or retained.
	keyStore *clientKeyStore

	// serverEndpointBinding is precomputed once at startup from the
	// proxy's own TLS certificate — tls-server-end-point (RFC 5929) hashes
	// the *server's* certificate, and that's the same certificate on every
	// connection, so there's no need to recompute it per handshake. Nil
	// when TLS isn't configured, in which case SCRAM-SHA-256-PLUS is
	// simply never offered.
	serverEndpointBinding *scram.ChannelBinding
}

// SetClientKeyStore enables SCRAM pass-through capture. Call it only
// when at least one pool asks for pass-through: without a store no
// authentication material is ever derived, let alone kept.
func (a *SCRAMAuth) SetClientKeyStore(store *clientKeyStore) {
	a.keyStore = store
}

// SetDynamicLookup wires an auth_query-style resolver used when a user
// isn't present in the static verifier map. Optional; if nil, unknown
// users are simply rejected.
func (a *SCRAMAuth) SetDynamicLookup(fn func(user string) (scram.StoredCredentials, error)) {
	a.dynamicLookup = fn
}

// NewSCRAMAuth builds an SCRAMAuth from username -> verifier-string pairs
// (see ParseSCRAMVerifier for the format). Fails closed: any malformed
// verifier is a config error, not a runtime surprise. tlsCert is the
// proxy's own certificate (nil if TLS is disabled) — used only to compute
// the tls-server-end-point channel binding for SCRAM-SHA-256-PLUS.
func NewSCRAMAuth(users map[string]string, tlsCert *tls.Certificate) (*SCRAMAuth, error) {
	creds := make(map[string]scram.StoredCredentials, len(users))
	for user, verifier := range users {
		sc, err := ParseSCRAMVerifier(verifier)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", user, err)
		}
		creds[user] = sc
	}

	a := &SCRAMAuth{users: creds}
	if tlsCert != nil {
		cb, err := tlsServerEndpointBinding(tlsCert)
		if err != nil {
			return nil, fmt.Errorf("tls-server-end-point channel binding: %w", err)
		}
		a.serverEndpointBinding = &cb
	}
	return a, nil
}

// tlsServerEndpointBinding computes the RFC 5929 tls-server-end-point
// value for cert: a hash of the DER-encoded leaf certificate, using
// SHA-256 unless the certificate itself was signed with SHA-384/SHA-512,
// per the RFC's "use the cert's own signature hash, or SHA-256 if that
// hash is MD5 or SHA-1" rule. This mirrors scram.NewTLSServerEndpointBinding
// exactly, just applied to *our own* certificate instead of a peer's —
// that library helper only reads connState.PeerCertificates, which is
// empty on our side (the TLS server) without mutual TLS.
func tlsServerEndpointBinding(cert *tls.Certificate) (scram.ChannelBinding, error) {
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return scram.ChannelBinding{}, fmt.Errorf("parse leaf certificate: %w", err)
		}
		leaf = parsed
	}

	var h hash.Hash
	switch leaf.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h = sha512.New384()
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h = sha512.New()
	default:
		h = sha256.New() // covers SHA-256 signatures, and the RFC's MD5/SHA-1 fallback
	}
	h.Write(leaf.Raw)

	return scram.ChannelBinding{Type: scram.ChannelBindingTLSServerEndpoint, Data: h.Sum(nil)}, nil
}

func (a *SCRAMAuth) Authenticate(pg *pgproto3.Backend, conn net.Conn, startup *pgproto3.StartupMessage) error {
	user := startup.Parameters["user"]
	creds, ok := a.users[user]
	if !ok {
		// Fall back to auth_query-style dynamic lookup if configured.
		// This is the same escape hatch PgBouncer uses to avoid
		// listing every application user in the static config.
		if a.dynamicLookup == nil {
			return fmt.Errorf("no such user %q", user)
		}
		resolved, err := a.dynamicLookup(user)
		if err != nil {
			return fmt.Errorf("auth_query lookup for %q: %w", user, err)
		}
		creds = resolved
	}

	mechanisms := []string{"SCRAM-SHA-256"}
	var channelBinding scram.ChannelBinding
	haveChannelBinding := false
	if _, isTLS := conn.(*tls.Conn); isTLS && a.serverEndpointBinding != nil {
		channelBinding = *a.serverEndpointBinding
		haveChannelBinding = true
		mechanisms = []string{"SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"} // offer the stronger one first
	}

	// pgproto3 v5 changed Send() from returning an error to buffering
	// silently — every state-changing send now needs an explicit Flush()
	// afterward, and that Flush is where the write error actually
	// surfaces. Keep the buffered-then-flushed pattern paired every time.
	pg.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: mechanisms})
	if err := pg.Flush(); err != nil {
		return fmt.Errorf("send sasl mechanisms: %w", err)
	}
	if err := pg.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		return fmt.Errorf("set auth type: %w", err)
	}

	msg, err := pg.Receive()
	if err != nil {
		return fmt.Errorf("receive sasl initial response: %w", err)
	}
	initial, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok {
		return fmt.Errorf("expected SASLInitialResponse, got %T", msg)
	}
	// Copied now, not later: pgproto3 decodes into a reused buffer, so
	// initial.Data is overwritten by the next Receive. Pass-through
	// needs this message verbatim once the exchange has completed.
	clientFirst := string(initial.Data)

	server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		// Real Postgres ignores the username embedded in the SCRAM message
		// itself and authenticates strictly against the StartupMessage's
		// "user" — we do the same, so this lookup always returns the one
		// set of credentials we already resolved above.
		return creds, nil
	})
	if err != nil {
		return fmt.Errorf("init scram server: %w", err)
	}

	var conv *scram.ServerConversation
	switch initial.AuthMechanism {
	case "SCRAM-SHA-256-PLUS":
		if !haveChannelBinding {
			return fmt.Errorf("client requested SCRAM-SHA-256-PLUS but this connection has no TLS channel binding available")
		}
		conv = server.NewConversationWithChannelBindingRequired(channelBinding)
	case "SCRAM-SHA-256":
		conv = server.NewConversation()
	default:
		return fmt.Errorf("unsupported SASL mechanism %q", initial.AuthMechanism)
	}
	slog.Debug("scram: negotiated", "user", user, "mechanism", initial.AuthMechanism)

	serverFirst, err := conv.Step(string(initial.Data))
	if err != nil {
		return fmt.Errorf("scram step 1: %w", err)
	}
	pg.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := pg.Flush(); err != nil {
		return fmt.Errorf("send sasl continue: %w", err)
	}
	if err := pg.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		return fmt.Errorf("set auth type: %w", err)
	}

	msg, err = pg.Receive()
	if err != nil {
		return fmt.Errorf("receive sasl response: %w", err)
	}
	final, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return fmt.Errorf("expected SASLResponse, got %T", msg)
	}
	clientFinal := string(final.Data)

	serverFinal, err := conv.Step(string(final.Data))
	if err != nil {
		return fmt.Errorf("scram verification failed: %w", err)
	}
	if !conv.Valid() {
		// Defense in depth: Step's own error is what should gate this in
		// practice, but an explicit Valid() check costs nothing and removes
		// any doubt about which signal actually matters here.
		return fmt.Errorf("scram conversation did not validate")
	}

	// The client has proved itself, which means its proof carries a
	// recoverable ClientKey — the credential pass-through needs to open
	// backend connections as this user. Captured here rather than
	// reconstructed later because these three messages are gone the
	// moment this function returns.
	a.captureClientKey(user, creds, scramExchange{
		ClientFirst: clientFirst,
		ServerFirst: serverFirst,
		ClientFinal: clientFinal,
	})

	pg.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
	if err := pg.Flush(); err != nil {
		// Named like every other stage in this function. A client that
		// disappears exactly here is indistinguishable from one that
		// disappeared at any other send unless the error says which.
		return fmt.Errorf("send sasl final: %w", err)
	}
	return nil
}

// captureClientKey recovers and stores the client's ClientKey. A
// failure is logged, not returned: the client has authenticated
// correctly and refusing it over a pooling-identity concern would turn
// a degraded feature into an outage. The consequence is that this
// user's queries run under the pool's own backend role instead of their
// own, which is the behaviour of every pool without pass-through — so
// the warning has to say enough to notice.
func (a *SCRAMAuth) captureClientKey(user string, creds scram.StoredCredentials, ex scramExchange) {
	if a.keyStore == nil {
		return
	}
	clientKey, err := recoverClientKey(ex, creds.StoredKey)
	if err != nil {
		slog.Warn("scram: could not recover the client key, this user falls back to the pool's own backend role",
			"user", user, "err", err)
		return
	}
	a.keyStore.remember(user, clientKey, creds)
}

// ParseSCRAMVerifier parses Postgres's own SCRAM verifier format:
// SCRAM-SHA-256$<iterations>:<salt-b64>$<storedkey-b64>:<serverkey-b64> —
// exactly what `SELECT rolpassword FROM pg_authid` returns for a role
// using SCRAM-SHA-256. Config never needs to hold a plaintext password.
func ParseSCRAMVerifier(s string) (scram.StoredCredentials, error) {
	const prefix = "SCRAM-SHA-256$"
	if !strings.HasPrefix(s, prefix) {
		return scram.StoredCredentials{}, fmt.Errorf("verifier must start with %q", prefix)
	}

	iterSalt, keys, ok := strings.Cut(s[len(prefix):], "$")
	if !ok {
		return scram.StoredCredentials{}, fmt.Errorf("malformed verifier: missing '$' between iterations/salt and keys")
	}
	iterStr, saltB64, ok := strings.Cut(iterSalt, ":")
	if !ok {
		return scram.StoredCredentials{}, fmt.Errorf("malformed verifier: missing ':' between iterations and salt")
	}
	storedB64, serverB64, ok := strings.Cut(keys, ":")
	if !ok {
		return scram.StoredCredentials{}, fmt.Errorf("malformed verifier: missing ':' between stored key and server key")
	}

	iters, err := strconv.Atoi(iterStr)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("invalid iteration count: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("invalid salt: %w", err)
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedB64)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("invalid stored key: %w", err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverB64)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("invalid server key: %w", err)
	}

	return scram.StoredCredentials{
		KeyFactors: scram.KeyFactors{Salt: string(salt), Iters: iters},
		StoredKey:  storedKey,
		ServerKey:  serverKey,
	}, nil
}

// GenerateSCRAMVerifier derives a verifier string from a plaintext password
// — an operator-facing convenience for provisioning users who don't have
// an existing Postgres role to copy rolpassword from. iterations follows
// Postgres's own default (4096) unless the caller wants a different cost.
func GenerateSCRAMVerifier(password string, iterations int) (string, error) {
	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		return "", fmt.Errorf("normalize password: %w", err)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	creds, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt), Iters: iterations})
	if err != nil {
		return "", fmt.Errorf("derive credentials: %w", err)
	}

	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(creds.StoredKey),
		base64.StdEncoding.EncodeToString(creds.ServerKey),
	), nil
}
