package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// A Postgres that speaks just enough of the wire protocol to be dialed
// over TCP.
//
// The existing helpers in this package put a pgproto3 Backend on one end
// of a net.Pipe, which is right for testing the relay in isolation but
// cannot exercise anything that dials: connectTargets, the SSLRequest
// negotiation, SASL against a real socket, or the whole of run(). Those
// paths were the least covered in the package for exactly that reason.
//
// It is deliberately minimal and deliberately strict: it answers the
// messages pgman actually sends and fails the test on anything else,
// because a fake that quietly tolerates a malformed exchange proves
// nothing about the code that produced it.

// fakePGAuth selects how the fake server authenticates a client.
type fakePGAuth int

const (
	fakeAuthTrust  fakePGAuth = iota // AuthenticationOk immediately
	fakeAuthSCRAM                    // full SCRAM-SHA-256 exchange
	fakeAuthReject                   // ErrorResponse 28P01 instead of auth
)

type fakePGOptions struct {
	auth fakePGAuth
	// password is the one fakeAuthSCRAM accepts. The verifier is derived
	// from it, which is what makes pass-through work: pgman signs with a
	// ClientKey recovered from a verifier built the same way.
	password string
	// tls, when set, makes the server accept SSLRequest and upgrade.
	// Otherwise it answers 'N' and stays in plain text.
	tls *tls.Certificate
	// rows answers a query with a result set, for both the simple and
	// the extended protocol. A nil func — or a nil column list — means
	// "no rows", which is what DISCARD ALL, SET and SELECT 1 all need.
	//
	// One hook for both protocols because the caller should not have to
	// know which one the code under test uses: auth_query goes through
	// pgx and therefore Parse/Describe/Bind/Execute, while the pool's
	// reset query and GUC replay are simple queries.
	rows func(sql string) (cols []string, data [][]string)
}

type fakePG struct {
	t    *testing.T
	ln   net.Listener
	opts fakePGOptions

	mu       sync.Mutex
	startups []map[string]string // one per accepted connection, in order
	queries  []string
}

// startFakePG brings up the server on an ephemeral loopback port and
// tears it down with the test.
func startFakePG(t *testing.T, opts fakePGOptions) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake pg listen: %v", err)
	}
	f := &fakePG{t: t, ln: ln, opts: opts}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed by cleanup
			}
			go f.serve(conn)
		}
	}()
	return f
}

func (f *fakePG) addr() string { return f.ln.Addr().String() }

// dsn is a keyword DSN pointing at this server, with sslmode chosen to
// match whether the server can actually do TLS.
func (f *fakePG) dsn(user, database string) string {
	host, port, _ := net.SplitHostPort(f.addr())
	sslmode := "disable"
	if f.opts.tls != nil {
		// The certificate is self-signed and generated per test, so
		// verification cannot succeed — require encryption without
		// asserting an identity.
		sslmode = "require"
	}
	return fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=%s", user, host, port, database, sslmode)
}

func (f *fakePG) startupParams() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.startups...)
}

func (f *fakePG) seenQueries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func (f *fakePG) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	// A test that hangs tells you nothing; a test that fails on a
	// deadline tells you which side stopped talking.
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	be := pgproto3.NewBackend(conn, conn)
	startup, err := be.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := startup.(*pgproto3.SSLRequest); ok {
		if f.opts.tls == nil {
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
		} else {
			if _, err := conn.Write([]byte{'S'}); err != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{
				Certificates: []tls.Certificate{*f.opts.tls},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
			be = pgproto3.NewBackend(conn, conn)
		}
		if startup, err = be.ReceiveStartupMessage(); err != nil {
			return
		}
	}

	sm, ok := startup.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	f.mu.Lock()
	f.startups = append(f.startups, sm.Parameters)
	f.mu.Unlock()

	if err := f.authenticate(be, sm.Parameters["user"]); err != nil {
		// Logged rather than swallowed: a rejected handshake is
		// sometimes the point of the test and sometimes the reason a
		// different assertion failed three layers up.
		f.t.Logf("fake pg: authentication for %q failed: %v", sm.Parameters["user"], err)
		return
	}

	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0 (pgman fake)"})
	be.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: secretBytes(0xDEAD)})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return
	}

	f.serveQueries(be)
}

// authenticate runs the chosen auth exchange. Returns an error when the
// client is not authenticated, in which case the caller drops the
// connection.
func (f *fakePG) authenticate(be *pgproto3.Backend, user string) error {
	switch f.opts.auth {
	case fakeAuthReject:
		be.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL", Code: "28P01", Message: "password authentication failed",
		})
		_ = be.Flush()
		return errors.New("rejected")

	case fakeAuthSCRAM:
		return f.authenticateSCRAM(be, user)

	default:
		be.Send(&pgproto3.AuthenticationOk{})
		return nil
	}
}

// authenticateSCRAM is a real server-side SCRAM-SHA-256 conversation,
// driven by the same library the proxy's own SCRAM server uses. Real
// rather than scripted because the point of the pass-through tests is
// that a ClientKey recovered from one exchange produces a proof another
// server accepts — a fake that rubber-stamps the proof would pass while
// the derivation was wrong.
func (f *fakePG) authenticateSCRAM(be *pgproto3.Backend, user string) error {
	kf := scram.KeyFactors{Salt: "fakepgsalt", Iters: 4096}
	client, err := scram.SHA256.NewClient(user, f.opts.password, "")
	if err != nil {
		return err
	}
	creds, err := client.GetStoredCredentialsWithError(kf)
	if err != nil {
		return err
	}
	server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		return creds, nil
	})
	if err != nil {
		return err
	}
	conv := server.NewConversation()

	be.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := be.Flush(); err != nil {
		return err
	}
	// pgproto3 cannot decode a 'p' message without knowing which auth
	// exchange is in flight — they all share the same message type byte.
	// Skipping this makes the client's SASLInitialResponse arrive as a
	// plain PasswordMessage, which is the kind of confusing failure a
	// fake server should not be the source of.
	if err := be.SetAuthType(pgproto3.AuthTypeSASL); err != nil {
		return err
	}

	initial, err := be.Receive()
	if err != nil {
		return err
	}
	first, ok := initial.(*pgproto3.SASLInitialResponse)
	if !ok {
		return fmt.Errorf("expected SASLInitialResponse, got %T", initial)
	}
	serverFirst, err := conv.Step(string(first.Data))
	if err != nil {
		return err
	}
	be.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := be.Flush(); err != nil {
		return err
	}
	if err := be.SetAuthType(pgproto3.AuthTypeSASLContinue); err != nil {
		return err
	}

	response, err := be.Receive()
	if err != nil {
		return err
	}
	final, ok := response.(*pgproto3.SASLResponse)
	if !ok {
		return fmt.Errorf("expected SASLResponse, got %T", response)
	}
	serverFinal, err := conv.Step(string(final.Data))
	if err != nil {
		be.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL", Code: "28P01", Message: "SCRAM proof rejected: " + err.Error(),
		})
		_ = be.Flush()
		return err
	}
	be.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
	be.Send(&pgproto3.AuthenticationOk{})
	return nil
}

// serveQueries answers messages until the client goes away.
//
// Both protocols are handled because both are used against this fake:
// the pool's reset query and GUC replay are simple queries, while
// anything going through pgx — auth_query — uses Parse / Describe /
// Bind / Execute and will reject a server that answers Describe with
// NoData when the statement does return rows.
func (f *fakePG) serveQueries(be *pgproto3.Backend) {
	// The statement the last Parse named, so Describe and Execute know
	// which result set they are describing. One slot is enough: pgx
	// finishes a statement before starting the next on one connection.
	var parsed string

	for {
		msg, err := be.Receive()
		if err != nil {
			return // EOF, reset, or deadline — all mean "client is gone"
		}
		switch m := msg.(type) {
		case *pgproto3.Terminate:
			return

		case *pgproto3.Query:
			f.record(m.String)
			cols, data := f.resultFor(m.String)
			f.sendResult(be, m.String, cols, data)
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}

		case *pgproto3.Parse:
			parsed = m.Query
			f.record(m.Query)
			be.Send(&pgproto3.ParseComplete{})

		case *pgproto3.Describe:
			// ParameterDescription first, then the shape of the rows —
			// the order libpq and pgx both expect.
			if m.ObjectType == 'S' {
				be.Send(&pgproto3.ParameterDescription{ParameterOIDs: textOIDs(parsed)})
			}
			if cols, _ := f.resultFor(parsed); len(cols) > 0 {
				be.Send(&pgproto3.RowDescription{Fields: textFields(cols)})
			} else {
				be.Send(&pgproto3.NoData{})
			}

		case *pgproto3.Bind:
			be.Send(&pgproto3.BindComplete{})

		case *pgproto3.Execute:
			cols, data := f.resultFor(parsed)
			for _, row := range data {
				be.Send(&pgproto3.DataRow{Values: textValues(row)})
			}
			be.Send(&pgproto3.CommandComplete{CommandTag: commandTag(parsed, len(cols), len(data))})

		case *pgproto3.Close:
			be.Send(&pgproto3.CloseComplete{})

		case *pgproto3.Sync:
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := be.Flush(); err != nil {
				return
			}
		}
	}
}

func (f *fakePG) record(sql string) {
	f.mu.Lock()
	f.queries = append(f.queries, sql)
	f.mu.Unlock()
}

func (f *fakePG) resultFor(sql string) (cols []string, data [][]string) {
	if f.opts.rows == nil || sql == "" {
		return nil, nil
	}
	return f.opts.rows(sql)
}

// sendResult writes a simple-query result: the row shape, the rows, then
// the tag. Skipped entirely for a statement that returns nothing.
func (f *fakePG) sendResult(be *pgproto3.Backend, sql string, cols []string, data [][]string) {
	if len(cols) > 0 {
		be.Send(&pgproto3.RowDescription{Fields: textFields(cols)})
		for _, row := range data {
			be.Send(&pgproto3.DataRow{Values: textValues(row)})
		}
	}
	be.Send(&pgproto3.CommandComplete{CommandTag: commandTag(sql, len(cols), len(data))})
}

// textFields describes every column as text, which is enough for the
// queries pgman itself runs: it reads verifiers and GUC values, never
// binary-encoded types.
func textFields(cols []string) []pgproto3.FieldDescription {
	fields := make([]pgproto3.FieldDescription, 0, len(cols))
	for _, c := range cols {
		fields = append(fields, pgproto3.FieldDescription{
			Name:         []byte(c),
			DataTypeOID:  25, // text
			DataTypeSize: -1,
			TypeModifier: -1,
		})
	}
	return fields
}

func textValues(row []string) [][]byte {
	out := make([][]byte, 0, len(row))
	for _, v := range row {
		out = append(out, []byte(v))
	}
	return out
}

// textOIDs claims one text parameter per $n placeholder in the
// statement. pgx asks for parameter types before it binds, and a
// mismatch in count is a protocol error rather than a wrong answer.
func textOIDs(sql string) []uint32 {
	n := strings.Count(sql, "$")
	oids := make([]uint32, n)
	for i := range oids {
		oids[i] = 25
	}
	return oids
}

func commandTag(sql string, cols, rows int) []byte {
	if cols > 0 {
		return []byte(fmt.Sprintf("SELECT %d", rows))
	}
	if upper := strings.ToUpper(strings.TrimSpace(sql)); strings.HasPrefix(upper, "SET") ||
		strings.HasPrefix(upper, "DISCARD") {
		return []byte(strings.SplitN(upper, " ", 2)[0])
	}
	return []byte("SELECT 0")
}

// scramVerifierFor builds the same verifier string config files carry, so
// a test can hand pgman credentials that match what the fake backend
// holds — the precondition SCRAM pass-through documents.
func scramVerifierFor(t *testing.T, password string) string {
	t.Helper()
	v, err := GenerateSCRAMVerifier(password, 4096)
	if err != nil {
		t.Fatalf("generate verifier: %v", err)
	}
	return v
}

// fakePGVerifier is the verifier matching the fake server's own salt and
// iteration count, for the pass-through case where pgman's verifier must
// be byte-identical to the backend's.
func fakePGVerifier(t *testing.T, password string) string {
	t.Helper()
	kf := scram.KeyFactors{Salt: "fakepgsalt", Iters: 4096}
	client, err := scram.SHA256.NewClient("", password, "")
	if err != nil {
		t.Fatalf("scram client: %v", err)
	}
	creds, err := client.GetStoredCredentialsWithError(kf)
	if err != nil {
		t.Fatalf("stored credentials: %v", err)
	}
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		kf.Iters,
		base64.StdEncoding.EncodeToString([]byte(kf.Salt)),
		base64.StdEncoding.EncodeToString(creds.StoredKey),
		base64.StdEncoding.EncodeToString(creds.ServerKey))
}
