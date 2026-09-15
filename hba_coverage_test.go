package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// hbaCapture pairs a pgproto3.Backend with the buffer it writes into.
// Every denial in hba.go goes out as a FATAL ErrorResponse before the
// error is returned, and that message is the only thing a real client
// ever sees — the SQLSTATE and text are part of the contract with
// libpq, so the tests need to read them back rather than trust the
// Go-level error alone. Writing into a buffer instead of a socket also
// keeps hbaReject's Flush from blocking on a peer that never reads.
type hbaCapture struct {
	buf bytes.Buffer
	pg  *pgproto3.Backend
}

func newHBACapture() *hbaCapture {
	c := &hbaCapture{}
	c.pg = pgproto3.NewBackend(bytes.NewReader(nil), &c.buf)
	return c
}

// errorResponse decodes the single ErrorResponse the backend was
// expected to emit, failing the test if nothing was sent at all — a
// silent denial leaves the client staring at a closed socket with no
// diagnostic, which is the failure mode worth guarding.
func (c *hbaCapture) errorResponse(t *testing.T) *pgproto3.ErrorResponse {
	t.Helper()
	if c.buf.Len() == 0 {
		t.Fatal("nothing was sent to the client — the denial carried no FATAL ErrorResponse")
	}
	fe := pgproto3.NewFrontend(&c.buf, io.Discard)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("decode what was sent to the client: %v", err)
	}
	resp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("client received %T, want an ErrorResponse", msg)
	}
	return resp
}

// assertHBADenial checks the parts of a denial that clients key off:
// FATAL severity terminates the connection attempt, and SQLSTATE 28000
// is what drivers map to an authorization failure. Getting either
// wrong turns a deliberate deny into a confusing generic error.
func assertHBADenial(t *testing.T, c *hbaCapture, wantSubstring string) {
	t.Helper()
	resp := c.errorResponse(t)
	if resp.Severity != "FATAL" {
		t.Errorf("severity = %q, want FATAL", resp.Severity)
	}
	if resp.Code != "28000" {
		t.Errorf("SQLSTATE = %q, want 28000", resp.Code)
	}
	if !strings.Contains(resp.Message, wantSubstring) {
		t.Errorf("message = %q, want it to mention %q", resp.Message, wantSubstring)
	}
}

// hbaStartup builds the startup message the auth path reads its
// identity from. Only `user` and `database` are consulted, but they
// have to be present: a missing key reads back as the empty string and
// would quietly change which rule matches.
func hbaStartup(user, database string) *pgproto3.StartupMessage {
	return &pgproto3.StartupMessage{
		ProtocolVersion: 196608,
		Parameters:      map[string]string{"user": user, "database": database},
	}
}

// hbaRecordingAuth stands in for the SCRAM backend so the delegation
// path can be observed without running a password exchange. It records
// whether it ran, because the difference between "trust accepted the
// client" and "the inner backend accepted the client" is invisible in
// the return value alone.
type hbaRecordingAuth struct {
	called  int
	startup *pgproto3.StartupMessage
	err     error
}

func (a *hbaRecordingAuth) Authenticate(pg *pgproto3.Backend, conn net.Conn, startup *pgproto3.StartupMessage) error {
	a.called++
	a.startup = startup
	return a.err
}

// hbaWriteFile writes an auth_hba_file and returns its path.
func hbaWriteFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hba.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write hba file: %v", err)
	}
	return path
}

// hbaPipeConn returns a connection that is neither *tls.Conn nor
// *net.UnixConn and has no IP address — the shape every plain-TCP
// assertion here needs, minus a real listener.
func hbaPipeConn(t *testing.T) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	return server
}

// hbaTLSConn hands back the server side of a completed TLS handshake,
// optionally with a client certificate presented. The version is
// pinned to TLS 1.2 on purpose: under TLS 1.3 the client's certificate
// travels in a flight the server only processes once it reads
// application data, so ConnectionState().PeerCertificates would be
// empty right after Handshake and the cert tests would be racy for
// reasons that have nothing to do with hba.go.
func hbaTLSConn(t *testing.T, withClientCert bool) *tls.Conn {
	t.Helper()
	serverCert := generateTestCert(t)
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() {
		_ = serverSide.Close()
		_ = clientSide.Close()
	})

	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	}
	if withClientCert {
		clientCert := generateTestCert(t)
		clientCfg.Certificates = []tls.Certificate{clientCert}
	}
	// RequestClientCert rather than RequireAndVerifyClientCert: the
	// throwaway cert is self-signed and verifying it is the TLS stack's
	// job, not what authenticateCert is being tested for.
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	tlsServer := tls.Server(serverSide, serverCfg)
	tlsClient := tls.Client(clientSide, clientCfg)
	clientDone := make(chan error, 1)
	go func() { clientDone <- tlsClient.Handshake() }()
	if err := tlsServer.Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return tlsServer
}

// TestLoadHBAFileKeepsSourceLineNumbers: LineNum is what every denial
// log and audit record points an operator at. If comments and blank
// lines shifted the numbering, the audit trail would name the wrong
// rule and nobody could tell which line let a connection through.
func TestLoadHBAFileKeepsSourceLineNumbers(t *testing.T) {
	path := hbaWriteFile(t, "# header\n\n   \nhost all all all trust\n# trailing comment\nlocal all all all reject\n")
	rules, err := LoadHBAFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 — comments and blank lines must not become rules", len(rules))
	}
	if rules[0].LineNum != 4 {
		t.Errorf("first rule LineNum = %d, want 4", rules[0].LineNum)
	}
	if rules[1].LineNum != 6 {
		t.Errorf("second rule LineNum = %d, want 6", rules[1].LineNum)
	}
}

// TestLoadHBAFileNamesTheOffendingLine: an HBA file is edited by hand
// and pgman refuses to start when it cannot be parsed. Without the
// line number in the error the operator is left bisecting the file
// during an outage.
func TestLoadHBAFileNamesTheOffendingLine(t *testing.T) {
	path := hbaWriteFile(t, "# comment\nhost all all all trust\nhost all all 10.0.0.0/8 md5\n")
	_, err := LoadHBAFile(path)
	if err == nil {
		t.Fatal("an unsupported METHOD was accepted")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("error = %v, want it to point at line 3", err)
	}
}

// TestLoadHBAFileMissingFileIsAnError: a configured-but-absent
// auth_hba_file must stop startup. Treating it like the empty path
// would silently drop every rule and leave the proxy running with no
// host-based restrictions at all.
func TestLoadHBAFileMissingFileIsAnError(t *testing.T) {
	_, err := LoadHBAFile(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	if err == nil {
		t.Fatal("a missing auth_hba_file was accepted as empty")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error = %v, want it to wrap os.ErrNotExist so callers can distinguish it", err)
	}
}

// TestLoadHBAFileReportsAnUnreadableFile: the line scanner has a
// 64 KiB ceiling per line, so a file that is corrupt or was written
// without newlines stops being readable partway through. Startup has
// to fail on that rather than run with however many rules were parsed
// before the read gave up, which would enforce a truncated policy.
func TestLoadHBAFileReportsAnUnreadableFile(t *testing.T) {
	path := hbaWriteFile(t, "host all all all trust\nhost all "+strings.Repeat("x", 128*1024)+" all trust\n")
	_, err := LoadHBAFile(path)
	if err == nil {
		t.Fatal("a file the scanner could not read through was accepted")
	}
	if !strings.Contains(err.Error(), "scan") {
		t.Errorf("error = %v, want it to report the read failure", err)
	}
}

// TestLoadHBAFileRejectsUnknownConnectionType keeps typos from being
// interpreted. A line the parser cannot classify would either be
// skipped — leaving the intended restriction unenforced — or default to
// some type the operator did not write.
func TestLoadHBAFileRejectsUnknownConnectionType(t *testing.T) {
	path := hbaWriteFile(t, "hostsssl all all all trust\n")
	_, err := LoadHBAFile(path)
	if err == nil {
		t.Fatal("a misspelled connection type was accepted")
	}
	if !strings.Contains(err.Error(), "connection type") {
		t.Errorf("error = %v, want it to name the connection type as the problem", err)
	}
}

// TestParseHBALineAcceptsKeywordsCaseInsensitively mirrors Postgres,
// where `HOST ... TRUST` is the same rule as the lowercase form.
// Rejecting it would make a pg_hba.conf that works on Postgres fail
// here, which is the whole point of claiming compatibility.
func TestParseHBALineAcceptsKeywordsCaseInsensitively(t *testing.T) {
	types := map[string]HBAConnType{
		"HOST":      HBAHostAny,
		"HostSSL":   HBAHostSSL,
		"hostNOSSL": HBAHostNoSSL,
		"LOCAL":     HBALocal,
	}
	for field, want := range types {
		rule, err := parseHBALine(field + " all all all trust")
		if err != nil {
			t.Fatalf("TYPE %q: %v", field, err)
		}
		if rule.Type != want {
			t.Errorf("TYPE %q parsed as %v, want %v", field, rule.Type, want)
		}
	}

	methods := map[string]HBAMethod{
		"TRUST":         HBAMethodTrust,
		"Reject":        HBAMethodReject,
		"SCRAM-SHA-256": HBAMethodSCRAM,
		"Peer":          HBAMethodPeer,
		"CERT":          HBAMethodCert,
	}
	for field, want := range methods {
		rule, err := parseHBALine("host all all all " + field)
		if err != nil {
			t.Fatalf("METHOD %q: %v", field, err)
		}
		if rule.Method != want {
			t.Errorf("METHOD %q parsed as %q, want %q", field, rule.Method, want)
		}
	}
}

// TestParseHBALineAddressForms pins which ADDRESS spellings are
// understood. The address is the only thing standing between a rule
// meant for one subnet and the whole internet, so a form that parses
// into something wider than written would be a silent hole — and a
// form that fails to parse has to fail loudly rather than degrade into
// the nil "matches everything" Net.
func TestParseHBALineAddressForms(t *testing.T) {
	accepted := []struct {
		address  string
		wantNet  string
		samehost bool
	}{
		{address: "all"},
		{address: "samehost", samehost: true},
		{address: "10.0.0.0/8", wantNet: "10.0.0.0/8"},
		{address: "192.168.5.7/32", wantNet: "192.168.5.7/32"},
		// A host-bit-carrying CIDR is masked down, so 10.1.2.3/8
		// becomes the whole 10.0.0.0/8 — worth pinning, because it
		// means a rule can cover far more than its text suggests.
		{address: "10.1.2.3/8", wantNet: "10.0.0.0/8"},
		{address: "2001:db8::/32", wantNet: "2001:db8::/32"},
		{address: "::1/128", wantNet: "::1/128"},
		{address: "SAMEHOST", samehost: true},
	}
	for _, tc := range accepted {
		rule, err := parseHBALine("host all all " + tc.address + " trust")
		if err != nil {
			t.Fatalf("ADDRESS %q: %v", tc.address, err)
		}
		if rule.Samehost != tc.samehost {
			t.Errorf("ADDRESS %q: Samehost = %v, want %v", tc.address, rule.Samehost, tc.samehost)
		}
		if tc.wantNet == "" {
			if rule.Net != nil {
				t.Errorf("ADDRESS %q: Net = %v, want nil", tc.address, rule.Net)
			}
			continue
		}
		if rule.Net == nil {
			t.Fatalf("ADDRESS %q: Net is nil, which matches every address", tc.address)
		}
		if rule.Net.String() != tc.wantNet {
			t.Errorf("ADDRESS %q: Net = %v, want %v", tc.address, rule.Net, tc.wantNet)
		}
	}

	// Everything else is refused, including the two forms Postgres does
	// accept: a bare IP (implicitly /32) and a hostname. Refusing them
	// is a documented limitation of this subset, and it is safe — an
	// address that cannot be parsed must never widen into "all".
	rejected := []string{"10.0.0.0/33", "10.0.0.1", "localhost", "example.com", ".example.com", "10.0.0.0/8/8", "0.0.0.0/-1"}
	for _, address := range rejected {
		rule, err := parseHBALine("host all all " + address + " trust")
		if err == nil {
			t.Errorf("ADDRESS %q was accepted as %+v", address, rule)
			continue
		}
		if !strings.Contains(err.Error(), "ADDRESS") {
			t.Errorf("ADDRESS %q: error = %v, want it to name ADDRESS as the problem", address, err)
		}
	}
}

// TestParseHBALineUnquotesValuesAndSuppressesKeywords: Postgres's own
// pg_hba.conf parser strips double quotes and treats a quoted value as
// a literal identifier, so `"all"` is a database called all rather than
// the wildcard. pgman used to keep the quotes as part of the value,
// which made an operator's copied line match nothing at all — a rule
// that looks like it grants access and silently does not.
func TestParseHBALineUnquotesValuesAndSuppressesKeywords(t *testing.T) {
	rule, err := parseHBALine(`host "all" "alice" all trust`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rule.AllDatabases {
		t.Error(`a quoted "all" was taken as the wildcard; quoting is how you name a database called all`)
	}
	if got := rule.Databases; len(got) != 1 || got[0] != "all" {
		t.Errorf("DATABASE parsed as %q, want the unquoted name all", got)
	}
	if got := rule.Users; len(got) != 1 || got[0] != "alice" {
		t.Errorf("USER parsed as %q, want alice", got)
	}

	// It matches the database of that name, and nothing else.
	if _, ok := MatchHBA([]HBARule{rule}, false, false, net.ParseIP("10.0.0.1"), "alice", "all"); !ok {
		t.Error(`the rule did not match the database literally named all`)
	}
	if _, ok := MatchHBA([]HBARule{rule}, false, false, net.ParseIP("10.0.0.1"), "alice", "shop"); ok {
		t.Error("a quoted name behaved as the wildcard")
	}

	// A quoted ADDRESS is a literal too, and no literal parses as a
	// CIDR — so the file fails to load rather than running with a rule
	// that can never match.
	if _, err := parseHBALine(`host all all "all" trust`); err == nil {
		t.Error("a quoted ADDRESS was accepted")
	}
}

// TestParseHBALineAcceptsWhitespaceInCommaLists: operators write
// `db1, db2` with a space after the comma. That used to split into two
// fields before the list was parsed, which shifted every later field
// left — the line was then read with a database name where its ADDRESS
// should be, so the rule either failed to load or applied to something
// nobody had written.
func TestParseHBALineAcceptsWhitespaceInCommaLists(t *testing.T) {
	for _, line := range []string{
		"host app,reports alice,bob all trust",
		"host app, reports alice, bob all trust",
		"host app ,reports alice ,bob all trust",
		"host app,,reports alice,bob all trust",
	} {
		rule, err := parseHBALine(line)
		if err != nil {
			t.Errorf("%q: %v", line, err)
			continue
		}
		if got := strings.Join(rule.Databases, "|"); got != "app|reports" {
			t.Errorf("%q: DATABASE list = %q, want app|reports", line, got)
		}
		if got := strings.Join(rule.Users, "|"); got != "alice|bob" {
			t.Errorf("%q: USER list = %q, want alice|bob", line, got)
		}
		// The fields after the lists must still be the fields that were
		// written, which is what the shift used to destroy.
		if rule.Net != nil || rule.Samehost {
			t.Errorf("%q: ADDRESS was read as %v/samehost=%v, want the all keyword",
				line, rule.Net, rule.Samehost)
		}
		if rule.Method != HBAMethodTrust {
			t.Errorf("%q: METHOD = %q, want trust", line, rule.Method)
		}
	}
}

// TestParseHBALineRejectsExtraFields: Postgres puts per-method options
// in the sixth field and pgman supports none of them, so accepting one
// silently would let an operator write `clientcert=verify-full` and
// believe a restriction applies that the proxy never reads.
func TestParseHBALineRejectsExtraFields(t *testing.T) {
	if _, err := parseHBALine("host all all all cert clientcert=verify-full"); err == nil {
		t.Error("a per-method option was accepted and ignored")
	}
}

// TestParseHBALineRejectsAnEmptyNameList: a list that reduces to
// nothing used to be accepted and then matched nothing, which is the
// worst of both — the rule sits in the file looking like it grants
// something, and no error ever says otherwise.
func TestParseHBALineRejectsAnEmptyNameList(t *testing.T) {
	for _, line := range []string{
		"host , all all trust",
		"host ,, all all trust",
		"host all , all trust",
	} {
		if _, err := parseHBALine(line); err == nil {
			t.Errorf("%q was accepted, but it can never match anything", line)
		}
	}
}

// TestTokenizeHBALineReportsAnUnterminatedQuote: an unclosed quote
// swallows the rest of the line, so the fields that follow it silently
// become part of one value. Failing the load is the only safe answer.
func TestTokenizeHBALineReportsAnUnterminatedQuote(t *testing.T) {
	if _, err := parseHBALine(`host "all all all trust`); err == nil {
		t.Error("a line with an unterminated quote was accepted")
	}
}

// TestMatchHBALocalRulesOnlyCoverUnixSockets is the separation the
// whole TYPE column exists for. A `local` rule that also matched TCP
// would extend socket-level trust to the network; a `host` rule that
// matched the Unix socket would apply IP-based restrictions to a
// connection that has no IP and would deny local admin access.
func TestMatchHBALocalRulesOnlyCoverUnixSockets(t *testing.T) {
	local := []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	host := []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}

	if _, ok := MatchHBA(local, false, true, nil, "u", "d"); !ok {
		t.Error("a local rule did not match a Unix-socket connection")
	}
	if _, ok := MatchHBA(local, false, false, net.ParseIP("127.0.0.1"), "u", "d"); ok {
		t.Error("a local rule matched a TCP connection, extending socket trust to the network")
	}
	for _, isTLS := range []bool{false, true} {
		if _, ok := MatchHBA(host, isTLS, true, nil, "u", "d"); ok {
			t.Errorf("a host rule matched a Unix-socket connection (tls=%v)", isTLS)
		}
	}
	for _, typ := range []HBAConnType{HBAHostSSL, HBAHostNoSSL} {
		rules := []HBARule{{Type: typ, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
		for _, isTLS := range []bool{false, true} {
			if _, ok := MatchHBA(rules, isTLS, true, nil, "u", "d"); ok {
				t.Errorf("a %v rule matched a Unix-socket connection (tls=%v)", typ, isTLS)
			}
		}
	}
}

// TestMatchHBAHostNoSSLExcludesEncryptedConnections: hostnossl is how
// an operator carves out an exception for a client that cannot do TLS.
// If it also matched TLS connections that weaker exception would apply
// to everyone, and `host` would be the only type anyone could trust.
func TestMatchHBAHostNoSSLExcludesEncryptedConnections(t *testing.T) {
	rules := []HBARule{{Type: HBAHostNoSSL, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("10.0.0.1"), "u", "d"); !ok {
		t.Error("hostnossl did not match a plain TCP connection")
	}
	if _, ok := MatchHBA(rules, true, false, net.ParseIP("10.0.0.1"), "u", "d"); ok {
		t.Error("hostnossl matched a TLS connection")
	}

	// host, by contrast, deliberately spans both.
	hostAny := []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	for _, isTLS := range []bool{false, true} {
		if _, ok := MatchHBA(hostAny, isTLS, false, net.ParseIP("10.0.0.1"), "u", "d"); !ok {
			t.Errorf("host did not match a TCP connection with tls=%v", isTLS)
		}
	}
}

// TestMatchHBAUnrecognisedTypeNeverMatches guards the fail-closed
// default. A rule carrying a type the matcher does not know about must
// be inert rather than universally applicable, so that adding a new
// HBAConnType cannot accidentally open every existing deployment.
func TestMatchHBAUnrecognisedTypeNeverMatches(t *testing.T) {
	rules := []HBARule{{Type: HBAConnType(99), AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	for _, isUnix := range []bool{false, true} {
		for _, isTLS := range []bool{false, true} {
			if _, ok := MatchHBA(rules, isTLS, isUnix, net.ParseIP("127.0.0.1"), "u", "d"); ok {
				t.Errorf("an unknown connection type matched (tls=%v unix=%v)", isTLS, isUnix)
			}
		}
	}
}

// TestMatchHBANameComparisonIsCaseInsensitive: Postgres folds unquoted
// identifiers to lower case, so a client connecting as `Alice` arrives
// as `alice`. Matching names exactly would make rules depend on how
// the client happened to spell the identifier.
func TestMatchHBANameComparisonIsCaseInsensitive(t *testing.T) {
	rules := []HBARule{{Type: HBAHostAny, Databases: []string{"App"}, Users: []string{"Alice"}, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("10.0.0.1"), "alice", "app"); !ok {
		t.Error("a rule written in mixed case did not match the lower-case request")
	}

	// The `all` keyword folds too. It used to be compared byte-for-byte
	// while TYPE, METHOD and names were folded, so `host ALL ALL all
	// trust` covered only a database and role literally called all —
	// the opposite of what the line says, and silently so.
	upper, err := parseHBALine("HOST ALL ALL all TRUST")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !upper.AllDatabases || !upper.AllUsers {
		t.Fatalf("ALL was read as a name: AllDatabases=%v AllUsers=%v", upper.AllDatabases, upper.AllUsers)
	}
	if _, ok := MatchHBA([]HBARule{upper}, false, false, net.ParseIP("10.0.0.1"), "alice", "shop"); !ok {
		t.Error("an upper-case ALL did not behave as the wildcard")
	}
}

// TestMatchHBAAddresslessConnectionsOnlyMatchAddressAllRules: Unix
// sockets and pipe-backed connections have no IP, and so does anything
// whose RemoteAddr is not a *net.TCPAddr. Such a connection must fail
// every address-constrained rule instead of being treated as inside
// the subnet — otherwise a rule scoped to 10.0.0.0/8 would cover a
// caller whose address could not be determined.
func TestMatchHBAAddresslessConnectionsOnlyMatchAddressAllRules(t *testing.T) {
	_, net10, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	cidr := []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Net: net10, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(cidr, false, true, nil, "u", "d"); ok {
		t.Error("a CIDR-scoped rule matched a connection with no address")
	}

	samehost := []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Samehost: true, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(samehost, false, true, nil, "u", "d"); ok {
		t.Error("a samehost rule matched a connection with no address")
	}

	all := []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(all, false, true, nil, "u", "d"); !ok {
		t.Error("an ADDRESS=all rule did not match a connection with no address, which locks out Unix sockets")
	}
}

// TestMatchHBAIPv6CIDRs: a v6-scoped rule has to actually constrain v6
// clients. net.IP holds both families in one type, so a matcher that
// ignored the family could let a v4 address fall inside a v6 prefix or
// the reverse.
func TestMatchHBAIPv6CIDRs(t *testing.T) {
	_, v6, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	rules := []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Net: v6, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("2001:db8::5"), "u", "d"); !ok {
		t.Error("a v6 prefix did not match an address inside it")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("2001:dead::5"), "u", "d"); ok {
		t.Error("a v6 prefix matched an address outside it")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("10.0.0.1"), "u", "d"); ok {
		t.Error("a v6 prefix matched a v4 address")
	}

	// IPv6 loopback counts as samehost, which is what a client
	// connecting to ::1 on a dual-stack host actually presents.
	loopback := []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Samehost: true, Method: HBAMethodTrust}}
	if _, ok := MatchHBA(loopback, false, false, net.ParseIP("::1"), "u", "d"); !ok {
		t.Error("samehost did not match the IPv6 loopback address")
	}
}

// TestMatchHBAEmptyRuleSetMatchesNothing: an HBA file that parsed to
// zero rules must not be mistaken for "anything goes". NewHBAAuth
// treats that case by skipping HBA entirely, so the matcher's own
// answer needs to stay a clean no-match.
func TestMatchHBAEmptyRuleSetMatchesNothing(t *testing.T) {
	rule, ok := MatchHBA(nil, false, false, net.ParseIP("127.0.0.1"), "u", "d")
	if ok || rule != nil {
		t.Errorf("empty rule set returned (%v, %v), want (nil, false)", rule, ok)
	}
}

// TestNewHBAAuthWithoutRulesReturnsInnerUnchanged: an empty or absent
// rule file must leave the configured auth backend in place. Wrapping
// it in an HBAAuth with no rules would reject every connection, taking
// the whole proxy down over an empty file.
func TestNewHBAAuthWithoutRulesReturnsInnerUnchanged(t *testing.T) {
	inner := &hbaRecordingAuth{}
	if got := NewHBAAuth(nil, inner); got != AuthBackend(inner) {
		t.Errorf("NewHBAAuth(nil, inner) = %T, want the inner backend itself", got)
	}
	rules := []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust}}
	if _, ok := NewHBAAuth(rules, inner).(*HBAAuth); !ok {
		t.Error("NewHBAAuth with rules did not wrap the inner backend")
	}
}

// TestHBAAuthTrustBypassesInnerBackend: trust is defined as "no
// password exchange". If the inner SCRAM backend still ran, a client
// covered by a trust rule would be asked for credentials it was
// explicitly excused from providing, and libpq would fail the
// connection.
func TestHBAAuthTrustBypassesInnerBackend(t *testing.T) {
	inner := &hbaRecordingAuth{err: errors.New("inner must not run for a trust rule")}
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust, LineNum: 1}},
		Inner: inner,
	}
	c := newHBACapture()
	if err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("alice", "app")); err != nil {
		t.Fatalf("trust rule returned %v, want acceptance", err)
	}
	if inner.called != 0 {
		t.Errorf("inner backend ran %d times for a trust rule", inner.called)
	}
	if c.buf.Len() != 0 {
		t.Errorf("trust wrote %d bytes to the client; the startup loop owns the AuthenticationOk", c.buf.Len())
	}
}

// TestHBAAuthRejectTellsTheClientWhy: a reject rule is a deliberate
// deny and the client has to learn that from a FATAL 28000, not from a
// dropped socket. The message names the host, user and database so the
// person debugging it can find the rule.
func TestHBAAuthRejectTellsTheClientWhy(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, Users: []string{"eve"}, Method: HBAMethodReject, LineNum: 7}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("eve", "app"))
	if err == nil {
		t.Fatal("a reject rule accepted the connection")
	}
	if !strings.Contains(err.Error(), "line 7") {
		t.Errorf("error = %v, want it to name the rule's line", err)
	}
	assertHBADenial(t, c, "rejects connection")
}

// TestHBAAuthUnmatchedConnectionIsDenied is the fail-closed guarantee.
// PgBouncer and Postgres both refuse a client no rule covers; falling
// through to the inner backend instead would make every HBA file an
// allowlist of exceptions on top of an open default.
func TestHBAAuthUnmatchedConnectionIsDenied(t *testing.T) {
	inner := &hbaRecordingAuth{}
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, Databases: []string{"app"}, AllUsers: true, Method: HBAMethodTrust, LineNum: 1}},
		Inner: inner,
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("alice", "other"))
	if err == nil {
		t.Fatal("a connection matching no rule was accepted")
	}
	if inner.called != 0 {
		t.Errorf("inner backend ran %d times for an unmatched connection", inner.called)
	}
	assertHBADenial(t, c, "no pg_hba.conf entry")
}

// TestHBAAuthSCRAMDelegatesToInner: the scram-sha-256 method owns none
// of the exchange itself. It has to hand the same startup message to
// the inner backend and propagate its verdict unchanged, because the
// outer startup loop is what turns a failure into the 28P01 response
// clients expect from a wrong password.
func TestHBAAuthSCRAMDelegatesToInner(t *testing.T) {
	inner := &hbaRecordingAuth{}
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodSCRAM, LineNum: 2}},
		Inner: inner,
	}
	startup := hbaStartup("alice", "app")
	c := newHBACapture()
	if err := h.Authenticate(c.pg, hbaPipeConn(t), startup); err != nil {
		t.Fatalf("delegation returned %v, want the inner backend's nil", err)
	}
	if inner.called != 1 {
		t.Fatalf("inner backend ran %d times, want 1", inner.called)
	}
	if inner.startup != startup {
		t.Error("the inner backend received a different startup message than the client sent")
	}

	// A failing exchange must surface as-is: swallowing it here would
	// accept a client that never proved its password.
	wantErr := errors.New("password authentication failed")
	inner.err = wantErr
	if err := h.Authenticate(newHBACapture().pg, hbaPipeConn(t), startup); !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want the inner backend's error", err)
	}
}

// TestHBAAuthUnhandledMethodFailsClosed: HBAMethod is a string, so a
// rule can carry a value the switch does not cover — a future method
// wired into the parser but not the auth path, say. That must deny,
// never accept, and it must say so: this was the one denial path that
// closed the socket in silence, which a driver reports as a connection
// reset and a retry loop treats as a transient network fault.
func TestHBAAuthUnhandledMethodFailsClosed(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethod("md5"), LineNum: 3}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("alice", "app"))
	if err == nil {
		t.Fatal("a rule with an unhandled method accepted the connection")
	}
	if !strings.Contains(err.Error(), "unhandled method") {
		t.Errorf("error = %v, want it to name the unhandled method", err)
	}
	// The line number turns "something is wrong with auth" into a file
	// and a line an operator can open, and the method name says what
	// about it to change.
	assertHBADenial(t, c, `line 3 uses method "md5"`)
}

// TestHBAAuthCertRequiresTLS: METHOD=cert derives identity purely from
// the client certificate, so on a connection with no TLS there is
// nothing to derive it from. Accepting such a connection would hand
// out the certificate's identity to anyone who could reach the port.
func TestHBAAuthCertRequiresTLS(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodCert, LineNum: 4}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("alice", "app"))
	if err == nil {
		t.Fatal("a cert rule accepted a plain connection")
	}
	assertHBADenial(t, c, "requires a TLS connection")

	// The second guard inside authenticateCert is unreachable through
	// Authenticate, which derives isTLS from the very same type
	// assertion. Exercised directly so the defensive branch is known to
	// deny rather than panic if the two ever drift apart.
	c2 := newHBACapture()
	if err := h.authenticateCert(c2.pg, hbaPipeConn(t), "alice", true, 4); err == nil {
		t.Fatal("authenticateCert accepted a conn that is not a *tls.Conn")
	}
	assertHBADenial(t, c2, "not a TLS connection")
}

// TestHBAAuthCertRequiresAClientCertificate: TLS alone only proves the
// server's identity. Without a client certificate there is no subject
// to compare against the requested user, and treating that as a pass
// would make METHOD=cert equivalent to trust for any TLS client.
func TestHBAAuthCertRequiresAClientCertificate(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostSSL, AllDatabases: true, AllUsers: true, Method: HBAMethodCert, LineNum: 5}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaTLSConn(t, false), hbaStartup("alice", "app"))
	if err == nil {
		t.Fatal("a cert rule accepted a TLS connection with no client certificate")
	}
	assertHBADenial(t, c, "requires a client certificate")
}

// TestHBAAuthCertMatchesCommonNameAgainstRequestedUser is the identity
// check itself. If any valid certificate authorised any username, one
// issued cert would be enough to connect as every role in the cluster,
// superuser included.
func TestHBAAuthCertMatchesCommonNameAgainstRequestedUser(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostSSL, AllDatabases: true, AllUsers: true, Method: HBAMethodCert, LineNum: 6}},
		Inner: &hbaRecordingAuth{},
	}

	// generateTestCert issues its certificate with CN=localhost, so
	// that is the one username this client may claim.
	accepted := newHBACapture()
	if err := h.Authenticate(accepted.pg, hbaTLSConn(t, true), hbaStartup("localhost", "app")); err != nil {
		t.Fatalf("a certificate whose CN equals the requested user was rejected: %v", err)
	}
	if accepted.buf.Len() != 0 {
		t.Errorf("an accepted cert auth wrote %d bytes to the client", accepted.buf.Len())
	}

	denied := newHBACapture()
	err := h.Authenticate(denied.pg, hbaTLSConn(t, true), hbaStartup("postgres", "app"))
	if err == nil {
		t.Fatal("a certificate with CN=localhost authenticated the user postgres")
	}
	assertHBADenial(t, denied, "does not match requested user")
}

// TestHBAAuthPeerRequiresAUnixSocket: SO_PEERCRED only exists for
// Unix-domain sockets. A peer rule that matched TCP would have no
// credentials to read and must deny rather than fall through to
// something weaker.
func TestHBAAuthPeerRequiresAUnixSocket(t *testing.T) {
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodPeer, LineNum: 8}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaPipeConn(t), hbaStartup("alice", "app"))
	if err == nil {
		t.Fatal("a peer rule accepted a non-Unix connection")
	}
	assertHBADenial(t, c, "requires a Unix-domain socket")
}

// hbaUnixConn returns the server side of a connected Unix-domain
// socket, which is the only connection shape a peer rule will look at.
func hbaUnixConn(t *testing.T) *net.UnixConn {
	t.Helper()
	path := filepath.Join(shortTempDir(t), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- result{conn, err}
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	got := <-accepted
	if got.err != nil {
		t.Fatalf("accept unix: %v", got.err)
	}
	t.Cleanup(func() { _ = got.conn.Close() })
	uc, ok := got.conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("accepted %T, want *net.UnixConn", got.conn)
	}
	return uc
}

// TestHBAAuthPeerOnAnUnsupportedPlatform: only Linux implements
// SO_PEERCRED here, and a peer rule on any other platform has no way
// to learn the caller's identity. It must say so and deny — silently
// degrading to trust would turn the socket into an unauthenticated
// entry point.
func TestHBAAuthPeerOnAnUnsupportedPlatform(t *testing.T) {
	if peerCredSupported {
		t.Skip("this platform implements SO_PEERCRED; the supported path is covered separately")
	}
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Method: HBAMethodPeer, LineNum: 9}},
		Inner: &hbaRecordingAuth{},
	}
	c := newHBACapture()
	err := h.Authenticate(c.pg, hbaUnixConn(t), hbaStartup("alice", "app"))
	if err == nil {
		t.Fatal("a peer rule was honoured on a platform without SO_PEERCRED")
	}
	assertHBADenial(t, c, "not supported on this platform")
}

// TestHBAAuthPeerComparesOSIdentityToRequestedUser covers the whole
// point of METHOD=peer: the kernel-reported owner of the connecting
// process is the identity, and claiming any other username must fail.
// Without the comparison, one local shell account could connect as
// every role in the cluster over the socket.
func TestHBAAuthPeerComparesOSIdentityToRequestedUser(t *testing.T) {
	if !peerCredSupported {
		t.Skip("SO_PEERCRED is unavailable on this platform")
	}
	h := &HBAAuth{
		Rules: []HBARule{{Type: HBALocal, AllDatabases: true, AllUsers: true, Method: HBAMethodPeer, LineNum: 10}},
		Inner: &hbaRecordingAuth{},
	}

	// The UID lookup is stubbed rather than read from the test runner's
	// environment: container images routinely run as a UID with no
	// /etc/passwd entry, and the behaviour under test is the comparison,
	// not os/user.
	original := lookupUsernameByUID
	t.Cleanup(func() { lookupUsernameByUID = original })

	lookupUsernameByUID = func(uint32) (string, error) { return "alice", nil }
	accepted := newHBACapture()
	if err := h.Authenticate(accepted.pg, hbaUnixConn(t), hbaStartup("alice", "app")); err != nil {
		t.Fatalf("peer auth rejected a client whose OS user matches: %v", err)
	}
	if accepted.buf.Len() != 0 {
		t.Errorf("an accepted peer auth wrote %d bytes to the client", accepted.buf.Len())
	}

	denied := newHBACapture()
	if err := h.Authenticate(denied.pg, hbaUnixConn(t), hbaStartup("postgres", "app")); err == nil {
		t.Fatal("peer auth let the OS user alice connect as postgres")
	}
	assertHBADenial(t, denied, "peer authentication failed")

	// An unresolvable UID is a deny too. Mapping it to anything else —
	// the requested user, or an empty name — would authenticate a
	// process whose owner is unknown.
	lookupUsernameByUID = func(uid uint32) (string, error) { return "", fmt.Errorf("no such user %d", uid) }
	unresolved := newHBACapture()
	if err := h.Authenticate(unresolved.pg, hbaUnixConn(t), hbaStartup("alice", "app")); err == nil {
		t.Fatal("peer auth accepted a client whose UID could not be resolved")
	}
	assertHBADenial(t, unresolved, "cannot resolve OS user")
}

// TestHBAAuthPeerReportsUnreadableCredentials: getPeerCred can fail on
// a socket that is already gone, and the connection then has no
// identity. Reached directly because Authenticate's isUnix check
// screens out everything that would make the syscall fail.
func TestHBAAuthPeerReportsUnreadableCredentials(t *testing.T) {
	if !peerCredSupported {
		t.Skip("SO_PEERCRED is unavailable on this platform")
	}
	h := &HBAAuth{Inner: &hbaRecordingAuth{}}
	c := newHBACapture()
	if err := h.authenticatePeer(c.pg, hbaPipeConn(t), "alice", true, 11); err == nil {
		t.Fatal("unreadable peer credentials were accepted")
	}
	assertHBADenial(t, c, "cannot read peer credentials")
}

// TestRemoteAddrIPOnlyTrustsTCPAddresses: the extracted IP decides
// which address-scoped rules apply, and it is also interpolated into
// the denial message. Anything other than a real TCP address has to
// come back nil so address-constrained rules fail closed instead of
// matching on a fabricated address.
func TestRemoteAddrIPOnlyTrustsTCPAddresses(t *testing.T) {
	if got := remoteAddrIP(nil); got != nil {
		t.Errorf("remoteAddrIP(nil) = %v, want nil", got)
	}
	if got := remoteAddrIP(hbaPipeConn(t)); got != nil {
		t.Errorf("a pipe connection reported the address %v, want nil", got)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	got := remoteAddrIP(server)
	if got == nil || !got.IsLoopback() {
		t.Errorf("remoteAddrIP over TCP = %v, want the loopback peer address", got)
	}
}

// TestHBAAuthEndToEndFromFile drives the loaded-from-disk rule set the
// way production does, so the parser and the matcher are checked
// against each other. Ordering is the part that only shows up here: a
// specific deny written above a broad trust has to win, and the same
// client has to be accepted for a database the deny does not name.
func TestHBAAuthEndToEndFromFile(t *testing.T) {
	path := hbaWriteFile(t, `# TYPE  DATABASE  USER   ADDRESS  METHOD
host    secret    all    all      reject
host    all       all    all      trust
`)
	rules, err := LoadHBAFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	h, ok := NewHBAAuth(rules, &hbaRecordingAuth{}).(*HBAAuth)
	if !ok {
		t.Fatalf("NewHBAAuth returned %T, want *HBAAuth", h)
	}

	denied := newHBACapture()
	if err := h.Authenticate(denied.pg, hbaPipeConn(t), hbaStartup("alice", "secret")); err == nil {
		t.Error("the broad trust rule overrode the specific reject above it")
	}
	assertHBADenial(t, denied, "rejects connection")

	accepted := newHBACapture()
	if err := h.Authenticate(accepted.pg, hbaPipeConn(t), hbaStartup("alice", "app")); err != nil {
		t.Errorf("the trust rule did not apply to a database the reject does not name: %v", err)
	}
}

// TestParseHBALineRejectsListsInSingleValueFields: a comma in TYPE,
// ADDRESS or METHOD is a typo, and reading only the first element would
// quietly apply a rule narrower — or wider — than the one written.
func TestParseHBALineRejectsListsInSingleValueFields(t *testing.T) {
	cases := map[string]string{
		"host,hostssl all all all trust":    "TYPE",
		"host all all 10.0.0.0/8,all trust": "ADDRESS",
		"host all all all trust,reject":     "METHOD",
	}
	for line, field := range cases {
		_, err := parseHBALine(line)
		if err == nil {
			t.Errorf("%q was accepted, but %s cannot be a list", line, field)
			continue
		}
		if !strings.Contains(err.Error(), field) {
			t.Errorf("%q: error = %q, want it to name the %s field", line, err, field)
		}
	}
}

// TestParseHBALineRejectsAQuotedEmptyName: `""` is a name of zero
// length, which no role or database can have. Accepting it would put an
// entry in the list that can never match and can never be spotted in
// the file.
func TestParseHBALineRejectsAQuotedEmptyName(t *testing.T) {
	for _, line := range []string{
		`host "" all all trust`,
		`host all "" all trust`,
		`host app,"" all all trust`,
	} {
		if _, err := parseHBALine(line); err == nil {
			t.Errorf("%q was accepted with an empty name in it", line)
		}
	}
}

// TestParseHBALineKeepsQuotedWhitespaceInNames: quoting exists so a
// name can contain a space. Postgres allows such identifiers, and a
// parser that split them would make the rule unwritable rather than
// merely unusual.
func TestParseHBALineKeepsQuotedWhitespaceInNames(t *testing.T) {
	rule, err := parseHBALine(`host "my db","other db" "alice smith" all trust`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := strings.Join(rule.Databases, "|"); got != "my db|other db" {
		t.Errorf("DATABASE list = %q, want \"my db|other db\"", got)
	}
	if got := strings.Join(rule.Users, "|"); got != "alice smith" {
		t.Errorf("USER list = %q, want \"alice smith\"", got)
	}
	if _, ok := MatchHBA([]HBARule{rule}, false, false, net.ParseIP("10.0.0.1"), "alice smith", "other db"); !ok {
		t.Error("a quoted name containing a space did not match a client using it")
	}
}
