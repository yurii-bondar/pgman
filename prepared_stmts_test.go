package main

import (
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// psFixture gives each test a session, a backend, and a Frontend whose
// writes are captured instead of sent to a real Postgres. Everything
// ensureBackendHasStmt prepends lands in sent().
type psFixture struct {
	t       *testing.T
	fe      *pgproto3.Frontend
	backend *backendConn
	sess    *session
	msgs    chan pgproto3.FrontendMessage
}

func newPSFixture(t *testing.T) *psFixture {
	t.Helper()
	proxySide, serverSide := net.Pipe()
	t.Cleanup(func() { proxySide.Close(); serverSide.Close() })

	f := &psFixture{
		t:       t,
		fe:      pgproto3.NewFrontend(proxySide, proxySide),
		backend: &backendConn{Conn: proxySide, addr: "fake", pid: 1, secretKey: secretBytes(2)},
		sess:    &session{user: "u", database: "d", poolMode: "transaction"},
		msgs:    make(chan pgproto3.FrontendMessage, 16),
	}
	// Fake Postgres: decode whatever the proxy forwards.
	go func() {
		be := pgproto3.NewBackend(serverSide, serverSide)
		for {
			msg, err := be.Receive()
			if err != nil {
				return
			}
			if p, ok := msg.(*pgproto3.Parse); ok {
				cp := *p
				f.msgs <- &cp
				continue
			}
			f.msgs <- msg
		}
	}()
	return f
}

// flushAndCollect sends whatever is buffered and returns the Parse
// messages the backend saw, in order.
func (f *psFixture) flushAndCollect(want int) []*pgproto3.Parse {
	f.t.Helper()
	if err := f.fe.Flush(); err != nil {
		f.t.Fatalf("flush: %v", err)
	}
	var out []*pgproto3.Parse
	for i := 0; i < want; i++ {
		msg := <-f.msgs
		p, ok := msg.(*pgproto3.Parse)
		if !ok {
			f.t.Fatalf("message %d is %T, want Parse", i, msg)
		}
		out = append(out, p)
	}
	return out
}

// TestParseRecordsStatementForReplay: the session cache is what makes
// transaction pooling survive prepared statements at all, so a named
// Parse has to be remembered even though it is forwarded unchanged.
func TestParseRecordsStatementForReplay(t *testing.T) {
	f := newPSFixture(t)

	parse := &pgproto3.Parse{Name: "s1", Query: "SELECT $1::int", ParameterOIDs: []uint32{23}}
	out, swallow := processClientMsg(f.fe, f.backend, f.sess, parse)

	if out != pgproto3.FrontendMessage(parse) {
		t.Error("Parse must be forwarded unchanged")
	}
	if swallow != 0 {
		t.Errorf("swallow = %d, want 0: the client sent this Parse itself", swallow)
	}
	info, ok := f.sess.psCache["s1"]
	if !ok {
		t.Fatal("named Parse was not recorded in the session cache")
	}
	if info.SQL != "SELECT $1::int" {
		t.Errorf("cached SQL = %q", info.SQL)
	}
	// The OIDs must be copied: pgproto3 reuses the message struct, so
	// keeping the caller's slice would alias memory the next Receive
	// overwrites.
	parse.ParameterOIDs[0] = 999
	if info.ParameterOIDs[0] != 23 {
		t.Error("ParameterOIDs were aliased instead of copied")
	}
	if _, has := f.backend.preparedStmts["s1"]; !has {
		t.Error("the backend receiving this Parse was not marked as knowing it")
	}
}

func TestUnnamedParseIsNotCached(t *testing.T) {
	f := newPSFixture(t)

	processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Parse{Name: "", Query: "SELECT 1"})

	if len(f.sess.psCache) != 0 {
		t.Error("the unnamed statement is single-use and must not be cached")
	}
}

// TestBindOnColdBackendPrependsParse is the whole trick: in transaction
// pooling the next statement can land on a backend that never saw the
// client's Parse, and Postgres would answer "prepared statement does
// not exist".
func TestBindOnColdBackendPrependsParse(t *testing.T) {
	f := newPSFixture(t)

	// Client prepared s1 on some earlier backend.
	f.sess.psCache = psCache{"s1": {SQL: "SELECT $1::int", ParameterOIDs: []uint32{23}}}

	bind := &pgproto3.Bind{PreparedStatement: "s1"}
	out, swallow := processClientMsg(f.fe, f.backend, f.sess, bind)
	f.fe.Send(out)

	if swallow != 1 {
		t.Fatalf("swallow = %d, want 1: the synthetic Parse produces a ParseComplete "+
			"the client never asked for and must not see", swallow)
	}

	parses := f.flushAndCollect(1)
	if parses[0].Name != "s1" || parses[0].Query != "SELECT $1::int" {
		t.Errorf("prepended Parse = %+v, want s1/SELECT $1::int", parses[0])
	}
	if _, has := f.backend.preparedStmts["s1"]; !has {
		t.Error("the backend was not marked as knowing s1 after the replay")
	}
}

// TestBindOnWarmBackendDoesNotPrepend: replaying on every Bind would
// add a Parse to every single statement in the steady state, which is
// the cost this cache exists to avoid.
func TestBindOnWarmBackendDoesNotPrepend(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psCache = psCache{"s1": {SQL: "SELECT 1"}}
	f.backend.preparedStmts = backendPSCache{"s1": struct{}{}}

	_, swallow := processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Bind{PreparedStatement: "s1"})
	if swallow != 0 {
		t.Errorf("swallow = %d, want 0: the backend already has this statement", swallow)
	}
}

func TestBindForUnknownStatementIsForwardedAsIs(t *testing.T) {
	f := newPSFixture(t)

	// No Parse was ever seen for "ghost" — forwarding it unchanged lets
	// the backend produce the authoritative error.
	_, swallow := processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Bind{PreparedStatement: "ghost"})
	if swallow != 0 {
		t.Errorf("swallow = %d, want 0", swallow)
	}
}

func TestDescribeStatementReplaysButPortalDoesNot(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psCache = psCache{"s1": {SQL: "SELECT 1"}}

	// 'S' — describe by statement name, needs the statement to exist.
	_, swallow := processClientMsg(f.fe, f.backend, f.sess,
		&pgproto3.Describe{ObjectType: 'S', Name: "s1"})
	if swallow != 1 {
		t.Errorf("Describe('S') swallow = %d, want 1", swallow)
	}

	// 'P' — describe by portal. Portals are per-transaction and are
	// never replayed.
	f.backend.preparedStmts = nil
	_, swallow = processClientMsg(f.fe, f.backend, f.sess,
		&pgproto3.Describe{ObjectType: 'P', Name: "s1"})
	if swallow != 0 {
		t.Errorf("Describe('P') swallow = %d, want 0", swallow)
	}
}

// TestCloseDropsStatementFromBothCaches: leaving the entry behind is
// the unbounded-growth path, and it would also make a later Bind skip
// the replay for a statement the backend no longer has.
func TestCloseDropsStatementFromBothCaches(t *testing.T) {
	f := newPSFixture(t)
	f.sess.psCache = psCache{"s1": {SQL: "SELECT 1"}}
	f.backend.preparedStmts = backendPSCache{"s1": struct{}{}}

	processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Close{ObjectType: 'S', Name: "s1"})

	if _, still := f.sess.psCache["s1"]; still {
		t.Error("Close left the statement in the session cache")
	}
	if _, still := f.backend.preparedStmts["s1"]; still {
		t.Error("Close left the statement in the backend cache")
	}
}

// TestDDLInvalidatesCaches guards against Postgres' "cached plan must
// not change result type": after a schema change, a replayed Parse of
// the old statement would be planned against the old shape.
func TestDDLInvalidatesCaches(t *testing.T) {
	for _, sql := range []string{
		"ALTER TABLE users ADD COLUMN x int",
		"drop table users",
		"  \n CREATE INDEX idx ON users(id)",
		"-- migration step 3\nALTER TABLE users DROP COLUMN x",
		"TRUNCATE users",
	} {
		t.Run(sql, func(t *testing.T) {
			f := newPSFixture(t)
			f.sess.psCache = psCache{"s1": {SQL: "SELECT * FROM users"}}
			f.backend.preparedStmts = backendPSCache{"s1": struct{}{}}

			processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Query{String: sql})

			if f.sess.psCache != nil {
				t.Error("session prepared-statement cache survived a DDL")
			}
			if f.backend.preparedStmts != nil {
				t.Error("backend prepared-statement cache survived a DDL")
			}
		})
	}
}

func TestNonDDLLeavesCachesIntact(t *testing.T) {
	for _, sql := range []string{
		"SELECT * FROM users",
		"INSERT INTO users (id) VALUES (1)",
		"UPDATE users SET x = 1",
		"BEGIN",
		"-- just a comment",
	} {
		t.Run(sql, func(t *testing.T) {
			f := newPSFixture(t)
			f.sess.psCache = psCache{"s1": {SQL: "SELECT 1"}}
			f.backend.preparedStmts = backendPSCache{"s1": struct{}{}}

			processClientMsg(f.fe, f.backend, f.sess, &pgproto3.Query{String: sql})

			if f.sess.psCache == nil {
				t.Errorf("%q was misdetected as DDL and flushed the cache", sql)
			}
		})
	}
}

func TestIsDDLKeywordDetection(t *testing.T) {
	ddl := []string{
		"CREATE TABLE t (id int)", "ALTER TABLE t ADD c int", "DROP TABLE t",
		"TRUNCATE t", "GRANT SELECT ON t TO r", "REVOKE ALL ON t FROM r",
		"COMMENT ON TABLE t IS 'x'", "REINDEX TABLE t", "VACUUM FULL t",
		"REFRESH MATERIALIZED VIEW mv", "CLUSTER t USING idx",
		"create table t (id int)", // case-insensitive
	}
	for _, sql := range ddl {
		if !isDDL(sql) {
			t.Errorf("isDDL(%q) = false, want true", sql)
		}
	}

	notDDL := []string{
		"SELECT 1", "INSERT INTO t VALUES (1)", "UPDATE t SET c = 1",
		"DELETE FROM t", "BEGIN", "COMMIT", "SET x = 1",
		"", "  ", "--", "-- only a comment with no newline",
		"CREA", // too short to be a keyword
	}
	for _, sql := range notDDL {
		if isDDL(sql) {
			t.Errorf("isDDL(%q) = true, want false", sql)
		}
	}
}

// TestClearBackendPSCacheAfterReset pairs with server_reset_query:
// DISCARD ALL drops every prepared statement on the backend, so a cache
// that still claims otherwise would suppress the replay and produce the
// exact "does not exist" error this machinery prevents.
func TestClearBackendPSCacheAfterReset(t *testing.T) {
	b := &backendConn{preparedStmts: backendPSCache{"s1": struct{}{}}}
	clearBackendPSCache(b)
	if b.preparedStmts != nil {
		t.Error("clearBackendPSCache left entries behind")
	}
	clearBackendPSCache(nil) // must not panic
}

// TestProcessClientMsgPassesThroughHotPathMessages: Bind/Execute/Sync
// is the steady-state loop, and two of those three must do no work.
func TestProcessClientMsgPassesThroughHotPathMessages(t *testing.T) {
	f := newPSFixture(t)

	for _, msg := range []pgproto3.FrontendMessage{
		&pgproto3.Execute{}, &pgproto3.Sync{}, &pgproto3.Flush{},
		&pgproto3.CopyData{}, &pgproto3.CopyDone{}, &pgproto3.Terminate{},
	} {
		out, swallow := processClientMsg(f.fe, f.backend, f.sess, msg)
		if out != msg {
			t.Errorf("%T was not passed through unchanged", msg)
		}
		if swallow != 0 {
			t.Errorf("%T produced swallow = %d, want 0", msg, swallow)
		}
	}
}

func TestEnsureBackendHasStmtHandlesNilInputs(t *testing.T) {
	f := newPSFixture(t)

	// No session cache yet — nothing to replay from.
	if _, swallow := ensureBackendHasStmt(f.fe, f.backend, f.sess, "s1", &pgproto3.Bind{}); swallow != 0 {
		t.Error("replay attempted with an empty session cache")
	}
	// Empty name refers to the unnamed statement or a portal.
	f.sess.psCache = psCache{"s1": {SQL: "SELECT 1"}}
	if _, swallow := ensureBackendHasStmt(f.fe, f.backend, f.sess, "", &pgproto3.Bind{}); swallow != 0 {
		t.Error("replay attempted for an empty statement name")
	}
	// No backend held (between transactions).
	if _, swallow := ensureBackendHasStmt(f.fe, nil, f.sess, "s1", &pgproto3.Bind{}); swallow != 0 {
		t.Error("replay attempted without a backend")
	}
}
