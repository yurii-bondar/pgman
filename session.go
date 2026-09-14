package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// cancelDialTimeout bounds sendRealCancelRequest — a real Postgres that
// went unreachable must not leak goroutines/FDs by letting a fire-and-
// forget cancel dial hang forever.
var cancelDialTimeout = 5 * time.Second

// sessionShardCount is the number of stripes in the sharded session
// registry. A power of two so pid → shard is a bitmask, not a division.
// 32 is enough that at a realistic 10^5 concurrent sessions no single
// stripe holds more than ~3k entries and, more importantly, the write
// contention on registerSession/deregisterSession/cancelSession is
// spread 32-way. Going higher costs memory (32 * ~48-byte overhead per
// empty map, per stripe struct) without a real return past that point.
const sessionShardCount = 32

// backendConn decorates a hijacked real-Postgres connection with the
// identity Postgres gave it (PID + secret) — needed only to route a
// real CancelRequest to this exact backend process later. Embedding
// net.Conn means backendConn satisfies net.Conn itself, so pool.Pool
// (which only knows about net.Conn) needs no changes to carry this
// extra data around.
//
// secretKey is []byte in v5's pgproto3 because Postgres 18 lengthened
// cancel-key material past the pre-18 fixed 4 bytes. We just carry the
// raw bytes end-to-end; nobody in this file cares about the length.
// backendConn additionally carries a small per-connection prepared-
// statement registry (see prepared_stmts.go) — sits here rather than
// in a side map so the (short-lived, per-Acquire) lifetime is trivially
// correct: the cache dies with the conn.
type backendConn struct {
	// preparedStmts is populated on the fly by relay's message
	// interceptor. Keys are statement names as they appear on THIS
	// backend (currently identical to the client-side names).
	preparedStmts backendPSCache

	net.Conn
	addr      string
	pid       uint32
	secretKey []byte
}

// session tracks one client's fake identity (the BackendKeyData we
// handed it at fake-auth time) and, while a transaction is in flight,
// which real backend is currently serving it — nil between transactions.
// trackedParam is one (name, value) StartupMessage param the proxy
// replays on new backends. Kept as a slice-of-pairs (not a map) so
// replay order is stable — a few clients depend on TimeZone being SET
// before DateStyle, for example.
type trackedParam struct {
	Name  string
	Value string
}

type session struct {
	secret      []byte
	user        string
	database    string
	connectedAt time.Time
	// poolMode selects when relay releases the backend:
	//   "transaction" (default) — release on RFQ TxStatus='I' (between txns)
	//   "session"               — release only on client disconnect
	//   "statement"             — release on every RFQ regardless of TxStatus
	// Set once at startup from RouteDecision, never mutated.
	poolMode string

	// poolName is the registry key of the pool serving this session —
	// the label every pgman_pool_* series uses. Distinct from database
	// because aliases let several database names share a pool. Set once
	// at startup, never mutated.
	poolName string

	// trackedParams captures the subset of StartupMessage RuntimeParams
	// this proxy replays on every backend Acquire in transaction mode
	// (see track_extra_parameters config). Order-stable slice, not a
	// map, so replay order matches the client's original startup and
	// the emitted SET string is deterministic.
	trackedParams []trackedParam

	// psCache is the client-visible prepared-statement registry —
	// populated on Parse, consulted on Bind/Describe/Close for
	// lazy-Parse replay against fresh backends. See prepared_stmts.go
	// for the full protocol. Nil until the client's first Parse.
	psCache psCache

	// listenWarned trips true after we've logged the one-shot
	// "LISTEN in transaction pooling won't deliver NOTIFY" warning
	// for this session. Prevents log spam when a client issues many
	// LISTENs on different channels.
	listenWarned bool

	mu          sync.Mutex
	backend     *backendConn
	txStartedAt time.Time
}

func (s *session) setBackend(b *backendConn) {
	s.mu.Lock()
	s.backend = b
	if b != nil {
		s.txStartedAt = time.Now()
	} else {
		s.txStartedAt = time.Time{}
	}
	s.mu.Unlock()
}

// sessionShard is one stripe of the sharded session registry — its own
// mutex, its own map.
type sessionShard struct {
	mu       sync.Mutex
	sessions map[uint32]*session
}

// sessionRegistry is 32 stripes, each guarded by its own mutex. All
// look-ups route to `shards[pid % 32]` in constant time (masked, not
// divided). listSessions walks every shard once — this is O(total
// sessions) either way, and only runs from the admin UI polling loop,
// not from the hot per-query path.
type sessionRegistry struct {
	shards [sessionShardCount]*sessionShard
}

func newSessionRegistry() *sessionRegistry {
	r := &sessionRegistry{}
	for i := range r.shards {
		r.shards[i] = &sessionShard{sessions: make(map[uint32]*session)}
	}
	return r
}

func (r *sessionRegistry) shardFor(pid uint32) *sessionShard {
	return r.shards[pid&(sessionShardCount-1)]
}

// globalSessions is the process-wide registry. Kept as a package var
// so registerSession/deregisterSession/cancelSession/listSessions keep
// their pre-sharding signatures and the rest of the codebase (and
// existing tests) don't have to plumb a *sessionRegistry through.
var globalSessions = newSessionRegistry()

// randUint32 reads 4 bytes of crypto/rand as a uint32. crypto/rand
// failure means the OS entropy source is broken — panic loudly.
func randUint32() uint32 {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic(fmt.Sprintf("session: crypto/rand: %v", err))
	}
	return binary.BigEndian.Uint32(buf[:])
}

// randSecret returns 4 cryptographically-random bytes — the pre-18
// Postgres cancel-key width. If we ever start proxying Postgres 18+
// with longer keys, this width can grow without touching the wire
// paths (they already treat SecretKey as opaque []byte).
func randSecret() []byte {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("session: crypto/rand: %v", err))
	}
	return buf
}

// registerSession creates a session with a fresh, unpredictable
// identity (both pid and secret from crypto/rand) and makes it visible
// to future CancelRequests. pid is drawn until an unused value lands
// in its shard — with 100 attempts and a uint32 range, collisions are
// unmeasurable in practice.
func registerSession(user, database string) (pid uint32, sess *session) {
	for i := 0; i < 100; i++ {
		p := randUint32()
		if p == 0 {
			continue // pid 0 reserved by convention
		}
		shard := globalSessions.shardFor(p)
		shard.mu.Lock()
		if _, taken := shard.sessions[p]; taken {
			shard.mu.Unlock()
			continue
		}
		secret := randSecret()
		sess = &session{secret: secret, user: user, database: database, connectedAt: time.Now()}
		shard.sessions[p] = sess
		shard.mu.Unlock()
		return p, sess
	}
	panic("session: unable to allocate a unique pid after 100 attempts")
}

func deregisterSession(pid uint32) {
	shard := globalSessions.shardFor(pid)
	shard.mu.Lock()
	delete(shard.sessions, pid)
	shard.mu.Unlock()
}

// SessionInfo is a session's state as the admin UI needs to show it —
// a value copy, safe to hold and render without touching the live
// session's own mutex again.
type SessionInfo struct {
	PID         uint32
	User        string
	Database    string
	Active      bool
	ConnectedAt time.Time
	TxStartedAt time.Time
}

// listSessions snapshots every currently connected session across all
// shards, sorted by connection time (oldest first — the ones most
// likely to be stuck). Walks each shard in turn, so it holds at most
// one shard mutex at a time.
func listSessions() []SessionInfo {
	var out []SessionInfo
	for _, shard := range globalSessions.shards {
		shard.mu.Lock()
		for pid, sess := range shard.sessions {
			sess.mu.Lock()
			out = append(out, SessionInfo{
				PID:         pid,
				User:        sess.user,
				Database:    sess.database,
				ConnectedAt: sess.connectedAt,
				Active:      sess.backend != nil,
				TxStartedAt: sess.txStartedAt,
			})
			sess.mu.Unlock()
		}
		shard.mu.Unlock()
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ConnectedAt.Before(out[j].ConnectedAt) })
	return out
}

// lookupSession is a small helper for the two-step
// "find, then take a look at the backend" pattern in cancelSession
// and handleCancelRequest. Never holds the shard mu after returning —
// the caller inspects the session under its own per-session mutex.
func lookupSession(pid uint32) (*session, bool) {
	shard := globalSessions.shardFor(pid)
	shard.mu.Lock()
	sess, ok := shard.sessions[pid]
	shard.mu.Unlock()
	return sess, ok
}

// cancelSession forwards a real CancelRequest for the session's
// current backend, if it has one.
func cancelSession(pid uint32) error {
	sess, ok := lookupSession(pid)
	if !ok {
		return fmt.Errorf("session %d not found", pid)
	}

	sess.mu.Lock()
	backend := sess.backend
	sess.mu.Unlock()

	if backend == nil {
		return fmt.Errorf("session %d has no in-flight transaction to cancel", pid)
	}
	return sendRealCancelRequest(backend.addr, backend.pid, backend.secretKey)
}

// handleCancelRequest looks up which session owns the fake PID a
// client's CancelRequest names, checks the secret matches
// (bytes.Equal — v5's SecretKey is []byte, not uint32), and delegates
// to cancelSession. Fire-and-forget per protocol.
func handleCancelRequest(m *pgproto3.CancelRequest) {
	sess, ok := lookupSession(m.ProcessID)
	if !ok {
		slog.Debug("cancel: unknown session", "pid", m.ProcessID)
		return
	}
	if !bytes.Equal(sess.secret, m.SecretKey) {
		slog.Warn("cancel: secret mismatch", "pid", m.ProcessID)
		return
	}

	if err := cancelSession(m.ProcessID); err != nil {
		slog.Warn("cancel: forwarding failed", "pid", m.ProcessID, "err", err)
	}
}

// sendRealCancelRequest opens the short-lived, unauthenticated
// connection real Postgres expects a CancelRequest on, and closes it
// immediately. Uses a bounded dial timeout: a slow or unreachable
// backend must never hang the caller (see cancelDialTimeout).
func sendRealCancelRequest(addr string, pid uint32, secretKey []byte) error {
	conn, err := net.DialTimeout("tcp", addr, cancelDialTimeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(cancelDialTimeout))

	buf, err := (&pgproto3.CancelRequest{ProcessID: pid, SecretKey: secretKey}).Encode(nil)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	_, err = conn.Write(buf)
	return err
}
