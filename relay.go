// Package main — the relay: one client session's traffic, from the
// moment it is routed to a pool until it disconnects.
//
// Split out of main.go, which had grown to hold the process lifecycle,
// four listeners, the backend dialer and this — around two thousand
// lines in which the hot path was not findable. Nothing here changed in
// the move.
//
// The three sub-relays below the main loop exist because the protocol
// changes shape mid-session: COPY IN reverses the direction of traffic,
// COPY BOTH (replication) makes it bidirectional and open-ended, and
// both must be pumped by different code than the request/response loop.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/yurii-bondar/pgman/pool"
)

// relay is the pre-existing test entry — permissive defaults.
//
// client is the raw socket behind pg. relay needs it, not just the
// pgproto3 wrapper, because idle timeouts are enforced with read
// deadlines and pgproto3 deliberately exposes no way to reach through
// to the connection it was built on.
func relay(client net.Conn, pg *pgproto3.Backend, p *pool.Pool, sess *session, opts ...*runtimeOpts) {
	o := defaultRuntimeOpts()
	if len(opts) > 0 && opts[0] != nil {
		o = opts[0]
	}
	relayImpl(client, pg, p, sess, o)
}

// relayImpl implements transaction pooling: a backend is acquired only
// for the span of one transaction (BEGIN..COMMIT, or a single autocommit
// statement) and released the instant it reports ReadyForQuery{TxStatus:
// 'I'} — idle, outside any transaction. Between transactions the client
// holds no backend at all, so a later transaction may land on a
// completely different one.
//
// Two production-safety details this loop enforces that the naive
// version does not:
//
//   - query_wait_timeout: Acquire uses a bounded ctx (opts.queryWaitTimeout).
//     Without this, a saturated pool parks every waiting client goroutine
//     forever, growing memory/FDs unboundedly until the OOM killer wins.
//
//   - server_reset_query (DISCARD ALL): before a backend is returned to
//     the shared idle stack, any session state left over from this
//     client (SET, prepared statements, temp tables, listen/notify,
//     GUCs) is scrubbed synchronously. Without this, a later client
//     inherits the previous client's state — a correctness bug at best,
//     a data-leak (application_name/GUCs containing PII) at worst.
//
// Terminate is never forwarded to a held backend: real Postgres closes
// the connection on Terminate, which would destroy a backend we might
// still want to reuse. If we're holding a backend that's idle when
// Terminate arrives, we release it cleanly for the next client;
// otherwise (mid-transaction), we discard.
func relayImpl(client net.Conn, pg *pgproto3.Backend, p *pool.Pool, sess *session, opts *runtimeOpts) {
	var backend *backendConn
	var fe *pgproto3.Frontend
	var lastTxStatus byte // last RFQ status byte seen; 'I' = idle

	// inTransaction reports whether the client is sitting inside an open
	// transaction, which selects which of the two idle timeouts applies.
	// 'T' is an open transaction, 'E' is one that has errored but not
	// yet been rolled back — both still pin a backend and its locks.
	inTransaction := func() bool {
		return backend != nil && (lastTxStatus == 'T' || lastTxStatus == 'E')
	}

	// armClientIdleDeadline sets the read deadline that bounds how long
	// we will wait for the client's next message. Returns the SQLSTATE
	// and message to report if it fires, so the caller doesn't have to
	// re-derive which timeout was in force.
	//
	// Both codes are real Postgres SQLSTATEs for exactly these
	// conditions, so drivers and operators already know them.
	armClientIdleDeadline := func() (code, reason string) {
		if inTransaction() {
			if opts.idleTransactionTimeout <= 0 {
				_ = client.SetReadDeadline(time.Time{})
				return "", ""
			}
			_ = client.SetReadDeadline(time.Now().Add(opts.idleTransactionTimeout))
			return "25P03", "terminating connection due to idle-in-transaction timeout"
		}
		if opts.clientIdleTimeout <= 0 {
			_ = client.SetReadDeadline(time.Time{})
			return "", ""
		}
		_ = client.SetReadDeadline(time.Now().Add(opts.clientIdleTimeout))
		return "57P05", "terminating connection due to idle-session timeout"
	}

	// Once a message starts arriving the idle clock no longer applies —
	// a slow large COPY batch is not an idle client.
	disarmClientIdleDeadline := func() { _ = client.SetReadDeadline(time.Time{}) }

	// release hands the held backend back: reusable if this transaction
	// ended cleanly, discarded if we're abandoning it in an unknown or
	// mid-transaction state (never let another client inherit open
	// locks). When reusable AND server_reset_query is configured, the
	// scrub runs synchronously before the release so the next Acquire
	// on this conn sees a clean session.
	release := func(reusable bool) {
		if backend == nil {
			return
		}
		// Clear any query_timeout deadline before this connection can
		// reach another session. A leftover deadline travels with the
		// conn into the idle stack and makes the *next* client's first
		// read fail instantly, which is about as hard to diagnose as
		// bugs get.
		_ = backend.SetReadDeadline(time.Time{})
		if reusable {
			// No scrub here, and no round trip. The connection keeps
			// carrying this session's state, tagged with whose it is;
			// adoptBackend does the scrubbing when — and only when — a
			// different session picks it up. See stateOwner.
			backend.stateOwner = sess.id
			p.Release(backend)
		} else {
			p.Discard(backend)
		}
		backend, fe = nil, nil
		sess.setBackend(nil)
	}

	// pending counts the bytes of backend replies sitting unwritten in
	// pg's encode buffer. pgproto3.Backend.Send only appends to that
	// buffer — Flush is what performs the write(2) — so batching Sends
	// is how a result set becomes one syscall instead of one per row.
	//
	// The invariant every flush point below maintains: never block
	// reading from the client while pending > 0.
	pending := 0
	flushClient := func() error {
		if pending == 0 {
			return nil
		}
		pending = 0
		if err := pg.Flush(); err != nil {
			slog.Warn("relay: send to client", "err", err)
			release(false)
			return err
		}
		return nil
	}

	for {
		idleCode, idleReason := armClientIdleDeadline()
		msg, err := pg.Receive()
		disarmClientIdleDeadline()
		if err != nil {
			if idleCode != "" && errors.Is(err, os.ErrDeadlineExceeded) {
				slog.Info("relay: idle timeout",
					"code", idleCode, "user", sess.user, "database", sess.database,
					"in_transaction", inTransaction())
				// Report before releasing: once the backend is
				// discarded the error is just an unexplained close.
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     idleCode,
					Message:  idleReason,
				})
				_ = pg.Flush()
				// An idle-in-transaction backend is mid-transaction and
				// must be discarded; an idle *session* may be holding a
				// perfectly clean one worth keeping.
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				slog.Debug("relay: client receive", "err", err)
			}
			// If we happen to be holding a clean-idle backend when the
			// client vanishes without Terminate, don't waste it.
			release(backend != nil && lastTxStatus == 'I')
			return
		}
		if _, ok := msg.(*pgproto3.Terminate); ok {
			release(backend != nil && lastTxStatus == 'I')
			return
		}

		if backend == nil {
			// Shutdown boundary. We hold no backend, so this client is
			// between transactions and can be let go without aborting
			// anything. 57P01 (admin_shutdown) is what Postgres itself
			// sends on a fast shutdown, so drivers already treat it as
			// "reconnect", not as a query failure.
			if opts.draining.Load() {
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "57P01",
					Message:  "terminating connection due to administrator command (pgman is shutting down)",
				})
				_ = pg.Flush()
				return
			}

			ctx := context.Background()
			var cancel context.CancelFunc
			if opts.queryWaitTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, opts.queryWaitTimeout)
			}
			conn, err := p.Acquire(ctx)
			if cancel != nil {
				cancel()
			}
			if err != nil {
				slog.Info("relay: acquire failed", "err", err)
				// A closed pool means the process is going away, so the
				// session genuinely cannot continue — that one stays
				// fatal. Everything else is transient: the backend is
				// down or the pool is momentarily full, and both are
				// survivable if we let the client retry.
				//
				// Killing the session instead (the previous behaviour)
				// is actively harmful under load: application-side pools
				// answer a dropped connection with a reconnect storm,
				// aimed at a proxy that is already saturated.
				if errors.Is(err, pool.ErrPoolClosed) {
					pg.Send(&pgproto3.ErrorResponse{
						Severity: "FATAL",
						Code:     "57P01",
						Message:  "terminating connection due to administrator command (pgman is shutting down)",
					})
					_ = pg.Flush()
					return
				}
				code, message := "53300", "no backend connection available: "+err.Error()
				if errors.Is(err, pool.ErrCircuitOpen) {
					// 08006 connection_failure says "the server side is
					// broken", which is exactly what an open breaker
					// means and is distinct from "we are full".
					code, message = "08006", "backend unavailable: circuit breaker open"
				}
				if err := failQuery(pg, msg, code, message); err != nil {
					return
				}
				continue
			}
			backend = conn.(*backendConn)
			fe = backend.frontend()
			sess.setBackend(backend)

			if err := adoptBackend(fe, backend, sess, opts); err != nil {
				// The connection could not be made safe for this
				// session, so it must not be handed over. Discard it
				// and fail this one query rather than the session: a
				// retry lands on a different (or fresh) backend, which
				// is very likely to work.
				slog.Warn("relay: adopting backend failed", "err", err)
				p.Discard(backend)
				backend, fe = nil, nil
				sess.setBackend(nil)
				if err := failQuery(pg, msg, "08006", "backend could not be prepared for this session: "+err.Error()); err != nil {
					return
				}
				continue
			}
		}

		// Extended query protocol awareness: Postgres buffers responses
		// for Parse/Bind/Describe/Execute until Sync arrives, then
		// flushes everything including ReadyForQuery. If we forwarded
		// one message at a time and waited for RFQ after each, we'd
		// deadlock on Parse (backend waits for Sync, relay waits for
		// RFQ). Instead: buffer-forward all messages until we see a
		// terminal message (Query or Sync) that triggers RFQ from the
		// backend, then flush and read the response stream.
		//
		// Simple query protocol: a single Query message triggers an
		// immediate response ending with RFQ — treated as terminal.
		//
		// Prepared-statement replay: processClientMsg may prepend a
		// Parse for a stmt this backend doesn't yet know, and a Close
		// for the one it evicts to make room. Each injected message
		// emits an ack the client never asked for, so the counts say
		// how many of each to drop out of the response stream.
		// Fused per-message intercept: PS lazy-replay + LISTEN warn +
		// DDL cache flush in one type switch. Hot Bind/Execute/Sync
		// loop hits the "nothing to do" branch for 2 of every 3 msgs.
		var swallow psSwallow
		outMsg, injected, err := processClientMsg(fe, backend, sess, msg)
		if err != nil {
			// The only error this returns is a session that cannot be
			// served correctly any more. 54000 (program_limit_exceeded)
			// is what Postgres itself uses for "you asked for more than
			// this server will hold".
			slog.Warn("relay: prepared-statement ceiling",
				"err", err, "user", sess.user, "database", sess.database)
			pg.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "54000",
				Message:  err.Error(),
			})
			_ = pg.Flush()
			// The backend never saw this Parse, so it is still clean
			// unless a transaction is open on it.
			release(lastTxStatus == 'I')
			return
		}
		swallow.add(injected)
		fe.Send(outMsg)

		terminal := isTerminalMessage(msg)

		// If not terminal yet, keep reading + forwarding until we see
		// one. This covers the common extended-protocol batch:
		// Parse → Bind → Describe → Execute → Sync.
		for !terminal {
			next, err := pg.Receive()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					slog.Debug("relay: client receive (ext batch)", "err", err)
				}
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			if _, ok := next.(*pgproto3.Terminate); ok {
				release(backend != nil && lastTxStatus == 'I')
				return
			}
			outNext, injectedNext, err := processClientMsg(fe, backend, sess, next)
			if err != nil {
				slog.Warn("relay: prepared-statement ceiling",
					"err", err, "user", sess.user, "database", sess.database)
				pg.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "54000",
					Message:  err.Error(),
				})
				_ = pg.Flush()
				// Mid-batch: whatever of this batch already reached the
				// backend leaves it in a state nobody else may inherit.
				release(false)
				return
			}
			swallow.add(injectedNext)
			fe.Send(outNext)
			terminal = isTerminalMessage(next)
		}

		if err := fe.Flush(); err != nil {
			slog.Warn("relay: forward to backend", "err", err)
			release(false)
			return
		}

		// The query is now in flight. Everything from here to
		// ReadyForQuery is "the backend working", which is both what
		// query_timeout bounds and what the latency histogram measures.
		queryStart := time.Now()
		if opts.queryTimeout > 0 {
			// A read deadline, not a refreshing one: query_timeout is
			// the total time a statement may take, so it must not be
			// extended by a backend that keeps trickling rows.
			_ = backend.SetReadDeadline(queryStart.Add(opts.queryTimeout))
		}

		for {
			reply, err := fe.Receive()
			if err != nil {
				if opts.queryTimeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
					slog.Warn("relay: query_timeout exceeded",
						"timeout", opts.queryTimeout,
						"user", sess.user, "database", sess.database)
					// Discard, don't release: the backend is still
					// executing. Closing the socket is what actually
					// aborts the statement server-side, and it can
					// never be reused in that state.
					release(false)
					pg.Send(&pgproto3.ErrorResponse{
						Severity: "FATAL",
						Code:     "57014", // query_canceled
						Message:  "canceling statement due to query_timeout",
					})
					_ = pg.Flush()
					return
				}
				slog.Warn("relay: backend receive", "err", err)
				release(false)
				return
			}
			// Swallow the acks for messages the proxy injected: the
			// ParseComplete of a lazy-prepare prepend, and the
			// CloseComplete of the eviction that made room for it. The
			// client sent neither and is not expecting either.
			if swallow.parseComplete > 0 {
				if _, ok := reply.(*pgproto3.ParseComplete); ok {
					swallow.parseComplete--
					continue
				}
			}
			if swallow.closeComplete > 0 {
				if _, ok := reply.(*pgproto3.CloseComplete); ok {
					swallow.closeComplete--
					continue
				}
			}
			pg.Send(reply)
			pending += replyEncodedSize(reply)
			// Only pay a write(2) once the buffer is worth writing.
			// Flushing per message turned a 10k-row result set into
			// 10k syscalls; the threshold keeps memory bounded for
			// large streams while the flushes below guarantee the
			// client sees everything before we block on it.
			if pending >= clientFlushThreshold {
				if err := flushClient(); err != nil {
					return
				}
			}

			// COPY sub-protocol handoff. When the backend enters COPY
			// IN mode (client streams data to server), the roles flip:
			// we must relay client → backend until the client ends the
			// copy with CopyDone or CopyFail. Failing to do this makes
			// the whole session deadlock — backend sits waiting for
			// CopyData, we sit waiting for backend messages.
			if _, ok := reply.(*pgproto3.CopyInResponse); ok {
				// The client will not send a single CopyData byte
				// until it has actually seen CopyInResponse, and
				// relayCopyIn immediately blocks reading from it.
				// Flushing here is what stops that from deadlocking.
				if err := flushClient(); err != nil {
					return
				}
				// A bulk load takes as long as it takes; its duration
				// carries no information about backend health, so
				// query_timeout does not apply past this point.
				_ = backend.SetReadDeadline(time.Time{})
				if err := relayCopyIn(pg, fe); err != nil {
					slog.Warn("relay: copy-in", "err", err)
					release(false)
					return
				}
				// After CopyDone/CopyFail the backend produces
				// CommandComplete + RFQ — fall through to the outer
				// receive loop.
				continue
			}
			// CopyBothResponse: replication protocol (walsender /
			// logical CDC — Debezium, wal2json, pgoutput). Client
			// and server exchange CopyData messages asynchronously
			// in both directions, ended by client's CopyDone.
			if _, ok := reply.(*pgproto3.CopyBothResponse); ok {
				// Same handoff rule as COPY IN: relayCopyBoth starts a
				// goroutine that reads from the client straight away.
				if err := flushClient(); err != nil {
					return
				}
				// Replication streams are open-ended by design — a
				// walsender can idle for minutes between WAL records.
				_ = backend.SetReadDeadline(time.Time{})
				if err := relayCopyBoth(pg, fe, client, backend); err != nil {
					slog.Warn("relay: copy-both", "err", err)
					release(false)
					return
				}
				continue
			}
			// CopyOutResponse: backend streams CopyData → CopyDone →
			// CommandComplete → RFQ. The existing loop already handles
			// this correctly (keep reading until RFQ) — no special case
			// needed.

			rfq, ok := reply.(*pgproto3.ReadyForQuery)
			if !ok {
				continue
			}
			// End of the response cycle: the client is about to be the
			// only one with anything to say, so everything buffered
			// has to be on the wire before we go back to reading it.
			if err := flushClient(); err != nil {
				return
			}
			// The statement is done, so the query clock stops and the
			// deadline must come off before the conn can be released.
			_ = backend.SetReadDeadline(time.Time{})
			opts.metrics.observeQuery(sess.poolName, time.Since(queryStart))
			lastTxStatus = rfq.TxStatus
			// Release decision per pooling mode:
			//   transaction — release when backend is idle ('I')
			//   session     — never release on RFQ (only on disconnect)
			//   statement   — release on EVERY RFQ regardless of TxStatus.
			// Statement mode is the most aggressive: it makes BEGIN /
			// COMMIT / SET LOCAL effectively useless (each statement
			// lands on a fresh backend), so it's only appropriate for
			// pure autocommit read workloads.
			switch sess.poolMode {
			case "statement":
				release(rfq.TxStatus != 'E') // 'E' = errored, poison; discard
			case "session":
				// no-op
			default: // transaction (also empty string)
				if rfq.TxStatus == 'I' {
					release(true)
				}
			}
			break
		}
	}
}

// adoptBackend makes a just-acquired connection safe and correct for
// sess to use, and is where server_reset_query now runs.
//
// The scrub used to happen on release, which cost a full round trip at
// the end of every transaction — and with track_extra_parameters on by
// default, the replay of application_name and friends cost another one
// at the start of the next. Both were paid even when the connection
// went straight back to the session that had just handed it over,
// which with a LIFO pool and a serial client is the overwhelmingly
// common case. Between two transactions of the same session those two
// round trips scrub state the session owns, only to immediately
// restore it: the isolation they provide is isolation from nobody.
//
// So the work is deferred to here, where the next owner is finally
// known, and skipped outright when that owner is unchanged. What the
// deferral does NOT do is weaken isolation: no statement from a new
// session reaches the backend before the scrub, because this runs
// before the first message is forwarded.
//
// The trade is that a released connection now sits in the idle stack
// still holding its last owner's session state — GUCs, prepared
// statements, temp tables, session advisory locks — instead of being
// scrubbed immediately. That state belongs to a client that is still
// connected and, in transaction pooling, usually about to come back;
// server_idle_timeout and server_lifetime bound how long it can linger
// if that client goes quiet instead.
func adoptBackend(fe *pgproto3.Frontend, backend *backendConn, sess *session, opts *runtimeOpts) error {
	// Every session that touches a connection needs a real identity, or
	// two sessions built outside registerSession would both read as 0
	// and hand each other an unscrubbed backend. Issued lazily here so
	// the guarantee holds for any session, however it was constructed.
	if sess.id == 0 {
		sess.id = nextSessionID.Add(1)
	}
	if opts.resetSkipSameSession && backend.stateOwner == sess.id {
		return nil // our own state, already in place: nothing to do
	}

	// stateOwner == 0 is a connection nobody has used yet, so there is
	// nothing to scrub — but its GUCs are still Postgres defaults, so
	// the tracked-parameter replay below still has to run.
	if backend.stateOwner != 0 && opts.serverResetQuery != "" {
		if err := runResetQuery(fe, backend, opts.serverResetQuery, opts.healthCheckTimeout); err != nil {
			return fmt.Errorf("server_reset_query: %w", err)
		}
	}

	// Drop the record of which statements the backend was shown. It is
	// the previous session's, and statement names are chosen per
	// client: left in place, this session's Bind for a colliding name
	// would skip its lazy Parse and run the other client's statement.
	//
	// Note this happens whether or not the reset query ran. When an
	// operator disables server_reset_query the statements themselves
	// survive on the backend and a colliding name now raises 42P05,
	// which is a loud, correct failure rather than a silent wrong one.
	clearBackendPSCache(backend)

	// application_name & friends: replay startup params so
	// pg_stat_activity / TimeZone / client_encoding match what the
	// client asked for. Silent — the client never sees these SETs.
	if len(sess.trackedParams) > 0 {
		if err := applyTrackedParams(fe, sess.trackedParams); err != nil {
			return fmt.Errorf("apply tracked params: %w", err)
		}
	}

	backend.stateOwner = sess.id
	return nil
}

// clientFlushThreshold is how many bytes of backend replies may sit in
// the client write buffer before we force a write(2). It bounds the
// memory a single streaming result set can pin (per client connection)
// while still amortising the syscall across many rows. 64 KiB is well
// above a typical TCP send buffer's useful chunk and far below anything
// that matters against max_client_conn.
const clientFlushThreshold = 64 << 10

// replyEncodedSize approximates the wire size of a backend reply. It
// feeds the flush threshold only, so it needs to be cheap and roughly
// right, not exact. DataRow and CopyData are the only backend messages
// that can be arbitrarily large and the only ones that appear in bulk;
// everything else is small and bounded, so a flat estimate covers it.
func replyEncodedSize(msg pgproto3.BackendMessage) int {
	switch m := msg.(type) {
	case *pgproto3.DataRow:
		// type byte + int32 length + int16 column count, then an
		// int32 length prefix per column value.
		n := 7
		for _, v := range m.Values {
			n += 4 + len(v)
		}
		return n
	case *pgproto3.CopyData:
		return 5 + len(m.Data)
	default:
		return 128
	}
}

// failQuery reports a recoverable, query-scoped error and leaves the
// connection in a state the client can keep using.
//
// The subtlety is the extended query protocol. If the message we failed
// on is not the terminal one, the client has already pipelined the rest
// of its batch (Bind, Describe, Execute, Sync) and is waiting for a
// single response. Replying immediately would leave those messages in
// the socket to be misread as the start of the next query. Postgres
// solves this by discarding messages until Sync, and so do we.
//
// Returns a non-nil error only when the client itself is gone, in which
// case the caller must unwind.
func failQuery(pg *pgproto3.Backend, msg pgproto3.FrontendMessage, code, message string) error {
	if !isTerminalMessage(msg) {
		for {
			next, err := pg.Receive()
			if err != nil {
				return fmt.Errorf("drain to sync: %w", err)
			}
			if _, ok := next.(*pgproto3.Terminate); ok {
				return errClientTerminated
			}
			if isTerminalMessage(next) {
				break
			}
		}
	}

	// Severity ERROR, not FATAL: FATAL tells the driver the connection
	// is finished, which is precisely the reconnect storm we are trying
	// to avoid.
	pg.Send(&pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     code,
		Message:  message,
	})
	pg.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := pg.Flush(); err != nil {
		return fmt.Errorf("report query failure: %w", err)
	}
	return nil
}

// errClientTerminated marks "the client hung up while we were putting
// the protocol back together" — not an error worth logging.
var errClientTerminated = errors.New("client terminated")

// isTerminalMessage returns true for messages that cause Postgres to
// flush its response pipeline and end with ReadyForQuery in the *outer*
// protocol level:
//   - Query (simple protocol) — immediate full response
//   - Sync (extended protocol) — flushes buffered responses
//
// CopyDone / CopyFail are NOT terminal at this level — they're
// sub-protocol messages inside the COPY handoff, handled by
// relayCopyIn (which switches its own direction until it sees them).
// If we left them here, a client's COPY FROM STDIN batch would prematurely
// terminate the outer batching loop.
func isTerminalMessage(msg pgproto3.FrontendMessage) bool {
	switch msg.(type) {
	case *pgproto3.Query, *pgproto3.Sync:
		return true
	}
	return false
}

// relayCopyBoth drives the bidirectional CopyBoth sub-protocol used by
// PostgreSQL replication clients (walsender for physical, logical
// decoding plugins for CDC — Debezium, wal2json, pgoutput). Both sides
// send CopyData asynchronously; the exchange ends when the client sends
// CopyDone (or CopyFail / Terminate), which the backend acknowledges
// with its own CopyDone → CommandComplete → RFQ.
//
// Implementation: two goroutines pump each direction independently
// with per-message flush (replication is latency-sensitive, and each
// CopyData carries a WAL record or keepalive that the peer needs
// promptly). Errors on either side abort the pair.
//
// client and backend are the sockets behind pg and fe. They are needed
// because the two pumps can only be woken through their own
// connections: see the drain logic after the goroutines below.
func relayCopyBoth(pg *pgproto3.Backend, fe *pgproto3.Frontend, client, backend net.Conn) error {
	// Channel carries a single error from whichever direction fails
	// first. Second failure (usually the peer noticing the socket
	// closing) is discarded — the first error is the interesting one.
	errCh := make(chan error, 2)

	// client → backend
	go func() {
		for {
			msg, err := pg.Receive()
			if err != nil {
				errCh <- fmt.Errorf("client→backend receive: %w", err)
				return
			}
			switch msg.(type) {
			case *pgproto3.Terminate:
				// Synthesize CopyDone so the backend cleans up
				// gracefully instead of ending with a broken pipe.
				fe.Send(&pgproto3.CopyDone{})
				_ = fe.Flush()
				errCh <- nil
				return
			case *pgproto3.CopyDone, *pgproto3.CopyFail:
				fe.Send(msg)
				if err := fe.Flush(); err != nil {
					errCh <- fmt.Errorf("flush end-of-copy: %w", err)
					return
				}
				// After CopyDone/CopyFail the backend responds with
				// its own CopyDone + CommandComplete + RFQ. Leave the
				// other goroutine to relay those, then exit.
				errCh <- nil
				return
			default:
				fe.Send(msg)
				if err := fe.Flush(); err != nil {
					errCh <- fmt.Errorf("client→backend flush: %w", err)
					return
				}
			}
		}
	}()

	// backend → client
	go func() {
		for {
			msg, err := fe.Receive()
			if err != nil {
				errCh <- fmt.Errorf("backend→client receive: %w", err)
				return
			}
			pg.Send(msg)
			if err := pg.Flush(); err != nil {
				errCh <- fmt.Errorf("backend→client flush: %w", err)
				return
			}
			// ReadyForQuery from backend closes the copy-both round.
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				errCh <- nil
				return
			}
		}
	}()

	// First goroutine to finish decides the outcome. The second has to
	// be drained too, or it outlives this call holding a reference to
	// both connections.
	//
	// It will not always end on its own. Both pumps deliberately run
	// without read deadlines — a walsender can idle for minutes between
	// WAL records — so when one direction stops, the other can be
	// parked in Receive on a socket whose peer has nothing left to say.
	// Waiting for it unconditionally is what turned a client that
	// vanished mid-replication into a permanently stuck relay: three
	// goroutines, the backend connection and its pool slot, leaked for
	// the life of the process.
	//
	// Tripping the read deadlines is what unparks it. SetReadDeadline
	// is safe to call concurrently with a Read already in flight, and a
	// deadline in the past fails that Read immediately.
	first := <-errCh
	grace := copyBothDrainGrace
	if first != nil {
		// One side is already broken, so relayImpl is going to discard
		// this backend regardless. Nothing to wait politely for.
		grace = 0
	}
	select {
	case <-errCh:
	case <-time.After(grace):
		past := time.Now().Add(-time.Second)
		_ = client.SetReadDeadline(past)
		_ = backend.SetReadDeadline(past)
		<-errCh
		// Clear them again: on the clean path the caller keeps using
		// both connections for the rest of the session, and a deadline
		// left in the past would fail its very next read.
		_ = client.SetReadDeadline(time.Time{})
		_ = backend.SetReadDeadline(time.Time{})
	}
	return first
}

// copyBothDrainGrace is how long relayCopyBoth lets the second
// direction finish on its own after the first one has ended, before
// forcing it. The clean case needs a little room — the backend answers
// a client's CopyDone with CopyDone + CommandComplete + RFQ, and that
// round trip is real network time — while the failure case skips this
// entirely. A var, not a const, so tests can shorten it.
var copyBothDrainGrace = 5 * time.Second

// relayCopyIn drives the COPY-IN sub-protocol: backend has sent
// CopyInResponse and is now blocked waiting for the client's data
// stream (CopyData messages) terminated by CopyDone or CopyFail. We
// pass each client message straight through to the backend and flush
// every 32 messages (or on end-of-copy) to strike a balance between
// syscall cost and memory footprint for very large loads.
//
// Returns nil once CopyDone or CopyFail has been forwarded — the
// caller then resumes reading the backend's post-COPY response
// (CommandComplete + RFQ).
func relayCopyIn(pg *pgproto3.Backend, fe *pgproto3.Frontend) error {
	const flushEvery = 32
	pending := 0
	for {
		msg, err := pg.Receive()
		if err != nil {
			return fmt.Errorf("client receive: %w", err)
		}
		switch msg.(type) {
		case *pgproto3.Terminate:
			// Client abandoned mid-copy — synthesize a CopyFail so
			// the backend rolls back cleanly instead of thinking
			// this is a partial copy waiting to resume.
			fe.Send(&pgproto3.CopyFail{Message: "client terminated during COPY"})
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush copyfail: %w", err)
			}
			return nil
		case *pgproto3.CopyData:
			fe.Send(msg)
			pending++
			if pending >= flushEvery {
				if err := fe.Flush(); err != nil {
					return fmt.Errorf("flush: %w", err)
				}
				pending = 0
			}
		case *pgproto3.CopyDone, *pgproto3.CopyFail:
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush end-of-copy: %w", err)
			}
			return nil
		default:
			// Anything else during COPY IN is a protocol violation
			// by the client — pass through and let the backend
			// generate the appropriate error.
			fe.Send(msg)
			if err := fe.Flush(); err != nil {
				return fmt.Errorf("flush unexpected: %w", err)
			}
		}
	}
}

// runResetQuery sends the configured server_reset_query on the backend
// and consumes until ReadyForQuery. Uses the same deadline as the
// health-check path since it's the same round-trip shape.
// fe is the caller's own Frontend rather than a fresh one. Two
// Frontends reading the same socket is a desync waiting to happen — the
// one that is thrown away takes whatever it has buffered with it — and
// reusing the live one also skips a per-transaction allocation.
func runResetQuery(fe *pgproto3.Frontend, backend *backendConn, query string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if err := backend.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	defer func() { _ = backend.SetDeadline(time.Time{}) }()

	fe.Send(&pgproto3.Query{String: query})
	if err := fe.Flush(); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	for {
		msg, err := fe.Receive()
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			return fmt.Errorf("backend error: %s", m.Message)
		case *pgproto3.ReadyForQuery:
			return nil
		}
	}
}
