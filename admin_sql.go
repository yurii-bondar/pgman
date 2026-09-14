// Package main — PgBouncer-compatible admin SQL over the Postgres wire.
//
// When a client connects with database=<AdminDatabase> (default:
// "pgbouncer"), pgman does NOT route to a real Postgres. Instead it
// synthesizes Postgres wire responses to a small SQL vocabulary that
// mirrors PgBouncer's admin console:
//
//	SHOW POOLS     — one row per configured pool
//	SHOW STATS     — pool counters (waits, dials, discards, reaped)
//	SHOW CLIENTS   — one row per currently-registered session
//	SHOW SERVERS   — pool idle/in-use snapshot
//	SHOW DATABASES — pool config table
//	SHOW VERSION   — proxy version string
//	PAUSE  [name]  — pause one or every pool
//	RESUME [name]  — resume one or every pool
//	RECONNECT [name] — bump generation on one or every pool
//
// The whole surface is loopback-only in practice (admin_addr default
// is 127.0.0.1) but nothing here is inherently unsafe over TLS+auth
// either — the same three-tier admin auth still applies via HTTP.
// SQL-level auth (via psql) is the same as any client: SCRAM/trust.
package main

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// AdminDatabaseDefault is the reserved database name that switches a
// client into admin SQL mode. Matches PgBouncer's convention exactly
// so existing operator muscle memory works.
const AdminDatabaseDefault = "pgbouncer"

// adminSessionHandler builds the per-connection admin loop. Closes
// over the pool registry so SHOW POOLS, PAUSE, etc. see the live set.
func adminSessionHandler(registry *PoolRegistry) func(pg *pgproto3.Backend) {
	return func(pg *pgproto3.Backend) {
		// The relay skeleton is stripped down: no backend, no pool
		// acquire — every Query is answered synchronously from
		// in-process state.
		for {
			msg, err := pg.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Terminate:
				return
			case *pgproto3.Query:
				handleAdminQuery(pg, registry, m.String)
			case *pgproto3.Sync:
				// Extended-protocol clients (psql -c uses simple, but
				// pgx defaults to extended) send Sync after each
				// batch. Nothing to flush — just reply with RFQ.
				sendReadyForQuery(pg)
			case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe,
				*pgproto3.Execute, *pgproto3.Close, *pgproto3.Flush:
				// Extended protocol messages: acknowledge with the
				// matching *Complete message so the client's state
				// machine advances. We don't actually support
				// prepared statements in admin mode, but for the
				// simple SHOW/PAUSE commands even naive extended
				// clients need at least ParseComplete/BindComplete.
				handleAdminExtendedMsg(pg, m)
			default:
				// Unknown message type — just reply with an empty RFQ
				// so the client doesn't hang.
				sendReadyForQuery(pg)
			}
		}
	}
}

// handleAdminQuery parses and dispatches one SQL string. Errors are
// serialized as ErrorResponse; every path ends with ReadyForQuery.
func handleAdminQuery(pg *pgproto3.Backend, registry *PoolRegistry, sql string) {
	trimmed := strings.TrimRight(strings.TrimSpace(sql), ";")
	upper := strings.ToUpper(trimmed)

	switch {
	case upper == "SHOW POOLS":
		sendShowPools(pg, registry)
	case upper == "SHOW STATS":
		sendShowStats(pg, registry)
	case upper == "SHOW CLIENTS":
		sendShowClients(pg)
	case upper == "SHOW SERVERS":
		sendShowServers(pg, registry)
	case upper == "SHOW DATABASES":
		sendShowDatabases(pg, registry)
	case upper == "SHOW VERSION":
		sendSingleColumnRow(pg, "version", []string{"pgman 1.0 (PgBouncer-compatible admin)"}, "SHOW")
	case upper == "SHOW LISTS":
		sendShowLists(pg, registry)
	case strings.HasPrefix(upper, "PAUSE"):
		auditLog("admin_cmd", "cmd", trimmed)
		handlePauseCmd(pg, registry, trimmed)
	case strings.HasPrefix(upper, "RESUME"):
		auditLog("admin_cmd", "cmd", trimmed)
		handleResumeCmd(pg, registry, trimmed)
	case strings.HasPrefix(upper, "RECONNECT"):
		auditLog("admin_cmd", "cmd", trimmed)
		handleReconnectCmd(pg, registry, trimmed)
	default:
		sendError(pg, "42601", fmt.Sprintf("pgman admin: unsupported command %q", trimmed))
	}
	sendReadyForQuery(pg)
}

// handleAdminExtendedMsg emits the minimum ack sequence for a bare
// extended-protocol message from admin clients. Not a full prepared
// statement engine — just enough so a curious pgx client doesn't
// deadlock waiting for ParseComplete.
func handleAdminExtendedMsg(pg *pgproto3.Backend, msg pgproto3.FrontendMessage) {
	switch msg.(type) {
	case *pgproto3.Parse:
		pg.Send(&pgproto3.ParseComplete{})
	case *pgproto3.Bind:
		pg.Send(&pgproto3.BindComplete{})
	case *pgproto3.Describe:
		pg.Send(&pgproto3.NoData{})
	case *pgproto3.Execute:
		pg.Send(&pgproto3.CommandComplete{CommandTag: []byte("SHOW")})
	case *pgproto3.Close:
		pg.Send(&pgproto3.CloseComplete{})
	}
	_ = pg.Flush()
}

// ---- Command handlers ----------------------------------------------

func handlePauseCmd(pg *pgproto3.Backend, registry *PoolRegistry, cmd string) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(cmd), "PAUSE"))
	if name == "" {
		for _, p := range registry.Pools() {
			p.Pause()
		}
		sendCommandComplete(pg, "PAUSE")
		return
	}
	// Case-insensitive match against configured pool names.
	realName := findPoolName(registry, name)
	if realName == "" {
		sendError(pg, "3D000", fmt.Sprintf("pool %q not found", name))
		return
	}
	p, _ := registry.Get(realName)
	p.Pause()
	sendCommandComplete(pg, "PAUSE")
}

func handleResumeCmd(pg *pgproto3.Backend, registry *PoolRegistry, cmd string) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(cmd), "RESUME"))
	if name == "" {
		for _, p := range registry.Pools() {
			p.Resume()
		}
		sendCommandComplete(pg, "RESUME")
		return
	}
	realName := findPoolName(registry, name)
	if realName == "" {
		sendError(pg, "3D000", fmt.Sprintf("pool %q not found", name))
		return
	}
	p, _ := registry.Get(realName)
	p.Resume()
	sendCommandComplete(pg, "RESUME")
}

func handleReconnectCmd(pg *pgproto3.Backend, registry *PoolRegistry, cmd string) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(cmd), "RECONNECT"))
	if name == "" {
		for _, p := range registry.Pools() {
			p.Reconnect()
		}
		sendCommandComplete(pg, "RECONNECT")
		return
	}
	realName := findPoolName(registry, name)
	if realName == "" {
		sendError(pg, "3D000", fmt.Sprintf("pool %q not found", name))
		return
	}
	p, _ := registry.Get(realName)
	p.Reconnect()
	sendCommandComplete(pg, "RECONNECT")
}

func findPoolName(registry *PoolRegistry, wanted string) string {
	for _, n := range registry.Names() {
		if strings.EqualFold(n, wanted) {
			return n
		}
	}
	return ""
}

// ---- SHOW handlers -------------------------------------------------

func sendShowPools(pg *pgproto3.Backend, registry *PoolRegistry) {
	cols := []string{"database", "cl_active", "cl_waiting", "sv_active", "sv_idle", "maxwait", "pool_mode", "paused"}
	sendRowDescription(pg, cols)

	for _, name := range registry.Names() {
		p, _ := registry.Get(name)
		s := p.Stats()
		paused := "no"
		if p.IsPaused() {
			paused = "yes"
		}
		row := [][]byte{
			[]byte(name),
			itoa(0), // cl_active — we don't track per-DB client counts yet
			itoa(s.Waiting),
			itoa(s.InUse),
			itoa(s.Idle),
			itoa(int(s.WaitTime.Milliseconds())),
			[]byte("transaction"),
			[]byte(paused),
		}
		sendDataRow(pg, row)
	}
	sendCommandComplete(pg, "SHOW")
}

func sendShowStats(pg *pgproto3.Backend, registry *PoolRegistry) {
	cols := []string{"database", "total_wait_ms", "total_waits", "total_discards", "total_dial_errors", "total_reaped", "idle", "in_use", "limit"}
	sendRowDescription(pg, cols)

	for _, name := range registry.Names() {
		p, _ := registry.Get(name)
		s := p.Stats()
		row := [][]byte{
			[]byte(name),
			itoa64(s.WaitTime.Milliseconds()),
			itoa64(s.WaitCount),
			itoa64(s.Discards),
			itoa64(s.DialErrors),
			itoa64(s.Reaped),
			itoa(s.Idle),
			itoa(s.InUse),
			itoa(s.Limit),
		}
		sendDataRow(pg, row)
	}
	sendCommandComplete(pg, "SHOW")
}

func sendShowClients(pg *pgproto3.Backend) {
	cols := []string{"pid", "user", "database", "state"}
	sendRowDescription(pg, cols)

	// Walk the session shards. Each session has user/database/PID.
	for _, s := range listSessions() {
		state := "idle"
		if s.Active {
			state = "active"
		}
		sendDataRow(pg, [][]byte{
			itoa(int(s.PID)),
			[]byte(s.User),
			[]byte(s.Database),
			[]byte(state),
		})
	}
	sendCommandComplete(pg, "SHOW")
}

func sendShowServers(pg *pgproto3.Backend, registry *PoolRegistry) {
	cols := []string{"database", "state", "count"}
	sendRowDescription(pg, cols)

	for _, name := range registry.Names() {
		p, _ := registry.Get(name)
		s := p.Stats()
		sendDataRow(pg, [][]byte{[]byte(name), []byte("idle"), itoa(s.Idle)})
		sendDataRow(pg, [][]byte{[]byte(name), []byte("active"), itoa(s.InUse)})
	}
	sendCommandComplete(pg, "SHOW")
}

func sendShowDatabases(pg *pgproto3.Backend, registry *PoolRegistry) {
	cols := []string{"name", "host", "port", "database", "pool_size", "pool_mode"}
	sendRowDescription(pg, cols)

	for name, cfg := range registry.Configs() {
		host, port := splitAddr(cfg.BackendAddr)
		sendDataRow(pg, [][]byte{
			[]byte(name),
			[]byte(host),
			[]byte(port),
			[]byte(name),
			itoa(cfg.Limit),
			[]byte("transaction"),
		})
	}
	sendCommandComplete(pg, "SHOW")
}

func sendShowLists(pg *pgproto3.Backend, registry *PoolRegistry) {
	// PgBouncer's SHOW LISTS returns one row per named list with the
	// current count. We synthesize a subset relevant to pgman.
	cols := []string{"list", "items"}
	sendRowDescription(pg, cols)

	totalIdle, totalActive := 0, 0
	for _, p := range registry.Pools() {
		s := p.Stats()
		totalIdle += s.Idle
		totalActive += s.InUse
	}

	rows := [][2]interface{}{
		{"pools", len(registry.Pools())},
		{"servers_idle", totalIdle},
		{"servers_used", totalActive},
		{"clients", len(listSessions())},
	}
	for _, r := range rows {
		sendDataRow(pg, [][]byte{[]byte(r[0].(string)), itoa(r[1].(int))})
	}
	sendCommandComplete(pg, "SHOW")
}

// ---- Wire helpers --------------------------------------------------

// sendRowDescription emits a minimal-typed RowDescription (all TEXT,
// oid=25). PgBouncer uses the same trick for its admin console —
// clients don't care about precise types for these tables.
func sendRowDescription(pg *pgproto3.Backend, cols []string) {
	fields := make([]pgproto3.FieldDescription, len(cols))
	for i, name := range cols {
		fields[i] = pgproto3.FieldDescription{
			Name:                 []byte(name),
			TableOID:             0,
			TableAttributeNumber: 0,
			DataTypeOID:          25, // TEXT
			DataTypeSize:         -1,
			TypeModifier:         -1,
			Format:               0, // text
		}
	}
	pg.Send(&pgproto3.RowDescription{Fields: fields})
}

func sendDataRow(pg *pgproto3.Backend, values [][]byte) {
	pg.Send(&pgproto3.DataRow{Values: values})
}

func sendCommandComplete(pg *pgproto3.Backend, tag string) {
	pg.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
}

func sendReadyForQuery(pg *pgproto3.Backend) {
	pg.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	_ = pg.Flush()
}

func sendError(pg *pgproto3.Backend, code, msg string) {
	pg.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: code, Message: msg})
}

// sendSingleColumnRow — helper for tiny SHOW commands (SHOW VERSION).
func sendSingleColumnRow(pg *pgproto3.Backend, colName string, rows []string, tag string) {
	sendRowDescription(pg, []string{colName})
	for _, v := range rows {
		sendDataRow(pg, [][]byte{[]byte(v)})
	}
	sendCommandComplete(pg, tag)
}

func itoa(n int) []byte     { return []byte(fmt.Sprintf("%d", n)) }
func itoa64(n int64) []byte { return []byte(fmt.Sprintf("%d", n)) }

func splitAddr(addr string) (host, port string) {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i], addr[i+1:]
	}
	return addr, ""
}
