// Package main — tracked-parameter replay (application_name, TimeZone,
// client_encoding, etc.) on new backend Acquire in transaction mode.
//
// Without this, when the same client sends two queries in a row and
// they land on two different backends, only the FIRST backend has the
// client's application_name / TimeZone / DateStyle applied — the second
// gets its process-wide defaults. That breaks pg_stat_activity
// attribution, breaks timezone-sensitive reads, and breaks any tool
// (Django, ActiveRecord, etc.) that relies on session GUCs surviving
// across autocommit transactions.
//
// PgBouncer's equivalent is `track_extra_parameters`.
package main

import (
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgproto3"
)

// extractTrackedParams filters the client's StartupMessage
// parameters down to just the ones the operator wants replayed.
// Comparison is case-insensitive (Postgres GUC names are), but the
// original casing from the startup is preserved in the emitted SET
// so log lines / SHOW output match what the client sent.
func extractTrackedParams(startup map[string]string, whitelist []string) []trackedParam {
	if len(startup) == 0 || len(whitelist) == 0 {
		return nil
	}
	// Build a case-insensitive lookup once.
	want := make(map[string]struct{}, len(whitelist))
	for _, name := range whitelist {
		if name == "" || name == "-" {
			continue
		}
		want[strings.ToLower(name)] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}

	// Preserve whitelist order so replay is deterministic — some GUCs
	// (e.g. IntervalStyle → DateStyle) have interdependencies.
	var out []trackedParam
	for _, name := range whitelist {
		if name == "" || name == "-" {
			continue
		}
		// Startup keys are also case-insensitive by Postgres rules,
		// but pgx sends lowercase for the standard ones. Try both.
		if v, ok := startup[name]; ok && v != "" {
			out = append(out, trackedParam{Name: name, Value: v})
			continue
		}
		if v, ok := startup[strings.ToLower(name)]; ok && v != "" {
			out = append(out, trackedParam{Name: name, Value: v})
		}
	}
	return out
}

// applyTrackedParams sends one silent SET statement to the backend and
// drains the response up to (and including) ReadyForQuery. Errors are
// returned; the caller decides whether to Discard the backend.
//
// We batch every param into a single Query (SQL supports it: "SET a=x;
// SET b=y") so this is exactly one round trip regardless of how many
// params we're replaying. Values are single-quoted with ” escaping,
// which is the SQL-standard literal form and matches what libpq / pgx
// generate for their own SET emissions.
func applyTrackedParams(fe *pgproto3.Frontend, params []trackedParam) error {
	if len(params) == 0 {
		return nil
	}
	var sb strings.Builder
	for i, p := range params {
		if i > 0 {
			sb.WriteByte(';')
		}
		sb.WriteString(`SET `)
		sb.WriteString(quoteIdent(p.Name))
		sb.WriteString(` = `)
		sb.WriteString(quoteLiteral(p.Value))
	}

	fe.Send(&pgproto3.Query{String: sb.String()})
	if err := fe.Flush(); err != nil {
		return fmt.Errorf("flush SET batch: %w", err)
	}

	// Drain silently until ReadyForQuery — any ErrorResponse aborts
	// with the message so the caller can log & Discard.
	for {
		msg, err := fe.Receive()
		if err != nil {
			return fmt.Errorf("receive SET reply: %w", err)
		}
		if er, ok := msg.(*pgproto3.ErrorResponse); ok {
			return fmt.Errorf("SET rejected by backend: %s (SQLSTATE %s)", er.Message, er.Code)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return nil
		}
	}
}

// quoteIdent wraps a GUC name in double quotes and escapes embedded
// quotes. Standard PG identifier quoting. Guards against a malicious
// startup param like `foo"; DROP TABLE ...` (which would already fail
// as a GUC name, but defense in depth is cheap).
func quoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// quoteLiteral wraps a value in single quotes and escapes embedded
// single quotes. Standard SQL literal escaping. Postgres will also
// accept E'...' for backslash escapes, but plain ” doubling is safer
// (works regardless of standard_conforming_strings state).
func quoteLiteral(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `''`) + `'`
}
