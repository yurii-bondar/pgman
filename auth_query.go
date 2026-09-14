// Package main — auth_query provider.
//
// Instead of listing every application user's SCRAM verifier in the
// YAML config (which forces a proxy restart on every user add/remove),
// auth_query lets the proxy fetch verifiers on-demand from the real
// Postgres by running a small SELECT — typically:
//
//	SELECT usename, passwd FROM pg_shadow WHERE usename = $1
//
// The proxy connects to the backend as auth_user (a privileged role
// that has SELECT on pg_shadow) and extracts the pg-native
// SCRAM-SHA-256 verifier from `passwd`. Result is cached in-memory
// with a TTL to keep hot logins from hammering pg_shadow.
//
// PgBouncer feature parity: auth_user + auth_query + auth_query_cache.
package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/xdg-go/scram"
)

// AuthQueryProvider fetches SCRAM verifiers from a live Postgres
// instance and caches them in-memory.
type AuthQueryProvider struct {
	// dsn is the connection string used for auth lookups. Should be
	// auth_user's DSN, NOT a generic pool DSN — auth_user needs
	// SELECT on pg_shadow (typically a role granted pg_read_server_files
	// or just superuser in dev setups).
	dsn string
	// query is the SELECT — MUST return two columns (username, passwd)
	// and take exactly one bound parameter ($1) for the username.
	query string
	// ttl is how long a fetched credential stays fresh in the cache.
	// A short TTL (5-60s) is the standard PgBouncer setup — long enough
	// to absorb login bursts, short enough that password rotations
	// take effect within a minute.
	ttl time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	creds     scram.StoredCredentials
	expiresAt time.Time
}

// NewAuthQueryProvider builds an on-demand SCRAM resolver. Sensible
// defaults: PgBouncer-standard query, 60s cache TTL.
func NewAuthQueryProvider(dsn, query string, ttl time.Duration) *AuthQueryProvider {
	if query == "" {
		query = "SELECT usename, passwd FROM pg_shadow WHERE usename = $1"
	}
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &AuthQueryProvider{
		dsn:   dsn,
		query: query,
		ttl:   ttl,
		cache: make(map[string]cacheEntry),
	}
}

// Lookup returns the SCRAM verifier for user, going through cache
// first and falling back to a live SELECT. Errors are NOT cached —
// a transient backend failure shouldn't lock a user out for the TTL.
func (p *AuthQueryProvider) Lookup(user string) (scram.StoredCredentials, error) {
	if p == nil {
		return scram.StoredCredentials{}, errors.New("auth_query not configured")
	}

	// Cache hit?
	p.mu.Lock()
	if entry, ok := p.cache[user]; ok && time.Now().Before(entry.expiresAt) {
		p.mu.Unlock()
		return entry.creds, nil
	}
	p.mu.Unlock()

	// Miss: run the SELECT under a short deadline so a slow backend
	// doesn't stall login handshakes indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, p.dsn)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var username, passwd string
	err = conn.QueryRow(ctx, p.query, user).Scan(&username, &passwd)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return scram.StoredCredentials{}, fmt.Errorf("no such user")
		}
		return scram.StoredCredentials{}, fmt.Errorf("auth_query: %w", err)
	}
	if passwd == "" {
		return scram.StoredCredentials{}, fmt.Errorf("user %q has no password set", user)
	}

	// pg_shadow.passwd for SCRAM-SHA-256 rows is exactly the
	// "SCRAM-SHA-256$iters:salt$stored:server" format ParseSCRAMVerifier
	// consumes — no transformation needed. MD5 rows will fail here
	// (this proxy only speaks SCRAM), and that's the right answer:
	// silently degrading to a weaker mech is exactly the downgrade
	// vector we don't want to open.
	creds, err := ParseSCRAMVerifier(passwd)
	if err != nil {
		return scram.StoredCredentials{}, fmt.Errorf("unusable password format (not SCRAM-SHA-256?): %w", err)
	}

	// Cache the success.
	p.mu.Lock()
	p.cache[user] = cacheEntry{creds: creds, expiresAt: time.Now().Add(p.ttl)}
	p.mu.Unlock()

	return creds, nil
}

// Invalidate drops one user from the cache — useful after an admin
// password rotation so the next login re-fetches immediately without
// waiting out the TTL.
func (p *AuthQueryProvider) Invalidate(user string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	delete(p.cache, user)
	p.mu.Unlock()
}
