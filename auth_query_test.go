package main

import (
	"strings"
	"testing"
	"time"

	"github.com/xdg-go/scram"
)

// unreachableProvider points at an address nothing listens on, so any
// attempt to run the real SELECT fails fast and visibly. That is what
// makes the cache assertions below meaningful: a served request proves
// the cache answered, because the database could not have.
func unreachableProvider(t *testing.T, ttl time.Duration) *AuthQueryProvider {
	t.Helper()
	return NewAuthQueryProvider(
		"postgres://nobody:nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1",
		"", ttl)
}

func TestNewAuthQueryProviderDefaults(t *testing.T) {
	p := NewAuthQueryProvider("postgres://x/y", "", 0)

	// The default has to match pg_shadow's shape, because that is what
	// the documented auth_user grant gives access to.
	if !strings.Contains(p.query, "pg_shadow") || !strings.Contains(p.query, "$1") {
		t.Errorf("default query = %q, want a pg_shadow lookup bound on $1", p.query)
	}
	if p.ttl != 60*time.Second {
		t.Errorf("default ttl = %v, want 60s", p.ttl)
	}

	custom := NewAuthQueryProvider("postgres://x/y", "SELECT a, b FROM t WHERE a = $1", time.Second)
	if custom.query != "SELECT a, b FROM t WHERE a = $1" {
		t.Errorf("explicit query was overwritten: %q", custom.query)
	}
	if custom.ttl != time.Second {
		t.Errorf("explicit ttl was overwritten: %v", custom.ttl)
	}
}

// TestAuthQueryLookupServesFromCache is the property the whole cache
// exists for: a login burst must not turn into one pg_shadow SELECT per
// connection.
func TestAuthQueryLookupServesFromCache(t *testing.T) {
	p := unreachableProvider(t, time.Hour)

	want := scram.StoredCredentials{Salt: "salt", Iters: 4096}
	p.mu.Lock()
	p.cache["alice"] = cacheEntry{creds: want, expiresAt: time.Now().Add(time.Hour)}
	p.mu.Unlock()

	got, err := p.Lookup("alice")
	if err != nil {
		t.Fatalf("Lookup: %v (a cache hit must not touch the database)", err)
	}
	if got.Salt != want.Salt || got.Iters != want.Iters {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

// TestAuthQueryLookupRefetchesAfterTTL: the TTL is what makes a password
// rotation take effect within a minute instead of never.
func TestAuthQueryLookupRefetchesAfterTTL(t *testing.T) {
	p := unreachableProvider(t, time.Hour)

	p.mu.Lock()
	p.cache["alice"] = cacheEntry{
		creds:     scram.StoredCredentials{Salt: "stale"},
		expiresAt: time.Now().Add(-time.Second), // already expired
	}
	p.mu.Unlock()

	// With the entry expired the provider must go to the database,
	// which is unreachable — so an error here is the success condition.
	if _, err := p.Lookup("alice"); err == nil {
		t.Fatal("an expired entry was served from cache instead of being re-fetched")
	}
}

// TestAuthQueryLookupDoesNotCacheFailures: caching a transient backend
// error would lock a user out for the whole TTL, turning a one-second
// blip into a minute-long outage for them.
func TestAuthQueryLookupDoesNotCacheFailures(t *testing.T) {
	p := unreachableProvider(t, time.Hour)

	if _, err := p.Lookup("bob"); err == nil {
		t.Fatal("expected the lookup to fail against an unreachable backend")
	}

	p.mu.Lock()
	_, cached := p.cache["bob"]
	p.mu.Unlock()
	if cached {
		t.Error("a failed lookup was cached; the user would stay locked out for the TTL")
	}
}

func TestAuthQueryInvalidateDropsEntry(t *testing.T) {
	p := unreachableProvider(t, time.Hour)

	p.mu.Lock()
	p.cache["carol"] = cacheEntry{expiresAt: time.Now().Add(time.Hour)}
	p.mu.Unlock()

	p.Invalidate("carol")

	p.mu.Lock()
	_, still := p.cache["carol"]
	p.mu.Unlock()
	if still {
		t.Error("Invalidate left the entry in place; a rotated password would keep working")
	}
}

// TestAuthQueryNilProviderIsSafe: SCRAMAuth holds this as an optional
// dependency, so a nil receiver is reachable whenever auth_query is not
// configured.
func TestAuthQueryNilProviderIsSafe(t *testing.T) {
	var p *AuthQueryProvider

	if _, err := p.Lookup("alice"); err == nil {
		t.Error("nil provider should report that auth_query is not configured")
	}
	p.Invalidate("alice") // must not panic
}
