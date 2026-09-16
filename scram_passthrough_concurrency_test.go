package main

// SCRAM pass-through with several users logging in at the same time.
//
// Every other test of this feature is sequential: alice logs in, then
// bob, then alice again. That proves the identities are kept apart, but
// it cannot prove they are kept apart *under concurrency*, and this is
// the one place in pgman where losing that race is not a dropped
// connection — it is a client's statements running as somebody else's
// role. Row-level security, `GRANT`, and every audit trail on the
// database are downstream of getting it right.
//
// The store is a plain map behind an RWMutex, so the failure modes worth
// covering are the ones a mutex does not rule out on its own: a write
// racing a read on the same key (password rotation while a session is
// routing), and a reader receiving another user's entry.

import (
	"fmt"
	"sync"
	"testing"

	"github.com/xdg-go/scram"
)

// TestClientKeyStoreKeepsUsersApartUnderConcurrency writes and reads
// many users at once and checks nobody sees anyone else's key.
//
// Each user's key is derived from its own name, so a crossed wire is
// detectable rather than merely suspected: the assertion names both the
// user asked for and the user whose key came back.
func TestClientKeyStoreKeepsUsersApartUnderConcurrency(t *testing.T) {
	const (
		users   = 64
		rounds  = 200
		writers = 8
	)

	store := newClientKeyStore()
	keyFor := func(user string) []byte { return []byte("key-for-" + user) }

	var wg sync.WaitGroup

	// Writers: every user logging in repeatedly, which is what a
	// reconnecting client or a password rotation looks like.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(shard int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				for u := shard; u < users; u += writers {
					user := fmt.Sprintf("user%03d", u)
					store.remember(user, keyFor(user), scram.StoredCredentials{
						KeyFactors: scram.KeyFactors{Salt: user, Iters: 4096},
					})
				}
			}
		}(w)
	}

	// Readers: the routing path, asking "whose key is this" while the
	// writers are still going.
	mismatches := make([]string, users)
	for u := 0; u < users; u++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := fmt.Sprintf("user%03d", idx)
			want := string(keyFor(user))
			for r := 0; r < rounds; r++ {
				pc, ok := store.lookup(user)
				if !ok {
					// Legitimate before that user's first write lands.
					continue
				}
				if got := string(pc.clientKey); got != want {
					mismatches[idx] = fmt.Sprintf("lookup(%s) returned key %q, want %q", user, got, want)
					return
				}
				// The verifier travels with the key and is used to
				// check the server's signature; a torn pair would
				// authenticate against the wrong salt.
				if pc.creds.Salt != user {
					mismatches[idx] = fmt.Sprintf("lookup(%s) returned a key paired with salt %q", user, pc.creds.Salt)
					return
				}
			}
		}(u)
	}

	wg.Wait()

	for _, m := range mismatches {
		if m != "" {
			t.Error(m)
		}
	}

	// And every user must be present and correct once the dust settles.
	for u := 0; u < users; u++ {
		user := fmt.Sprintf("user%03d", u)
		pc, ok := store.lookup(user)
		if !ok {
			t.Fatalf("%s is missing from the store after all writes completed", user)
		}
		if string(pc.clientKey) != string(keyFor(user)) {
			t.Errorf("%s ended up holding the wrong key", user)
		}
	}
}

// TestClientKeyStoreHasAgreesWithLookupUnderConcurrency pins the
// consistency of the two accessors.
//
// `has` is what backendIdentityFor consults to decide whether a user
// gets its own backend identity at all; `lookup` is what the dialer
// then uses to authenticate. If those two can ever disagree, a session
// is routed to a per-user pool whose credential does not exist, and the
// user silently falls back to the shared role — the exact outcome
// pass-through exists to prevent.
func TestClientKeyStoreHasAgreesWithLookupUnderConcurrency(t *testing.T) {
	store := newClientKeyStore()

	const users = 32
	stop := make(chan struct{})

	// Two WaitGroups, not one. The writer runs until told to stop and
	// the readers stop on their own, so waiting for both together
	// deadlocks: the signal that stops the writer only comes after the
	// readers have finished. It did exactly that on the first run.
	var writer, readers sync.WaitGroup

	writer.Add(1)
	go func() {
		defer writer.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			user := fmt.Sprintf("user%02d", i%users)
			store.remember(user, []byte("k"), scram.StoredCredentials{})
		}
	}()

	disagreements := make([]int, users)
	for u := 0; u < users; u++ {
		readers.Add(1)
		go func(idx int) {
			defer readers.Done()
			user := fmt.Sprintf("user%02d", idx)
			for r := 0; r < 5000; r++ {
				// has() must never claim a user the store cannot then
				// produce. The reverse (lookup succeeding after has
				// said no) is fine — a login landed in between.
				if store.has(user) {
					if _, ok := store.lookup(user); !ok {
						disagreements[idx]++
					}
				}
			}
		}(u)
	}

	readers.Wait()
	close(stop)
	writer.Wait()

	for u, n := range disagreements {
		if n > 0 {
			t.Errorf("user%02d: has() said yes but lookup() said no %d times", u, n)
		}
	}
}

// TestClientKeyStoreNilIsConcurrencySafe: the store is nil whenever no
// pool enables pass-through, and the accessors are called from every
// session's routing path regardless. Nil-safety is already covered
// sequentially; this is here because the nil check and the mutex are
// two different mechanisms and only one of them is exercised when the
// store is absent.
func TestClientKeyStoreNilIsConcurrencySafe(t *testing.T) {
	var store *clientKeyStore

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			user := fmt.Sprintf("user%02d", idx)
			for r := 0; r < 1000; r++ {
				store.remember(user, []byte("k"), scram.StoredCredentials{})
				if _, ok := store.lookup(user); ok {
					t.Errorf("a nil store returned a credential for %s", user)
					return
				}
				if store.has(user) {
					t.Errorf("a nil store claims to hold %s", user)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
