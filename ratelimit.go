package main

import (
	"container/list"
	"sync"
	"time"
)

// authLimiter blocks repeated authentication failures from the same
// remote address — defense in depth on top of SCRAM's own resistance to
// offline guessing.
//
// Bounded LRU: the previous unbounded map was a straightforward OOM
// vector under IP-rotation credential stuffing. Evicting the oldest
// entry once we hit capacity gives up the *memory of an old attacker*
// (they'll get their fresh chance to fail again), which is the right
// trade-off: we can't tell an attacker cycling addresses from a NAT
// gateway holding a single one for hours, so unbounded retention has no
// defensive value that offsets the DoS surface.
type authLimiter struct {
	mu       sync.Mutex
	state    map[string]*limiterEntry
	lru      *list.List // front = most recently touched, back = oldest
	capacity int
}

type limiterEntry struct {
	addr        string
	failures    int
	lockedUntil time.Time
	elem        *list.Element // pointer into lru
}

const (
	authLockThreshold = 5               // failures before any lockout kicks in
	authLockBase      = 5 * time.Second // first lockout duration
	authLockMax       = 5 * time.Minute // lockout duration cap
	authLimiterCap    = 100_000         // max distinct addresses tracked at once
)

func newAuthLimiter() *authLimiter {
	return newAuthLimiterWithCapacity(authLimiterCap)
}

func newAuthLimiterWithCapacity(capacity int) *authLimiter {
	if capacity <= 0 {
		capacity = authLimiterCap
	}
	return &authLimiter{
		state:    make(map[string]*limiterEntry),
		lru:      list.New(),
		capacity: capacity,
	}
}

// Allowed reports whether addr may attempt authentication right now.
// Reading is a touch — every check moves the entry to the front of the
// LRU, so active-but-well-behaved addresses don't get evicted just
// because they've been around a long time.
func (l *authLimiter) Allowed(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.state[addr]
	if !ok {
		return true
	}
	l.lru.MoveToFront(e.elem)
	return time.Now().After(e.lockedUntil)
}

// RecordFailure counts one failed attempt from addr, locking it out with
// exponential backoff once authLockThreshold is reached.
func (l *authLimiter) RecordFailure(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.state[addr]
	if !ok {
		e = &limiterEntry{addr: addr}
		e.elem = l.lru.PushFront(e)
		l.state[addr] = e
		l.evictIfNeeded()
	} else {
		l.lru.MoveToFront(e.elem)
	}
	e.failures++

	if e.failures >= authLockThreshold {
		shift := e.failures - authLockThreshold
		backoff := authLockBase
		for i := 0; i < shift && backoff < authLockMax; i++ {
			backoff *= 2
		}
		if backoff > authLockMax {
			backoff = authLockMax
		}
		e.lockedUntil = time.Now().Add(backoff)
	}
}

// RecordSuccess clears addr's failure history entirely.
func (l *authLimiter) RecordSuccess(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.state[addr]; ok {
		l.lru.Remove(e.elem)
		delete(l.state, addr)
	}
}

// evictIfNeeded trims the LRU back to capacity. Called only from the
// hot RecordFailure path, so eviction is amortized — no separate reaper
// goroutine needed.
func (l *authLimiter) evictIfNeeded() {
	for len(l.state) > l.capacity {
		oldest := l.lru.Back()
		if oldest == nil {
			return
		}
		e := oldest.Value.(*limiterEntry)
		l.lru.Remove(oldest)
		delete(l.state, e.addr)
	}
}

// Size returns the current entry count — for metrics/tests only, not
// hot-path use.
func (l *authLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.state)
}
