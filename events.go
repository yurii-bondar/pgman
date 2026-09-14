package main

import (
	"sync"
	"time"
)

// Event is one pool.EventFunc firing, tagged with which pool it came from —
// the pool package itself doesn't know its own registry name.
type Event struct {
	Time time.Time
	Pool string
	Kind string // "discard" | "dial_error"
	Err  string
}

// EventLog is a small bounded ring buffer of recent pool events — enough
// for an admin UI's "what just broke" tail, not a general-purpose log
// store. Oldest entries are silently dropped past capacity.
type EventLog struct {
	mu       sync.Mutex
	events   []Event
	capacity int
}

func NewEventLog(capacity int) *EventLog {
	return &EventLog{capacity: capacity}
}

func (l *EventLog) Record(pool, kind string, err error) {
	e := Event{Time: time.Now(), Pool: pool, Kind: kind}
	if err != nil {
		e.Err = err.Error()
	}

	l.mu.Lock()
	l.events = append(l.events, e)
	if over := len(l.events) - l.capacity; over > 0 {
		l.events = l.events[over:]
	}
	l.mu.Unlock()
}

// Recent returns up to the last N events, most recent first.
func (l *EventLog) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]Event, len(l.events))
	copy(out, l.events)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
