package main

import (
	"errors"
	"sync"
	"testing"
)

func TestEventLogRecordAndRecentMostRecentFirst(t *testing.T) {
	l := NewEventLog(10)
	l.Record("pool-a", "discard", nil)
	l.Record("pool-b", "dial_error", errors.New("boom"))

	got := l.Recent()
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	if got[0].Pool != "pool-b" || got[0].Kind != "dial_error" || got[0].Err != "boom" {
		t.Errorf("most recent event wrong: %+v", got[0])
	}
	if got[1].Pool != "pool-a" || got[1].Kind != "discard" || got[1].Err != "" {
		t.Errorf("older event wrong: %+v", got[1])
	}
}

func TestEventLogBoundedCapacity(t *testing.T) {
	l := NewEventLog(3)
	for i := 0; i < 10; i++ {
		l.Record("p", "discard", nil)
	}
	got := l.Recent()
	if len(got) != 3 {
		t.Fatalf("expected capacity to cap Recent() at 3, got %d", len(got))
	}
}

func TestEventLogEmpty(t *testing.T) {
	l := NewEventLog(5)
	if got := l.Recent(); len(got) != 0 {
		t.Fatalf("expected no events, got %d", len(got))
	}
}

func TestEventLogConcurrentRecord(t *testing.T) {
	l := NewEventLog(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Record("p", "discard", nil)
		}()
	}
	wg.Wait()
	if got := len(l.Recent()); got != 50 {
		t.Fatalf("expected 50 events after concurrent recording, got %d", got)
	}
}
