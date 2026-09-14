package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fakeDialer(t *testing.T, calls *int32) Dialer {
	return func(ctx context.Context) (net.Conn, error) {
		atomic.AddInt32(calls, 1)
		client, server := net.Pipe()
		go io.Copy(io.Discard, server)
		t.Cleanup(func() {
			client.Close()
			server.Close()
		})
		return client, nil
	}
}

func TestAcquireBlocksAtLimit(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)
	ctx := context.Background()

	c1, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	c2, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}

	acquired := make(chan net.Conn, 1)
	go func() {
		c3, err := p.Acquire(ctx)
		if err != nil {
			t.Errorf("acquire c3: %v", err)
			return
		}
		acquired <- c3
	}()

	select {
	case <-acquired:
		t.Fatal("third Acquire returned before any Release — pool did not enforce limit 2")
	case <-time.After(100 * time.Millisecond):
	}

	p.Release(c1)

	select {
	case c3 := <-acquired:
		if c3 != c1 {
			t.Errorf("expected LIFO reuse of c1, got a different connection")
		}
	case <-time.After(time.Second):
		t.Fatal("third Acquire still blocked after Release")
	}

	p.Release(c2)
	p.Release(c1)

	if dials != 2 {
		t.Errorf("expected exactly 2 dials (pool reused released conns), got %d", dials)
	}
}

func TestDiscardFreesCapacityWithoutReuse(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	p.Discard(c1)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c2, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire after discard: %v", err)
	}
	defer p.Release(c2)

	if c2 == c1 {
		t.Error("expected a fresh connection after Discard, got the discarded one back")
	}
	if dials != 2 {
		t.Errorf("expected 2 dials (discarded conn not reused), got %d", dials)
	}
}

func TestAcquireSkipsUnhealthyIdleConnection(t *testing.T) {
	var dials, checks int32
	healthCheck := func(conn net.Conn) error {
		atomic.AddInt32(&checks, 1)
		if _, err := conn.Write([]byte("ping")); err != nil {
			return err
		}
		return nil
	}
	p := New(fakeDialer(t, &dials), 2, healthCheck, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	c1.Close() // simulate the backend dying while idle
	p.Release(c1)

	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}
	defer p.Release(c2)

	if c2 == c1 {
		t.Error("expected the dead connection to be skipped, got it back")
	}
	if checks != 1 {
		t.Errorf("expected exactly 1 health check (on the dead idle conn), got %d", checks)
	}
	if dials != 2 {
		t.Errorf("expected 2 dials (c1, then a fresh replacement for c2), got %d", dials)
	}
}

func TestStatsSnapshot(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}

	if s := p.Stats(); s.Limit != 2 || s.InUse != 2 || s.Idle != 0 {
		t.Fatalf("both held: got %+v, want Limit=2 InUse=2 Idle=0", s)
	}

	p.Release(c1)
	if s := p.Stats(); s.InUse != 1 || s.Idle != 1 {
		t.Fatalf("one released: got %+v, want InUse=1 Idle=1", s)
	}

	p.Discard(c2)
	if s := p.Stats(); s.InUse != 0 || s.Discards != 1 {
		t.Fatalf("one discarded: got %+v, want InUse=0 Discards=1", s)
	}

	if s := p.Stats(); s.WaitCount != 2 {
		t.Errorf("expected WaitCount=2 (two Acquire calls), got %d", s.WaitCount)
	}
}

func TestCloseDrainsInFlightAndRejectsNew(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 2, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	c2, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c2: %v", err)
	}
	p.Release(c2) // now idle: [c2], in-flight: [c1]

	closeErr := make(chan error, 1)
	go func() {
		closeErr <- p.Close(context.Background())
	}()

	// Close must not return while c1 is still checked out.
	select {
	case err := <-closeErr:
		t.Fatalf("Close returned early (err=%v) while a connection was still in flight", err)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := p.Acquire(context.Background()); err != ErrPoolClosed {
		t.Errorf("expected ErrPoolClosed for Acquire after Close, got %v", err)
	}

	p.Release(c1) // last in-flight connection returns

	select {
	case err := <-closeErr:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close still blocked after the last connection was released")
	}
}

func TestOnEventFiresForDiscardAndDialError(t *testing.T) {
	var dials int32
	dialShouldFail := false
	dial := func(ctx context.Context) (net.Conn, error) {
		if dialShouldFail {
			return nil, errors.New("boom")
		}
		atomic.AddInt32(&dials, 1)
		client, server := net.Pipe()
		go io.Copy(io.Discard, server)
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}

	var mu sync.Mutex
	var kinds []string
	onEvent := func(kind string, err error) {
		mu.Lock()
		kinds = append(kinds, kind)
		mu.Unlock()
	}

	p := New(dial, 1, nil, onEvent)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	p.Discard(c1)

	dialShouldFail = true
	if _, err := p.Acquire(context.Background()); err == nil {
		t.Fatal("expected dial error")
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"discard", "dial_error"}
	if len(kinds) != len(want) {
		t.Fatalf("got events %v, want %v", kinds, want)
	}
	for i, k := range want {
		if kinds[i] != k {
			t.Errorf("event %d: got %q, want %q", i, kinds[i], k)
		}
	}
}

func TestAcquireRespectsContextCancellation(t *testing.T) {
	var dials int32
	p := New(fakeDialer(t, &dials), 1, nil, nil)

	c1, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire c1: %v", err)
	}
	defer p.Release(c1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = p.Acquire(ctx)
	if err != context.DeadlineExceeded {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}
