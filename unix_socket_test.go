package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// shortTempDir returns a temp directory with a deliberately short path.
// Unix socket paths are capped at ~104 bytes by the kernel, and Go's
// t.TempDir() derives its name from the test name — long enough to blow
// that budget and produce an "invalid argument" that looks like a bug in
// the code under test.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pgs")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestOpenUnixSocketUsesLibpqPathConvention(t *testing.T) {
	dir := shortTempDir(t)

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	// libpq derives the socket name from the port, which is how
	// `psql -h /tmp -p 6435` finds it without being told the filename.
	want := filepath.Join(dir, ".s.PGSQL.6435")
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("socket file not created: %v", err)
	}
}

func TestOpenUnixSocketDefaultsPortWhenAddrHasNone(t *testing.T) {
	dir := shortTempDir(t)

	ln, path, err := openUnixSocket(dir, "", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	if want := filepath.Join(dir, ".s.PGSQL.5432"); path != want {
		t.Errorf("path = %q, want %q (5432 is the documented fallback)", path, want)
	}
}

// TestOpenUnixSocketAppliesMode matters because the socket's filesystem
// mode *is* the access control for local clients — with HBA
// METHOD=peer there is no password exchange behind it.
func TestOpenUnixSocketAppliesMode(t *testing.T) {
	dir := shortTempDir(t)

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("mode = %04o, want 0700", got)
	}
}

// TestOpenUnixSocketUnparseableModeFallsBackToDefault pins the
// documented behaviour. It is also worth knowing that the fallback is
// world-writable: a typo in unix_socket_mode silently widens access
// rather than failing the start.
func TestOpenUnixSocketUnparseableModeFallsBackToDefault(t *testing.T) {
	dir := shortTempDir(t)

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "not-an-octal-number")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o777 {
		t.Errorf("mode = %04o, want 0777 (documented fallback)", got)
	}
}

// TestOpenUnixSocketRemovesStaleFile is the restart path: bind(2) fails
// if the path is occupied, so a socket left behind by a crashed process
// would make every subsequent start fail until someone deleted it by
// hand.
func TestOpenUnixSocketRemovesStaleFile(t *testing.T) {
	dir := shortTempDir(t)
	stale := filepath.Join(dir, ".s.PGSQL.6435")

	// Simulate the leftover: a real socket whose owner is gone.
	first, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatalf("create stale socket: %v", err)
	}
	// Close the listener but leave the file — Go's unix listener unlinks
	// on Close, so recreate the file to model a hard crash.
	_ = first.Close()
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatalf("recreate stale file: %v", err)
	}

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket over a stale file: %v", err)
	}
	defer ln.Close()
	if path != stale {
		t.Errorf("path = %q, want %q", path, stale)
	}
}

func TestOpenUnixSocketCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "nested")

	ln, _, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		t.Errorf("socket directory was not created: err=%v", err)
	}
}

// TestOpenUnixSocketAcceptsConnections is the end-to-end check that the
// returned listener is actually usable, not merely constructed.
func TestOpenUnixSocketAcceptsConnections(t *testing.T) {
	dir := shortTempDir(t)

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err != nil {
		t.Fatalf("openUnixSocket: %v", err)
	}
	defer ln.Close()

	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if c != nil {
			_ = c.Close()
		}
		accepted <- err
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	defer client.Close()

	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
}
