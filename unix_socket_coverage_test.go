package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpenUnixSocketFailsWhenDirectoryCannotBeCreated: unix_socket_dir
// is operator-supplied, and the common mistakes — a path under a file,
// a path under a directory the process cannot write — must surface as
// a named mkdir failure at startup. Returning a listener anyway, or a
// bare "invalid argument" from bind(2), sends the operator looking at
// the wrong layer.
func TestOpenUnixSocketFailsWhenDirectoryCannotBeCreated(t *testing.T) {
	parent := shortTempDir(t)
	blocker := filepath.Join(parent, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("write blocking file: %v", err)
	}

	ln, path, err := openUnixSocket(filepath.Join(blocker, "sub"), "127.0.0.1:6435", "0700")
	if err == nil {
		_ = ln.Close()
		t.Fatal("a socket directory under a regular file was accepted")
	}
	if ln != nil || path != "" {
		t.Errorf("got (%v, %q) alongside the error, want (nil, \"\")", ln, path)
	}
}

// TestOpenUnixSocketReportsUndeletableStalePath is the diagnosis path
// for the restart case. Removing the leftover socket is unconditional,
// so when the removal itself fails — a permission problem on the
// directory, or something other than a socket sitting on the path —
// the operator needs to hear about that instead of the EADDRINUSE it
// would otherwise cause one line later.
func TestOpenUnixSocketReportsUndeletableStalePath(t *testing.T) {
	dir := shortTempDir(t)

	// A non-empty directory exactly where the socket belongs: os.Remove
	// fails with something other than not-exist, which is the branch
	// under test.
	occupied := filepath.Join(dir, ".s.PGSQL.6435")
	if err := os.MkdirAll(filepath.Join(occupied, "child"), 0o755); err != nil {
		t.Fatalf("occupy socket path: %v", err)
	}

	ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", "0700")
	if err == nil {
		_ = ln.Close()
		t.Fatal("an undeletable socket path was accepted")
	}
	if ln != nil || path != "" {
		t.Errorf("got (%v, %q) alongside the error, want (nil, \"\")", ln, path)
	}
}

// TestOpenUnixSocketEmptyModeUsesDefault keeps unix_socket_mode
// optional. An unset mode has to land on the documented 0777 rather
// than on Go's own default, which would be tighter than PgBouncer's and
// would silently lock out the local clients this listener exists for.
func TestOpenUnixSocketEmptyModeUsesDefault(t *testing.T) {
	for _, modeStr := range []string{"", "   "} {
		dir := shortTempDir(t)
		ln, path, err := openUnixSocket(dir, "127.0.0.1:6435", modeStr)
		if err != nil {
			t.Fatalf("openUnixSocket(mode=%q): %v", modeStr, err)
		}
		defer ln.Close()

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o777 {
			t.Errorf("mode=%q gave %04o, want 0777", modeStr, got)
		}
	}
}

// TestOpenUnixSocketDerivesPortFromMalformedAddr: listen_addr is not
// guaranteed to be host:port — it can be a bare host, or empty when the
// TCP listener is disabled entirely. The Unix path must still be one
// libpq can find, so an unparseable port falls back to 5432 rather than
// producing a socket nobody connects to.
func TestOpenUnixSocketDerivesPortFromMalformedAddr(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", ":not-a-port", "localhost:"} {
		dir := shortTempDir(t)
		ln, path, err := openUnixSocket(dir, addr, "0700")
		if err != nil {
			t.Fatalf("openUnixSocket(addr=%q): %v", addr, err)
		}
		defer ln.Close()

		if want := filepath.Join(dir, ".s.PGSQL.5432"); path != want {
			t.Errorf("addr=%q gave path %q, want %q", addr, path, want)
		}
	}
}
