package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// adminConsoleProbe drives one client through startup against an admin
// database and reports whether the in-process admin console was entered.
//
// The router always fails, which is what an unconfigured database name
// does in production: it is the reply a denied client is supposed to
// get, so the test can tell "denied" from "routed somewhere else".
func adminConsoleProbe(t *testing.T, adminUsers []string, user string) (entered bool, reply pgproto3.BackendMessage) {
	t.Helper()

	var reached atomic.Bool
	opts := defaultRuntimeOpts()
	opts.adminDatabase = "pgbouncer"
	opts.adminUsers = adminUserSet(adminUsers)
	opts.adminSession = func(pg *pgproto3.Backend) {
		reached.Store(true)
		// Behave like the real console: answer nothing, wait for the
		// client to hang up, so handleConn returns on its own.
		for {
			if _, err := pg.Receive(); err != nil {
				return
			}
		}
	}

	clientConn, proxyConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnWithOpts(proxyConn, staticRouter{err: fmt.Errorf("no such database")},
			TrustAuth{}, nil, newAuthLimiter(), opts)
	}()

	startup, _ := (&pgproto3.StartupMessage{
		ProtocolVersion: 196608,
		Parameters:      map[string]string{"user": user, "database": "pgbouncer"},
	}).Encode(nil)
	if _, err := clientConn.Write(startup); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	fe := pgproto3.NewFrontend(clientConn, clientConn)
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receive first reply: %v", err)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return")
	}
	return reached.Load(), msg
}

// TestAdminConsoleDeniedForUnlistedUser is the regression test for the
// privilege escalation this allowlist exists to close: before it, any
// client that passed plain auth could open database=pgbouncer and PAUSE
// every pool — a total outage issued by an ordinary tenant.
func TestAdminConsoleDeniedForUnlistedUser(t *testing.T) {
	entered, reply := adminConsoleProbe(t, []string{"ops"}, "app")

	if entered {
		t.Fatal("a user absent from admin_users reached the admin console")
	}
	errResp, ok := reply.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected the routing ErrorResponse, got %T", reply)
	}
	// The denial must be indistinguishable from "that database does not
	// exist" — anything else confirms the console is there and turns
	// the reply into an oracle for which users are admins.
	if errResp.Code != "3D000" {
		t.Errorf("SQLSTATE = %s, want 3D000 (same as any unknown database)", errResp.Code)
	}
}

// TestAdminConsoleDeniedWhenAllowlistEmpty covers the default: an
// operator who never sets admin_users gets a console nobody can open,
// not one everybody can.
func TestAdminConsoleDeniedWhenAllowlistEmpty(t *testing.T) {
	entered, reply := adminConsoleProbe(t, nil, "ops")

	if entered {
		t.Fatal("an empty admin_users must deny everyone, but the console was entered")
	}
	if _, ok := reply.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected an ErrorResponse, got %T", reply)
	}
}

// TestAdminConsoleAllowsListedUser is the other half of the contract:
// the allowlist must not lock out the operator it was written for.
func TestAdminConsoleAllowsListedUser(t *testing.T) {
	entered, reply := adminConsoleProbe(t, []string{"ops", "alice"}, "alice")

	if !entered {
		t.Fatalf("a user listed in admin_users was denied the console (first reply %T)", reply)
	}
	// The console answers a normal startup, so the first message back
	// is the fake handshake, never an error.
	if errResp, ok := reply.(*pgproto3.ErrorResponse); ok {
		t.Fatalf("expected a handshake, got ErrorResponse %s: %s", errResp.Code, errResp.Message)
	}
}

func TestAdminUserSet(t *testing.T) {
	if set := adminUserSet(nil); set != nil {
		t.Errorf("empty list should produce a nil set, got %v", set)
	}
	// Blank entries are a YAML typo ("admin_users:\n  - "), not a user
	// named "" — and the startup path compares against a username that
	// is empty whenever the client omits it.
	if set := adminUserSet([]string{""}); set[""] {
		t.Error("a blank admin_users entry must not authorise the empty username")
	}
	set := adminUserSet([]string{"ops"})
	if !set["ops"] || set["app"] {
		t.Errorf("set = %v, want exactly {ops}", set)
	}
}
