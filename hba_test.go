package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadHBAFile_BasicShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hba.conf")
	body := `
# comment line
# TYPE  DATABASE  USER  ADDRESS       METHOD
host    all       all   127.0.0.1/32  trust
hostssl app       all   10.0.0.0/8    scram-sha-256
host    all       bad   0.0.0.0/0     reject
host    all       all   all           scram-sha-256
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadHBAFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	if rules[0].Method != HBAMethodTrust {
		t.Errorf("rule[0].Method = %q, want trust", rules[0].Method)
	}
	if rules[1].Type != HBAHostSSL {
		t.Errorf("rule[1].Type = %v, want hostssl", rules[1].Type)
	}
	if rules[3].Net != nil {
		t.Errorf("rule[3] with ADDRESS=all should have Net=nil")
	}
}

func TestLoadHBAFile_MissingIsNoOp(t *testing.T) {
	rules, err := LoadHBAFile("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	if rules != nil {
		t.Fatalf("empty path should return nil rules")
	}
}

func TestLoadHBAFile_MalformedLineFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hba.conf")
	if err := os.WriteFile(path, []byte("host all all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHBAFile(path); err == nil {
		t.Fatal("expected error on too-few fields")
	}
}

func TestMatchHBA_FirstMatchWins(t *testing.T) {
	rules := []HBARule{
		{Type: HBAHostAny, Databases: []string{"secret"}, AllUsers: true, Method: HBAMethodReject},
		{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust},
	}
	// Client asks for "secret" — first rule matches → reject.
	got, ok := MatchHBA(rules, false, false, net.ParseIP("10.0.0.1"), "alice", "secret")
	if !ok || got.Method != HBAMethodReject {
		t.Errorf("secret-db match = %v ok=%v, want reject", got, ok)
	}
	// Client asks for "public" — first skipped, second wins → trust.
	got, ok = MatchHBA(rules, false, false, net.ParseIP("10.0.0.1"), "alice", "public")
	if !ok || got.Method != HBAMethodTrust {
		t.Errorf("public-db match = %v ok=%v, want trust", got, ok)
	}
}

func TestMatchHBA_TLSTypeFiltering(t *testing.T) {
	rules := []HBARule{
		{Type: HBAHostSSL, AllDatabases: true, AllUsers: true, Method: HBAMethodTrust},
	}
	// Plain conn — hostssl rule must NOT match.
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("1.2.3.4"), "u", "d"); ok {
		t.Error("hostssl matched a plain conn")
	}
	// TLS conn — matches.
	if _, ok := MatchHBA(rules, true, false, net.ParseIP("1.2.3.4"), "u", "d"); !ok {
		t.Error("hostssl did not match a TLS conn")
	}
}

func TestMatchHBA_CIDR(t *testing.T) {
	_, net10, _ := net.ParseCIDR("10.0.0.0/8")
	rules := []HBARule{
		{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Net: net10, Method: HBAMethodTrust},
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("10.5.5.5"), "u", "d"); !ok {
		t.Error("CIDR should include 10.5.5.5")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("192.168.1.1"), "u", "d"); ok {
		t.Error("CIDR should NOT include 192.168.1.1")
	}
}

func TestMatchHBA_UserAndDBLists(t *testing.T) {
	rules := []HBARule{
		{Type: HBAHostAny, Databases: []string{"app", "reports"}, Users: []string{"alice", "bob"}, Method: HBAMethodTrust},
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("1.1.1.1"), "bob", "reports"); !ok {
		t.Error("bob@reports should match")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("1.1.1.1"), "eve", "app"); ok {
		t.Error("eve@app should NOT match (user not in list)")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("1.1.1.1"), "alice", "other"); ok {
		t.Error("alice@other should NOT match (db not in list)")
	}
}

func TestMatchHBA_Samehost(t *testing.T) {
	rules := []HBARule{
		{Type: HBAHostAny, AllDatabases: true, AllUsers: true, Samehost: true, Method: HBAMethodTrust},
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("127.0.0.1"), "u", "d"); !ok {
		t.Error("samehost should match loopback")
	}
	if _, ok := MatchHBA(rules, false, false, net.ParseIP("1.2.3.4"), "u", "d"); ok {
		t.Error("samehost should NOT match public IP")
	}
}

// TestParseHBALine_UnsupportedMethodRejected — verifies we don't silently
// let md5/password/ldap through as trust.
func TestParseHBALine_UnsupportedMethodRejected(t *testing.T) {
	for _, method := range []string{"md5", "password", "ldap"} {
		_, err := parseHBALine("host all all 0.0.0.0/0 " + method)
		if err == nil {
			t.Errorf("method %q should be rejected", method)
		} else if !strings.Contains(err.Error(), "METHOD") {
			t.Errorf("method %q error should mention METHOD, got: %v", method, err)
		}
	}
}
