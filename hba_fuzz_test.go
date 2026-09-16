package main

// Fuzzing for the HBA parser — the other place pgman reads a format it
// did not design, from a file an operator wrote by hand.
//
// The stakes here are the mirror image of the SCRAM targets. A SCRAM
// parsing bug leaks a secret; an HBA parsing bug grants access. The
// dangerous outcome is not a crash on a malformed line — that is a
// startup failure, which is loud and safe. It is a line that parses
// into a rule *other than the one it reads as*: quoting or comma
// handling that turns `host app,reports alice 10.0.0.0/8 scram-sha-256`
// into something with a wider match than the operator intended.
//
// So the properties assert that a rule which parses is internally
// coherent and cannot be made to match on nonsense, rather than merely
// that the parser survived.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// knownHBAMethods is the closed set parseHBALine is allowed to produce.
// Kept here rather than derived from the parser so that adding a method
// to hba.go without thinking about it trips this test.
var knownHBAMethods = map[HBAMethod]bool{
	HBAMethodTrust:  true,
	HBAMethodReject: true,
	HBAMethodSCRAM:  true,
	HBAMethodPeer:   true,
	HBAMethodCert:   true,
}

// FuzzParseHBALine fuzzes one line of pg_hba.conf syntax, then puts
// whatever came out in front of MatchHBA.
//
// Parsing and matching are fuzzed together on purpose: a rule that
// parses without error but carries, say, a nil IPNet with Samehost
// unset is only a bug once something tries to match against it. Testing
// the parser alone would call that input "handled".
func FuzzParseHBALine(f *testing.F) {
	seeds := []string{
		"host all all 0.0.0.0/0 trust",
		"hostssl shop alice 10.0.0.0/8 scram-sha-256",
		"local all all peer",
		"host app,reports alice,bob samehost reject",
		`host "all" "user,with,commas" ::1/128 cert`,
		"host all all 127.0.0.1/32 md5",
		"",
		"#comment",
		"host",
		`host all all 1.2.3.4/33 trust`,
		`host all all "unterminated 1.2.3.4/32 trust`,
		"host\tall\tall\t::/0\ttrust",
		"host ,,, ,,, 0.0.0.0/0 trust",
	}
	for _, s := range seeds {
		f.Add(s, "alice", "shop")
	}

	f.Fuzz(func(t *testing.T, line, user, database string) {
		rule, err := parseHBALine(line)
		if err != nil {
			return
		}

		if !knownHBAMethods[rule.Method] {
			t.Fatalf("line %q parsed into unknown method %q", line, rule.Method)
		}

		// A rule with no address predicate matches every client. That is
		// legitimate — `all` in the ADDRESS field means exactly that,
		// same as Postgres — but it must be something the operator
		// wrote, never something the parser arrived at by dropping a
		// field it could not read. So the check is consistency with the
		// source token rather than a blanket ban.
		//
		// (The blanket ban was the first version of this assertion, and
		// the fuzzer knocked it over in twelve seconds with
		// `host 0 0 All trust`. Worth keeping the corrected form: it
		// still catches an ADDRESS that silently widens to any.)
		if rule.Net == nil && !rule.Samehost {
			fields, err := tokenizeHBALine(line)
			if err != nil || len(fields) < 4 || len(fields[3]) != 1 {
				t.Fatalf("line %q parsed but its ADDRESS field cannot be recovered", line)
			}
			if !fields[3][0].isKeyword("all") {
				t.Fatalf("line %q has ADDRESS %q yet matches every address",
					line, fields[3][0].value)
			}
		}

		// Matching must be total: every combination below is something
		// a real client can present, including the ones that look like
		// nothing.
		for _, ip := range []net.IP{
			nil,
			net.ParseIP("127.0.0.1"),
			net.ParseIP("10.1.2.3"),
			net.ParseIP("::1"),
			net.ParseIP("2001:db8::1"),
		} {
			for _, tls := range []bool{true, false} {
				for _, unix := range []bool{true, false} {
					MatchHBA([]HBARule{rule}, tls, unix, ip, user, database)
				}
			}
		}
	})
}

// FuzzTokenizeHBALine targets the quoting state machine directly.
//
// It is fuzzed apart from parseHBALine because its failure mode is
// invisible one level up: the field/item split is what decides whether
// `app, reports` is one database list or two fields, and a line that
// tokenizes wrongly can still produce five fields and parse "fine".
func FuzzTokenizeHBALine(f *testing.F) {
	for _, s := range []string{
		"host all all 0.0.0.0/0 trust",
		`host "a b" 'c d' 0.0.0.0/0 trust`,
		"host a,b,c d,e,f 0.0.0.0/0 trust",
		`host "quoted,comma" all 0.0.0.0/0 trust`,
		`""`,
		`"`,
		",",
		" , , ",
		`a"b"c`,
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		fields, err := tokenizeHBALine(line)
		if err != nil {
			return
		}
		for i, field := range fields {
			if len(field) == 0 {
				t.Fatalf("line %q produced an empty field at index %d — "+
					"a field with no items cannot be matched against anything", line, i)
			}
			for _, item := range field {
				// An unquoted item can never contain a separator: if it
				// does, the tokenizer handed back something the parser
				// will treat as a single name even though the operator
				// wrote a list.
				if !item.quoted && strings.ContainsAny(item.value, ", \t") {
					t.Fatalf("line %q produced unquoted item %q containing a separator",
						line, item.value)
				}
			}
		}
	})
}

// FuzzLoadHBAFile covers what the per-line targets cannot: comment
// stripping, blank lines, and the line numbering that every error
// message and audit record refers to. A file-level target is worth its
// runtime because auth_hba_file is read at startup and on SIGHUP, so a
// parse that succeeds against a file it should have rejected is a
// reload that quietly widens access.
func FuzzLoadHBAFile(f *testing.F) {
	f.Add("host all all 0.0.0.0/0 trust\n")
	f.Add("# comment\n\nlocal all all peer\nhostssl shop alice 10.0.0.0/8 scram-sha-256\n")
	f.Add("\n\n\n")
	f.Add("   # indented comment\nhost all all ::1/128 reject")
	f.Add("host all all 0.0.0.0/0 trust\r\nhost all all ::/0 reject\r\n")

	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, content string) {
		path := filepath.Join(dir, "pg_hba.conf")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write hba file: %v", err)
		}
		rules, err := LoadHBAFile(path)
		if err != nil {
			return
		}
		for _, r := range rules {
			if !knownHBAMethods[r.Method] {
				t.Fatalf("file %q yielded unknown method %q", content, r.Method)
			}
			// Line numbers are what an operator greps for after a
			// rejected connection. Zero means the rule cannot be traced
			// back to the line that created it.
			if r.LineNum <= 0 {
				t.Fatalf("rule %+v carries line number %d", r, r.LineNum)
			}
		}
	})
}
