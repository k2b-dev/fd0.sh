package main

import (
	"github.com/alecthomas/kong"
	"github.com/valentinkolb/fd0.sh/internal/agent"
	"testing"
)

func TestSSHGrantCommandsAndAutoUnlock(t *testing.T) {
	grants := []agent.SSHGrantView{{Name: "build", ScopeID: "scope-id", Active: true}}
	for _, tc := range []struct {
		args    []string
		command string
		bypass  bool
	}{
		{[]string{"ssh", "grant", "build", "--scope", "work"}, "ssh grant <alias>", false},
		{[]string{"ssh", "grants", "--json"}, "ssh grants", false},
		{[]string{"ssh", "revoke", "grant-id"}, "ssh revoke <id>", false},
		{[]string{"lock", "--all"}, "lock", false},
		{[]string{"ssh", "build"}, "ssh connect <alias>", true},
		{[]string{"ssh", "build", "--scope", "scope-id"}, "ssh connect <alias>", true},
		{[]string{"ssh", "build", "--scope", "other"}, "ssh connect <alias>", false},
		{[]string{"ssh", "buil"}, "ssh connect <alias>", false},
		{[]string{"ssh", "build", "--tag", "test"}, "ssh connect <alias>", false},
		{[]string{"sftp", "ls", "build"}, "sftp list <host>", true},
		{[]string{"ssh", "ls"}, "ssh list", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var c rootCLI
			p, err := kong.New(&c)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := p.Parse(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Command() != tc.command {
				t.Fatalf("got %s", parsed.Command())
			}
			if commandHasSSHGrant(parsed.Command(), &c, grants) != tc.bypass {
				t.Fatal("wrong auto-unlock decision")
			}
		})
	}
	if commandNeedsUnlockedVault("ssh grants") || commandNeedsUnlockedVault("ssh grant <alias>") {
		t.Fatal("grant commands must not silently borrow auto-unlock")
	}
}
