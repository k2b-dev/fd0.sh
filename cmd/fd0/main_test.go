package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

func TestDoctorDoesNotAutoUnlock(t *testing.T) {
	if commandNeedsUnlockedVault("doctor") {
		t.Fatal("doctor must report a locked agent instead of prompting for credentials")
	}
	if !commandNeedsUnlockedVault("pass list") {
		t.Fatal("vault commands must keep their interactive auto-unlock behavior")
	}
}

func TestSSHConnectAcceptsScope(t *testing.T) {
	var command rootCLI
	parser, err := kong.New(&command)
	if err != nil {
		t.Fatal(err)
	}
	context, err := parser.Parse([]string{"ssh", "connect", "--scope", "work", "server"})
	if err != nil {
		t.Fatal(err)
	}
	if got := context.Command(); got != "ssh connect <alias>" {
		t.Fatalf("command=%q", got)
	}
	if command.Ssh.Connect.Scope != "work" || command.Ssh.Connect.Alias != "server" {
		t.Fatalf("scope=%q alias=%q", command.Ssh.Connect.Scope, command.Ssh.Connect.Alias)
	}
}

func TestSFTPCommandsParseApprovedSurface(t *testing.T) {
	tests := []struct {
		argv    []string
		command string
		check   func(*testing.T, rootCLI)
	}{
		{
			argv:    []string{"sftp", "production"},
			command: "sftp connect <host>",
			check: func(t *testing.T, command rootCLI) {
				if command.Sftp.Connect.Host != "production" {
					t.Fatalf("host=%q", command.Sftp.Connect.Host)
				}
			},
		},
		{
			argv:    []string{"sftp", "ls", "production", "/srv", "--json", "--scope", "work"},
			command: "sftp list <host> <path>",
			check: func(t *testing.T, command rootCLI) {
				if command.Sftp.List.Host != "production" || command.Sftp.List.Path != "/srv" ||
					command.Sftp.List.Scope != "work" || !command.Sftp.List.JSON {
					t.Fatalf("list=%+v", command.Sftp.List)
				}
			},
		},
		{
			argv:    []string{"sftp", "cp", "production", "./release", "remote:/srv/release", "-r", "--force"},
			command: "sftp cp <host> <source> <dest>",
			check: func(t *testing.T, command rootCLI) {
				if command.Sftp.Copy.Source != "./release" || command.Sftp.Copy.Dest != "remote:/srv/release" ||
					!command.Sftp.Copy.Recursive || !command.Sftp.Copy.Force {
					t.Fatalf("copy=%+v", command.Sftp.Copy)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.command, func(t *testing.T) {
			var command rootCLI
			parser, err := kong.New(&command)
			if err != nil {
				t.Fatal(err)
			}
			context, err := parser.Parse(test.argv)
			if err != nil {
				t.Fatal(err)
			}
			if got := context.Command(); got != test.command {
				t.Fatalf("command=%q", got)
			}
			test.check(t, command)
		})
	}
}

func TestRunParsesCommandAndNeedsUnlock(t *testing.T) {
	var command rootCLI
	parser, err := kong.New(&command)
	if err != nil {
		t.Fatal(err)
	}
	context, err := parser.Parse([]string{"run", "--service", "app", "--field", "token", "--", "sh", "-c", "true"})
	if err != nil {
		t.Fatal(err)
	}
	if got := context.Command(); got != "run <command>" || !commandNeedsUnlockedVault(got) {
		t.Fatalf("command=%q needsUnlock=%v", got, commandNeedsUnlockedVault(got))
	}
	if command.Run.Service != "app" || len(command.Run.Fields) != 1 || command.Run.Command[len(command.Run.Command)-1] != "true" {
		t.Fatalf("parsed %+v", command.Run)
	}
}

func TestVersionLineNamesDesktopDistribution(t *testing.T) {
	if got := versionLine("0.20.0", "yubikey", "standalone"); got != "fd0 0.20.0 yubikey" {
		t.Fatalf("standalone: %q", got)
	}
	if got := versionLine("0.20.0", "yubikey", "desktop"); got != "fd0 0.20.0 yubikey (desktop)" {
		t.Fatalf("desktop: %q", got)
	}
}
