package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveExactHostRefusesGuessesAndCrossScopeAliases(t *testing.T) {
	// In-process agent and test vault only; nothing connects anywhere.
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	for _, h := range []HostAddOpts{
		{Alias: "web", Hostname: "web.example.test", Scope: scope},
		{Alias: "web", Hostname: "web.other.example.test", Scope: "other"},
		{Alias: "db-1", Hostname: "db1.example.test", Scope: scope},
	} {
		if err := RunHostAdd(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	withSession(t, ctx, func(s *Session) {
		mine, err := loadHosts(s, scope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resolveExactHost(s, mine, "web"); err == nil || !strings.Contains(err.Error(), "several scopes") {
			t.Fatalf("cross-scope alias resolved despite --scope: %v", err)
		}
		if _, err := resolveExactHost(s, mine, "db"); !errors.Is(err, errNoExactHost) || !strings.Contains(err.Error(), "db-1") {
			t.Fatalf("unique prefix must not resolve silently: %v", err)
		}
		host, err := resolveExactHost(s, mine, "db-1")
		if err != nil || host.Hostname != "db1.example.test" {
			t.Fatalf("exact alias: %v %+v", err, host)
		}
	})
}
