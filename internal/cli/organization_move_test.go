package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
)

func TestOrganizationMoveResumesAfterUnconfirmedDestination(t *testing.T) {
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "MOVE_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeItemTags(ctx, scope, "token", "add", []string{"Prod"}); err != nil {
			t.Fatal(err)
		}
		moves := []OrganizationMove{{ScopeID: scope, Name: "token", TargetScopeID: "destination"}}
		fail := func(*Session, context.Context, *moveJournal) error { return errors.New("synthetic offline") }
		if err := s.moveOrganizationItems(ctx, moves, fail); err == nil {
			t.Fatal("unconfirmed move succeeded")
		}
		for _, sc := range []string{scope, "destination"} {
			r, err := s.GetTypedSecret(sc, "token")
			if err != nil || len(r.OrganizationTags) != 1 {
				t.Fatal(sc, err)
			}
		}
		paths, err := filepath.Glob(filepath.Join(s.Paths.Home, "organization", "moves", "*.json"))
		if err != nil || len(paths) != 1 {
			t.Fatal(paths, err)
		}
		raw, _ := os.ReadFile(paths[0])
		if strings.Contains(string(raw), "CANARY") {
			t.Fatal("journal exposed payload")
		}
		if err := s.MoveOrganizationItems(ctx, moves); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetTypedSecret(scope, "token"); !errors.Is(err, ErrTypedSecretNotFound) {
			t.Fatal("source not archived", err)
		}
		if err := s.MoveOrganizationItems(ctx, moves); err != nil {
			t.Fatal("completed retry failed", err)
		}
		history, err := s.SecretHistory(scope, "token")
		if err != nil || !history[0].Tombstone() {
			t.Fatal("source history unavailable", err)
		}
	})
}

func TestOrganizationMoveRejectsDriftAndConflicts(t *testing.T) {
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "SOURCE", false, ""); err != nil {
			t.Fatal(err)
		}
		moves := []OrganizationMove{{ScopeID: scope, Name: "token", TargetScopeID: "destination"}}
		drift := func(s *Session, ctx context.Context, j *moveJournal) error {
			return s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "CHANGED", false, "")
		}
		if err := s.moveOrganizationItems(ctx, moves, drift); err == nil {
			t.Fatal("source drift ignored")
		}
		source, err := s.GetTypedSecret(scope, "token")
		if err != nil || source.Payload != "CHANGED" {
			t.Fatal("changed source lost", err)
		}
		if err := s.MoveOrganizationItems(ctx, moves); err == nil {
			t.Fatal("stale retry accepted")
		}
	})
}

func TestOrganizationMoveKeepsHostKeyGroupsTogether(t *testing.T) {
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scope, "ssh:deploy", string(sshkey.TypeEd25519), map[string]string{"synthetic": "KEY_CANARY"}); err != nil {
			t.Fatal(err)
		}
		host := &sshhost.Host{Alias: "web", Hostname: "example.invalid", KeyName: "deploy"}
		if err := s.SetTypedSecret(ctx, scope, "host:web", sshhost.TypeHost, host.Marshal()); err != nil {
			t.Fatal(err)
		}
		key := OrganizationMove{ScopeID: scope, Name: "ssh:deploy", TargetScopeID: "destination"}
		if err := s.MoveOrganizationItems(ctx, []OrganizationMove{key}); err == nil {
			t.Fatal("orphaning host accepted")
		}
		if err := s.MoveOrganizationItems(ctx, []OrganizationMove{key, {ScopeID: scope, Name: "host:web", TargetScopeID: "destination"}}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ssh:deploy", "host:web"} {
			if _, err := s.GetTypedSecret("destination", name); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestOrganizationMoveRejectsClearedDestinationTags(t *testing.T) {
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scope, "token", "kv.string", "CANARY"); err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeItemTags(ctx, scope, "token", "set", []string{"Prod"}); err != nil {
			t.Fatal(err)
		}
		moves := []OrganizationMove{{ScopeID: scope, Name: "token", TargetScopeID: "destination"}}
		if err := s.moveOrganizationItems(ctx, moves, func(*Session, context.Context, *moveJournal) error { return errors.New("offline") }); err == nil {
			t.Fatal("expected pending move")
		}
		if err := s.ChangeItemTags(ctx, "destination", "token", "clear", nil); err != nil {
			t.Fatal(err)
		}
		if err := s.MoveOrganizationItems(ctx, moves); err == nil {
			t.Fatal("cleared target tags overwritten")
		}
		if _, err := s.GetTypedSecret(scope, "token"); err != nil {
			t.Fatal("source lost")
		}
	})
}
