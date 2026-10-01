package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTalosSecretsBundleIsProtectedAndRemovable(t *testing.T) {
	// In-process agent and test vault only.
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx, scope := newTestVault(t)
	bundle := filepath.Join(isolation, "secrets.yaml")
	if err := os.WriteFile(bundle, []byte("synthetic: bundle\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunTalosSecretsImport(ctx, scope, "lab", bundle, false); err != nil {
		t.Fatal(err)
	}
	if err := RunTalosSecretsImport(ctx, scope, "lab", bundle, false); err == nil {
		t.Fatal("second import replaced the bundle without --force")
	}
	if err := RunTalosSecretsImport(ctx, scope, "lab", bundle, true); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"get", "rm", "set"} {
		err := guardPlainSecret(verb, "talos-secrets:lab")
		if err == nil || !strings.Contains(err.Error(), "talos secrets") {
			t.Fatalf("secret %s reached the bundle: %v", verb, err)
		}
	}
	if err := RunTalosSecretsRemove(ctx, scope, "lab", true); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(isolation, "restored.yaml")
	if err := RunTalosSecretsExport(ctx, scope, "lab", out, false); err == nil {
		t.Fatal("removed bundle is still exportable")
	}
}
