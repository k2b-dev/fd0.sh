package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTalosKubeconfigReleasesVaultLockWhileTalosctlRuns(t *testing.T) {
	// In-process agent, test vault and a fake talosctl; nothing contacts a cluster.
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	t.Setenv("FD0_KUBE_CONFIG_PATH", filepath.Join(isolation, "kube", "config.fd0"))
	t.Setenv("FD0_TALOS_CONFIG_PATH", filepath.Join(isolation, "talos", "config.fd0"))
	ctx, scope := newTestVault(t)
	donor := filepath.Join(isolation, "donor.talosconfig")
	if err := os.WriteFile(donor, []byte("context: lab\ncontexts:\n  lab:\n    endpoints: [192.0.2.10]\n    ca: QUFB\n    crt: QkJC\n    key: Q0ND\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RunTalosAdd(ctx, TalosAddOpts{FromConfig: donor, Scope: scope, Role: "os:admin"}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(os.Getenv("FD0_HOME"), ".lock")
	fake := filepath.Join(isolation, "talosctl")
	script := "#!/bin/sh\n" +
		"flock -n '" + lock + "' true || { echo 'vault lock held during talosctl' >&2; exit 3; }\n" +
		"cat <<'EOF'\n" +
		"apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: lab\n  cluster:\n    server: https://192.0.2.10:6443\n    certificate-authority-data: QUFB\n" +
		"users:\n- name: admin@lab\n  user:\n    client-certificate-data: QkJC\n    client-key-data: Q0ND\n" +
		"contexts:\n- name: admin@lab\n  context:\n    cluster: lab\n    user: admin@lab\n" +
		"current-context: admin@lab\nEOF\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envTalosctlBinary, fake)
	if err := RunTalosKubeconfig(ctx, "lab", scope); err != nil {
		t.Fatal(err)
	}
}
