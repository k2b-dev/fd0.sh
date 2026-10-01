package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

// FD0_TALOSCTL overrides the binary path — useful in tests where we
// stub talosctl with a shell script.
const envTalosctlBinary = "FD0_TALOSCTL"

func talosctlBin() string {
	if p := os.Getenv(envTalosctlBinary); p != "" {
		return p
	}
	return "talosctl"
}

// NOTE: `talos sync --merge` no longer shells out to talosctl — it
// uses the pure-Go structural merge in configmerge.go
// (mergeTalosconfigFile). talosctl is still required for the day-0 /
// cluster-admin paths below (gen secrets/config, config new,
// kubeconfig) which need Talos PKI crypto or a live API connection.

// TalosNewOpts drives `fd0 talos new` — day-0 cluster creation.
// We shell out to `talosctl gen secrets` and `talosctl gen config`,
// then suck the result into the vault.
type TalosNewOpts struct {
	Name        string
	Endpoint    string // e.g. https://10.0.1.10:6443 (k8s API URL — talosctl gen config needs this)
	OutputDir   string // where to write controlplane.yaml + worker.yaml (defaults to .)
	Scope       string // talosconfig scope
	VaultScope  string // separate scope for secrets.yaml DR bundle (option 1B). Empty → same as Scope.
	Description string
	Tags        []string

	// Force lets the user overwrite an existing cluster's stored
	// talosconfig + secrets.yaml. Without it we refuse — overwriting
	// a stored cluster is effectively cluster destruction.
	Force bool
}

// RunTalosNew bootstraps a brand-new Talos cluster's credential
// material:
//
//  1. `talosctl gen secrets` → secrets.yaml (root PKI, DR-grade)
//  2. `talosctl gen config <name> <endpoint> --with-secrets …`
//     → controlplane.yaml, worker.yaml, talosconfig
//  3. Store secrets.yaml under TypeTalosSecrets in VaultScope
//     (separate scope by default — least-privilege).
//  4. Store the generated talosconfig context under TypeTalosContext
//     in Scope.
//  5. Leave controlplane.yaml + worker.yaml on disk (the user
//     hands these to whatever provisions their nodes).
func RunTalosNew(ctx context.Context, o TalosNewOpts) error {
	defer trackCleanup()()
	if _, err := exec.LookPath(talosctlBin()); err != nil {
		return fmt.Errorf("talosctl not on PATH (or FD0_TALOSCTL not set): %w", err)
	}
	if o.Name == "" {
		return errors.New("talos new: --name is required")
	}
	if o.Endpoint == "" {
		return errors.New("talos new: --endpoint is required (k8s API URL, e.g. https://10.0.1.10:6443)")
	}
	if o.OutputDir == "" {
		o.OutputDir = "."
	}
	if err := os.MkdirAll(o.OutputDir, 0o700); err != nil {
		return err
	}

	// Preflight existing vault state BEFORE spending a talosctl run +
	// writing PKI files to disk. Propagating resolveScopeID errors is
	// load-bearing: the earlier version `scope, _ := …` silently
	// dropped them, then `if scope != ""` skipped the duplicate
	// check, and talosctl gen ran anyway — leaving root PKI on disk
	// without warning that the preflight was bypassed.
	{
		precheck, err := Open(ctx)
		if err != nil {
			return err
		}
		scope, err := precheck.resolveScopeID(o.Scope)
		if err != nil {
			precheck.Close()
			return fmt.Errorf("talos new: --scope: %w", err)
		}
		vault := o.VaultScope
		if vault == "" {
			vault = o.Scope
		}
		vaultID, err := precheck.resolveScopeID(vault)
		if err != nil {
			precheck.Close()
			return fmt.Errorf("talos new: --vault-scope: %w", err)
		}
		if err := ensureNoDuplicate(precheck, scope, talosNamePrefix, o.Name, o.Force); err != nil {
			precheck.Close()
			return err
		}
		if err := ensureNoDuplicate(precheck, vaultID, talosSecretsNamePrefix, o.Name, o.Force); err != nil {
			precheck.Close()
			return err
		}
		precheck.Close()
	}

	// Everything talosctl produces goes into a 0o700 tmp dir first.
	// We chmod each file to 0600 INSIDE the tmp dir (which only the
	// owner can list/access), then atomic-rename into OutputDir. That
	// closes the chmod-TOCTOU window where an inotify watcher could
	// open() the file during the umask-default window between
	// talosctl writing and our chmod.
	tmpDir, err := os.MkdirTemp(o.OutputDir, ".fd0-talos-gen-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return fmt.Errorf("chmod tmpdir: %w", err)
	}

	tmpSecretsPath := filepath.Join(tmpDir, "secrets.yaml")
	secretsPath := filepath.Join(o.OutputDir, "secrets.yaml")

	// 1. Generate the root PKI bundle into tmpDir.
	stderrln("→ talosctl gen secrets …")
	if err := runTalosctl(ctx, tmpDir, "gen", "secrets", "-o", tmpSecretsPath); err != nil {
		return fmt.Errorf("gen secrets: %w", err)
	}
	if err := os.Chmod(tmpSecretsPath, 0o600); err != nil {
		return fmt.Errorf("chmod tmp secrets.yaml: %w", err)
	}
	// Atomic rename — secrets.yaml never exists in OutputDir at
	// umask-default perms, even briefly.
	if err := os.Rename(tmpSecretsPath, secretsPath); err != nil {
		return fmt.Errorf("move secrets.yaml: %w", err)
	}
	if err := os.Chmod(secretsPath, 0o600); err != nil {
		return fmt.Errorf("chmod secrets.yaml: %w", err)
	}

	// 2. Generate controlplane.yaml + worker.yaml + talosconfig into
	// the same tmpDir. Same chmod-then-move story.
	stderrln("→ talosctl gen config %q %q …", o.Name, o.Endpoint)
	if err := runTalosctl(ctx, tmpDir, "gen", "config", o.Name, o.Endpoint,
		"--with-secrets", secretsPath, "-o", tmpDir); err != nil {
		return fmt.Errorf("gen config: %w", err)
	}

	// Chmod every file talosctl wrote in tmpDir to 0600 BEFORE the
	// move so they never appear in OutputDir at default umask.
	for _, f := range []string{"controlplane.yaml", "worker.yaml", "talosconfig"} {
		p := filepath.Join(tmpDir, f)
		if _, err := os.Stat(p); err == nil {
			if err := os.Chmod(p, 0o600); err != nil {
				return fmt.Errorf("chmod tmp %s: %w", f, err)
			}
		}
	}

	// Move install configs to OutputDir; talosconfig stays in tmpDir
	// and gets ingested into the vault next (then tmpDir is removed
	// by defer).
	for _, f := range []string{"controlplane.yaml", "worker.yaml"} {
		src := filepath.Join(tmpDir, f)
		dst := filepath.Join(o.OutputDir, f)
		if err := os.Rename(src, dst); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("move %s: %w", f, err)
			}
			continue
		}
		if err := os.Chmod(dst, 0o600); err != nil {
			return fmt.Errorf("chmod %s: %w", f, err)
		}
	}

	// 3. Read the freshly-generated talosconfig and stash the
	// admin context as a TypeTalosContext.
	tcfgBytes, err := os.ReadFile(filepath.Join(tmpDir, "talosconfig"))
	if err != nil {
		return fmt.Errorf("read generated talosconfig: %w", err)
	}
	_, contexts, err := talosctx.ParseTalosconfig(tcfgBytes)
	if err != nil {
		return fmt.Errorf("parse generated talosconfig: %w", err)
	}
	if len(contexts) == 0 {
		return errors.New("generated talosconfig had no contexts")
	}

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scope, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}
	vaultScope := o.VaultScope
	if vaultScope == "" {
		vaultScope = o.Scope
	}
	vault, err := s.resolveScopeID(vaultScope)
	if err != nil {
		return err
	}

	for _, c := range contexts {
		c.Scope = scope
		c.Role = talosctx.RoleAdmin
		c.Description = o.Description
		c.Tags = append([]string(nil), o.Tags...)
		if err := c.Validate(); err != nil {
			return err
		}
		if err := storeTalosContext(ctx, s, scope, c); err != nil {
			return err
		}
		stderrln("✓ stored talos context %q (scope: %s, role: %s)",
			c.Name, scopeName(s, scope), c.Role)
	}

	// 4. Stash secrets.yaml under TypeTalosSecrets in the vault
	// scope (could be the same as scope, but defaults to separate).
	secretsBlob, err := os.ReadFile(secretsPath)
	if err != nil {
		return fmt.Errorf("read secrets.yaml: %w", err)
	}
	if err := storeTalosSecrets(ctx, s, vault, o.Name, secretsBlob); err != nil {
		return err
	}
	stderrln("✓ stored secrets.yaml (DR bundle) in scope %s as %q",
		scopeName(s, vault), o.Name)

	stderrln("")
	stderrln("→ controlplane.yaml + worker.yaml written to %s/", o.OutputDir)
	stderrln("  hand them to your provisioning (cloud-init, Talos image, …).")
	stderrln("→ secrets.yaml is on disk *and* in fd0. Securely delete the on-disk copy")
	stderrln("  once you've handed off the install configs:")
	stderrln("      shred -u %s", secretsPath)

	if err := renderAndAutoMergeTalos(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

// runTalosctl is the thin subprocess wrapper. Streams talosctl's
// stderr to ours; captures stdout so error paths surface the actual
// command output.
func runTalosctl(ctx context.Context, dir string, args ...string) error {
	cmd := exec.CommandContext(ctx, talosctlBin(), args...)
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w (stdout: %q)", err, stdout.String())
	}
	return nil
}

// TalosRoleAddOpts drives `fd0 talos role-add` — mints a fresh
// role-scoped client cert against an existing cluster and stores it
// in the vault under a new context name.
type TalosRoleAddOpts struct {
	// SourceContext is an existing fd0-managed talosconfig
	// context with os:admin (or higher) privileges — the issuer.
	SourceContext string

	// NewName is the alias for the new context.
	NewName string

	// Role is the role to embed in the new cert (e.g. os:operator).
	Role string

	// TTL — passed through to `talosctl config new --crt-ttl`.
	// Empty falls back to talosctl's default (1 year).
	TTL string

	Scope       string
	Description string
	Tags        []string
}

// RunTalosRoleAdd shells out to `talosctl config new --roles <role>`
// against the source cluster, parses the resulting talosconfig, and
// stores it under NewName in the vault.
func RunTalosRoleAdd(ctx context.Context, o TalosRoleAddOpts) error {
	defer trackCleanup()()
	if _, err := exec.LookPath(talosctlBin()); err != nil {
		return fmt.Errorf("talosctl not on PATH (or FD0_TALOSCTL not set): %w", err)
	}
	if o.SourceContext == "" || o.NewName == "" || o.Role == "" {
		return errors.New("talos role-add: --from, --name, --role all required")
	}

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scope, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}
	src, err := lookupTalosContext(s, "", o.SourceContext)
	if err != nil {
		return err
	}

	// `talosctl config new` needs an issuer with at least os:admin
	// privileges. If the user passes a known non-admin issuer the
	// API call later fails with a permissions error wrapped opaquely
	// in "talosctl config new: ...". Surface a clear error up front
	// for the roles we know fail; unknown roles fall through to
	// talosctl in case Talos adds new issuer-capable roles later.
	switch src.Role {
	case talosctx.RoleReader, talosctx.RoleEtcdBackup, talosctx.RoleImpersonate:
		return fmt.Errorf("talos role-add: issuer %q has role %q, but minting new certs requires os:admin",
			src.Name, src.Role)
	}

	// Write the source talosconfig to a temp file so talosctl can
	// read it. We don't reuse ~/.talos/config — the source might
	// not be merged there yet.
	tmpDir, err := os.MkdirTemp("", "fd0-talos-roleadd-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	srcCfgPath := filepath.Join(tmpDir, "src.talosconfig")
	srcBytes, _ := talosctx.Render(talosctx.RenderInput{
		Contexts:      []*talosctx.TalosContext{src},
		ActiveContext: src.Name,
		Now:           nowFunc(),
	})
	if err := os.WriteFile(srcCfgPath, srcBytes, 0o600); err != nil {
		return err
	}

	outPath := filepath.Join(tmpDir, "new.talosconfig")
	args := []string{"--talosconfig", srcCfgPath, "config", "new",
		"--roles", o.Role, outPath}
	if o.TTL != "" {
		args = append(args, "--crt-ttl", o.TTL)
	}

	stderrln("→ talosctl config new --roles %s (against %s)…", o.Role, src.Name)
	if err := runTalosctl(ctx, tmpDir, args...); err != nil {
		return fmt.Errorf("talosctl config new: %w", err)
	}
	newBytes, err := os.ReadFile(outPath)
	if err != nil {
		return fmt.Errorf("read minted talosconfig: %w", err)
	}
	_, newCtxs, err := talosctx.ParseTalosconfig(newBytes)
	if err != nil {
		return err
	}
	if len(newCtxs) == 0 {
		return errors.New("minted talosconfig had no contexts")
	}
	// `talosctl config new` produces exactly one context — rename
	// it to the user's NewName.
	c := newCtxs[0]
	c.Name = o.NewName
	c.Scope = scope
	c.Role = o.Role
	c.Description = o.Description
	c.Tags = append([]string(nil), o.Tags...)
	if err := c.Validate(); err != nil {
		return err
	}
	if err := storeTalosContext(ctx, s, scope, c); err != nil {
		return err
	}
	stderrln("✓ stored %q (role: %s, scope: %s)", c.Name, c.Role, scopeName(s, scope))
	if err := renderAndAutoMergeTalos(s); err != nil {
		return err
	}
	hintSyncForPeers()
	return nil
}

// RunTalosKubeconfig calls `talosctl --context X kubeconfig -` to
// fetch a fresh admin kubeconfig from the named cluster, then stores
// it as a TypeKubeconfig secret so `fd0 kube ls` sees it.
//
// Re-entrancy: we hold the vault flock from Open() at the top. The
// previous version called RunKubeAdd() which calls Open() again →
// the second flock acquisition either fails instantly or blocks for
// FD0_LOCK_WAIT. The fix is to use the internal addKubeconfigOnSession
// helper that operates on the already-open session.
//
// Refresh semantics: this command's purpose is to refresh the admin
// cert against the cluster's k8s CA. We preserve user-customised
// fields (namespace, tags, description) and overwrite only the
// server/CA/cert/key. Without that, every refresh wiped user state.
func RunTalosKubeconfig(ctx context.Context, contextName, scopeFlag string) error {
	defer trackCleanup()()
	if _, err := exec.LookPath(talosctlBin()); err != nil {
		return fmt.Errorf("talosctl not on PATH (or FD0_TALOSCTL not set): %w", err)
	}

	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scope, err := s.resolveScopeID(scopeFlag)
	if err != nil {
		return err
	}

	src, err := lookupTalosContext(s, "", contextName)
	if err != nil {
		return err
	}

	// Materialise the source talosconfig in a 0o700 tmp dir.
	tmpDir, err := os.MkdirTemp("", "fd0-talos-kubecfg-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return fmt.Errorf("chmod tmpdir: %w", err)
	}
	tcfgPath := filepath.Join(tmpDir, "talosconfig")
	tcfgBytes, _ := talosctx.Render(talosctx.RenderInput{
		Contexts:      []*talosctx.TalosContext{src},
		ActiveContext: src.Name,
		Now:           nowFunc(),
	})
	if err := os.WriteFile(tcfgPath, tcfgBytes, 0o600); err != nil {
		return err
	}

	stderrln("→ talosctl kubeconfig (context %s) …", src.Name)
	cmd := exec.CommandContext(ctx, talosctlBin(), "--talosconfig", tcfgPath, "kubeconfig", "-")
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("talosctl kubeconfig: %w", err)
	}
	if len(out) == 0 {
		return fmt.Errorf("talosctl kubeconfig: returned empty output (network glitch? wrong endpoint?)")
	}

	// Refresh-preserving import: keep namespace / tags / description
	// / insecure-skip-tls-verify from the existing record (if any);
	// overwrite only the materially-rotated server / CA / cert / key.
	return addKubeconfigBytesOnSession(ctx, s, scope, src.Name, out, true)
}
