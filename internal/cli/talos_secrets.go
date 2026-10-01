package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// TypeTalosSecrets identifies a stored secrets.yaml bundle. We use
// a separate type so the day-to-day `fd0 talos sync` codepath can
// filter for TypeTalosContext only — secrets.yaml is DR-grade and
// rarely fetched.
const TypeTalosSecrets = "fd0-talos-secrets"

// talosSecretsNamePrefix scopes the name namespace, similar to
// `talos:`. Bundles end up as e.g. `talos-secrets:prod-1` in the
// vault.
const talosSecretsNamePrefix = "talos-secrets:"

// TalosSecretsJSON is the on-vault shape. We store the bundle as
// base64 to be safe across CBOR/JSON round-trips even if it contains
// embedded newlines / special chars.
type TalosSecretsJSON struct {
	Type    string `json:"type"`
	Name    string `json:"n"`
	BlobB64 string `json:"b"`
}

func storeTalosSecrets(ctx context.Context, s *Session, scopeID, name string, raw []byte) error {
	return s.SetTypedSecret(ctx, scopeID, talosSecretsNamePrefix+name,
		TypeTalosSecrets, TalosSecretsJSON{
			Type:    TypeTalosSecrets,
			Name:    name,
			BlobB64: base64.StdEncoding.EncodeToString(raw),
		})
}

// RunTalosSecretsExport writes the named secrets.yaml bundle to a
// file. Refuses to overwrite an existing path unless force is true
// — losing a freshly-extracted secrets.yaml on top of an old one
// would be the worst kind of foot-gun.
func RunTalosSecretsExport(ctx context.Context, scopeFlag, name, outPath string, force bool) error {
	if outPath == "" {
		return errors.New("talos secrets export: --out required")
	}
	if !force {
		if _, err := os.Stat(outPath); err == nil {
			return fmt.Errorf("talos secrets export: %s exists (pass --force to overwrite)", outPath)
		}
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

	rows, err := s.ListTypedSecrets(scope, TypeTalosSecrets)
	if err != nil {
		return err
	}
	var match *TypedRecord
	for i := range rows {
		raw, _ := rows[i].PayloadJSON()
		var j TalosSecretsJSON
		if err := json.Unmarshal(raw, &j); err == nil && j.Name == name {
			r := rows[i]
			match = &r
			break
		}
	}
	if match == nil {
		return fmt.Errorf("talos secrets export: no bundle %q in scope %s", name, scopeName(s, scope))
	}
	raw, _ := match.PayloadJSON()
	var j TalosSecretsJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return err
	}
	blob, err := base64.StdEncoding.DecodeString(j.BlobB64)
	if err != nil {
		return fmt.Errorf("talos secrets export: payload not valid base64: %w", err)
	}
	if err := writeFileAtomic(outPath, blob, 0o600); err != nil {
		return err
	}
	stderrln("✓ wrote %s (%d bytes, mode 0600)", outPath, len(blob))
	stderrln("")
	stderrln("⚠ this file is the root PKI for cluster %q.", name)
	stderrln("  Losing it means the cluster cannot be regenerated or")
	stderrln("  re-issued operator certs offline. Store it like a vault.")
	return nil
}

// RunTalosSecretsImport stuffs an existing secrets.yaml into the
// vault. Useful for "I had a cluster before fd0; let me get the DR
// bundle into the vault too".
func RunTalosSecretsImport(ctx context.Context, scopeFlag, name, inPath string, force bool) error {
	if inPath == "" {
		return errors.New("talos secrets import: --in required")
	}
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return err
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
	if !force {
		if _, err := s.GetTypedSecret(scope, talosSecretsNamePrefix+name); err == nil {
			return fmt.Errorf("talos secrets import: bundle %q already exists in scope %s (pass --force to replace it; the old bundle stays in history)", name, scopeName(s, scope))
		}
	}
	if err := storeTalosSecrets(ctx, s, scope, name, raw); err != nil {
		return err
	}
	stderrln("✓ stored %d-byte secrets.yaml as %q in scope %s",
		len(raw), name, scopeName(s, scope))
	hintSyncForPeers()
	return nil
}

// RunTalosSecretsRemove tombstones a stored bundle, e.g. for a retired
// cluster. Earlier versions stay in the item history.
func RunTalosSecretsRemove(ctx context.Context, scopeFlag, name string, yes bool) error {
	return removeRecord(ctx, scopeFlag, talosSecretsNamePrefix+name, name, "Talos secrets bundle", yes)
}

// RunTalosSecretsList lists secrets.yaml bundles (just the names).
// Bundles are large and dangerous — we never print contents from
// this command.
func RunTalosSecretsList(ctx context.Context, scopeFlag string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	scope, err := s.resolveScopeID(scopeFlag)
	if err != nil {
		return err
	}
	rows, err := s.ListTypedSecrets(scope, TypeTalosSecrets)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		stderrln("no secrets.yaml bundles in scope %s", scopeName(s, scope))
		return nil
	}
	for _, r := range rows {
		raw, _ := r.PayloadJSON()
		var j TalosSecretsJSON
		if err := json.Unmarshal(raw, &j); err != nil {
			fmt.Printf("%-30s  (malformed: %v)\n", r.Name, err)
			continue
		}
		blob, _ := base64.StdEncoding.DecodeString(j.BlobB64)
		fmt.Printf("%-30s  %d bytes  scope=%s\n",
			j.Name, len(blob), scopeName(s, r.ScopeID))
	}
	return nil
}
