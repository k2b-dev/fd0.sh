package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ItemKind describes one family of typed records.
//
// Every module that stores user-owned items — passwords, SSH hosts, keys,
// kubeconfigs, Talos contexts — keeps them as typed secrets under a shared
// record-name prefix. Naming that pattern once lets move, rename, history and
// restore be written once instead of per module, which is what keeps the six
// modules behaving the same way as they grow.
type ItemKind struct {
	// Noun names a single item in messages, lower case: "host", "key".
	Noun string
	// Command is the module's CLI verb, used to spell out recovery commands.
	Command string
	// Prefix is the record-name prefix identifying this family, e.g. "host:".
	Prefix string
}

// Item kinds. These prefixes are wire state: changing one orphans every
// existing record of that kind.
var (
	KindSecret = ItemKind{Noun: "secret", Command: "secret", Prefix: ""}
	KindPass   = ItemKind{Noun: "pass item", Command: "pass", Prefix: passNamePrefix}
	KindHost   = ItemKind{Noun: "host", Command: "ssh", Prefix: hostNamePrefix}
	KindKey    = ItemKind{Noun: "key", Command: "key", Prefix: keyNamePrefix}
	KindKube   = ItemKind{Noun: "cluster", Command: "kube", Prefix: kubeNamePrefix}
	KindTalos  = ItemKind{Noun: "context", Command: "talos", Prefix: talosNamePrefix}
)

// itemKinds is the registry every shared behaviour reads, so adding a module
// means adding it here rather than remembering a second list.
var itemKinds = []ItemKind{KindSecret, KindPass, KindHost, KindKey, KindKube, KindTalos}

// ItemHooks carry the parts of an operation that genuinely differ per module.
//
// Everything else — locating the record, refusing a duplicate, ordering the
// write before the tombstone, reporting the result — is identical, and lives in
// the shared functions below. Notably a payload never carries its own scope
// (Kubeconfig.Marshal and TalosContext.Marshal both omit it, because the scope
// is the record's location rather than part of its content), which is what lets
// move copy the stored bytes verbatim.
type ItemHooks struct {
	// After runs once the change is committed, for modules that render config
	// files from the vault. A failure here is reported but does not undo the
	// change, which is already durable.
	After func(*Session) error
}

func (h ItemHooks) after(s *Session) {
	if h.After == nil {
		return
	}
	if err := h.After(s); err != nil {
		stderrln("⚠ %v", err)
	}
}

// hooksFor is the single place that says which modules render files from the
// vault. Every shared operation reads it, so a module cannot end up rendering
// after `edit` but not after `restore` — the class of bug that comes from each
// command remembering to pass its own hook.
func hooksFor(kind ItemKind) ItemHooks {
	switch kind.Command {
	case "ssh":
		return ItemHooks{After: renderAndWarn}
	case "key":
		return ItemHooks{After: renderSSHWithSessionIfEnabled}
	case "kube":
		return ItemHooks{After: renderAndAutoMergeKube}
	case "talos":
		return ItemHooks{After: renderAndAutoMergeTalos}
	default:
		// Secrets and pass items have no rendered representation.
		return ItemHooks{}
	}
}

// record loads one item, mapping "not found" to a message naming the kind.
func (k ItemKind) record(s *Session, scopeID, name string) (*TypedRecord, error) {
	r, err := s.GetTypedSecret(scopeID, k.Prefix+name)
	if err != nil {
		if errors.Is(err, ErrTypedSecretNotFound) {
			return nil, fmt.Errorf("%s %q not found", k.Noun, name)
		}
		return nil, err
	}
	return r, nil
}

// validItemName rejects names that would collide with another kind's records
// or break the prefix scheme. Rename and move are the only places a user picks
// a stored record name directly, so the check lives here.
func validItemName(name string) error {
	switch {
	case name == MetaSecretName:
		return errors.New("reserved metadata name")
	case strings.TrimSpace(name) == "":
		return errors.New("name cannot be empty")
	case name != strings.TrimSpace(name):
		return errors.New("name cannot start or end with whitespace")
	case strings.ContainsAny(name, ":\n\r\t"):
		return errors.New(`name cannot contain ":" or control characters`)
	}
	return nil
}

// MoveItem relocates an item to another scope.
//
// The stored payload is copied verbatim rather than decoded and re-encoded, so
// a move cannot alter the item — including fields this build does not know
// about. The source is tombstoned only after the destination write succeeds,
// so an interrupted move leaves the item present rather than lost.
func (s *Session) MoveItem(
	ctx context.Context,
	kind ItemKind,
	name, fromScope, toScope string,
	force bool,
) error {
	if err := guardOwnedName(kind, "move", name); err != nil {
		return err
	}
	if fromScope == "" {
		record, err := kind.record(s, fromScope, name)
		if err != nil {
			return err
		}
		fromScope = record.ScopeID
	}
	if err := s.MoveOrganizationItems(ctx, []OrganizationMove{{ScopeID: fromScope, Name: kind.Prefix + name, TargetScopeID: toScope, Replace: force}}); err != nil {
		return err
	}
	stderrln("✓ moved %s %q to %s", kind.Noun, name, toScope)
	hintSyncForPeers()
	return nil
}

// RenameItem gives an item a new name within its scope.
//
// Records are addressed by name, so this writes the item under the new name and
// tombstones the old one. The item's own view of its name, where it has one, is
// the module's business: rename takes an optional hook for that.
func (s *Session) RenameItem(
	ctx context.Context,
	kind ItemKind,
	scopeID, oldName, newName string,
	force bool,
	retitle func(payload []byte, newName string) ([]byte, error),
) error {
	if err := guardOwnedName(kind, "rename", oldName); err != nil {
		return err
	}
	if err := validItemName(newName); err != nil {
		return fmt.Errorf("rename %s: %w", kind.Noun, err)
	}
	if oldName == newName {
		return fmt.Errorf("%s is already named %q", kind.Noun, newName)
	}
	r, err := kind.record(s, scopeID, oldName)
	if err != nil {
		return err
	}
	if err := ensureNoDuplicate(s, r.ScopeID, kind.Prefix, newName, force); err != nil {
		return err
	}
	payload, err := r.PayloadJSON()
	if err != nil {
		return err
	}
	if retitle != nil {
		if payload, err = retitle(payload, newName); err != nil {
			return err
		}
	}
	if err := s.writeTypedSecretPayload(ctx, r.ScopeID, kind.Prefix+newName, r.Type, string(payload), false, "", r.metadata()); err != nil {
		return err
	}
	if err := s.copyOrganizationTags(r, r.ScopeID, kind.Prefix+newName); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, r.ScopeID, r.Name); err != nil {
		return fmt.Errorf("wrote %s %q under its new name but failed to remove %q: %w (clean up with: fd0 %s rm %s --scope %s)",
			kind.Noun, newName, oldName, err, kind.Command, oldName, scopeName(s, r.ScopeID))
	}
	stderrln("✓ renamed %s %q → %q in %s", kind.Noun, oldName, newName, scopeName(s, r.ScopeID))
	hooksFor(kind).after(s)
	hintSyncForPeers()
	return nil
}

// EditItem is the shared shape of every edit command: load, patch, save.
//
// patch receives the decoded item and reports whether it changed anything. An
// edit that changes nothing writes nothing, so it cannot burn a revision or a
// sync round-trip on a typo.
func EditItem[T any](
	ctx context.Context,
	kind ItemKind,
	scopeID, name string,
	decode func(TypedRecord) (*T, error),
	patch func(*T) (bool, error),
	validate func(*T) error,
	encode func(*T) (secretType string, payload any),
) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	r, err := kind.record(s, scopeID, name)
	if err != nil {
		return err
	}
	item, err := decode(*r)
	if err != nil {
		return err
	}
	changed, err := patch(item)
	if err != nil {
		return err
	}
	if !changed {
		stderrln("· %s %q unchanged", kind.Noun, name)
		return nil
	}
	if validate != nil {
		if err := validate(item); err != nil {
			return err
		}
	}
	secretType, payload := encode(item)
	if err := s.SetTypedSecret(ctx, r.ScopeID, r.Name, secretType, payload); err != nil {
		return err
	}
	stderrln("✓ updated %s %q in %s", kind.Noun, name, scopeName(s, r.ScopeID))
	hooksFor(kind).after(s)
	hintSyncForPeers()
	return nil
}

// setString applies an optional string flag, reporting whether it changed the
// field. Edit commands use pointer flags so "not given" and "set to empty" stay
// distinguishable — clearing a value is a real edit.
func setString(field *string, next *string, changed *bool) {
	if next == nil || *field == *next {
		return
	}
	*field = *next
	*changed = true
}

// setInt is setString for numeric fields.
func setInt(field *int, next *int, changed *bool) {
	if next == nil || *field == *next {
		return
	}
	*field = *next
	*changed = true
}

// setStrings applies an optional list flag.
func setStrings(field *[]string, next *[]string, changed *bool) {
	if next == nil || equalStrings(*field, *next) {
		return
	}
	*field = *next
	*changed = true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunItemHistory prints an item's version history, newest first.
//
// The list is the same for every module because the history lives in the chain,
// not in the payload: each entry is one signed event, ordered by sequence. The
// newest-first order matches SecretHistory, which the desktop reads too, so a
// sequence number means the same thing in both.
func RunItemHistory(ctx context.Context, kind ItemKind, scopeID, name string, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := guardOwnedName(kind, "history", name); err != nil {
		return err
	}
	entries, err := s.SecretHistory(scopeID, kind.Prefix+name)
	if err != nil {
		return err
	}
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(itemHistoryRows(entries))
	}
	if len(entries) == 0 {
		stderrln("no history for %s %q", kind.Noun, name)
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%s\n", formatHistoryEntry(e))
	}
	stderrln("\nrestore with: fd0 %s history restore %s <seq>", kind.Command, name)
	return nil
}

// itemHistoryRow is the machine-readable shape of one version. Author is hex
// rather than raw bytes so the output stays valid JSON text.
type itemHistoryRow struct {
	Seq       uint64 `json:"seq"`
	EventID   string `json:"eventId"`
	Author    string `json:"author"`
	Deleted   bool   `json:"deleted"`
	Revision  int64  `json:"revision,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

func itemHistoryRows(entries []SecretVersionEntry) []itemHistoryRow {
	rows := make([]itemHistoryRow, 0, len(entries))
	for _, e := range entries {
		row := itemHistoryRow{
			Seq:       e.Seq,
			EventID:   e.EventID,
			Author:    hex.EncodeToString(e.Author),
			Deleted:   e.Tombstone(),
			UpdatedAt: e.UpdatedAt,
		}
		if e.HasRevision {
			row.Revision = e.Revision
		}
		rows = append(rows, row)
	}
	return rows
}

func formatHistoryEntry(e SecretVersionEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "seq %-6d", e.Seq)
	switch {
	case e.Tombstone():
		b.WriteString("deleted")
	case e.HasRevision:
		fmt.Fprintf(&b, "revision %d", e.Revision)
	default:
		b.WriteString("updated")
	}
	if e.UpdatedAt != "" {
		fmt.Fprintf(&b, "  %s", e.UpdatedAt)
	}
	return b.String()
}

// RunItemRestore brings back an earlier version.
//
// The restored content is written as a new version rather than by rewinding the
// chain, so the history stays append-only and the restore itself is auditable.
func RunItemRestore(ctx context.Context, kind ItemKind, scopeID, name string, seq uint64) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := guardOwnedName(kind, "history restore", name); err != nil {
		return err
	}
	if err := s.RestoreSecretVersion(ctx, scopeID, kind.Prefix+name, seq); err != nil {
		return err
	}
	stderrln("✓ restored %s %q to the content of seq %d", kind.Noun, name, seq)
	hooksFor(kind).after(s)
	hintSyncForPeers()
	return nil
}

// kindOwning reports which module owns a stored record name, if any.
//
// Records are namespaced by prefix ("host:", "pass:", …). Plain secrets have no
// prefix, which means the secret commands would otherwise address every other
// module's records too — `fd0 secret rm host:prod` would delete an SSH host
// while claiming to remove a secret.
func kindOwning(name string) (ItemKind, bool) {
	for _, kind := range itemKinds {
		if kind.Prefix != "" && strings.HasPrefix(name, kind.Prefix) {
			return kind, true
		}
	}
	return ItemKind{}, false
}

// guardPlainSecret refuses a name that belongs to another module and points at
// the command that does own it. Modules stay reachable — just not by pretending
// their records are plain secrets.
// ValidatePlainSecretName rejects reserved scope metadata and typed-item namespaces.
func ValidatePlainSecretName(name string) error { return guardPlainSecret("set", name) }

func guardPlainSecret(verb, name string) error {
	if name == MetaSecretName {
		return errors.New("reserved scope metadata is not a plain secret")
	}
	kind, owned := kindOwning(name)
	if !owned {
		return nil
	}
	bare := strings.TrimPrefix(name, kind.Prefix)
	return fmt.Errorf("%q is a %s, not a plain secret\n  use: fd0 %s %s %s",
		name, kind.Noun, kind.Command, secretVerbFor(kind, verb), bare)
}

// secretVerbFor maps a secret verb onto the owning module's equivalent. Only
// the spellings that actually differ need translating.
func secretVerbFor(kind ItemKind, verb string) string {
	if verb == "get" {
		// Modules render a whole item; there is no single value to print.
		return "show"
	}
	return verb
}

// guardOwnedName applies the plain-secret namespace guard, but only for the
// unprefixed secret module: a prefixed kind already scopes its own names, and
// a host legitimately called "pass:notes" is its own business.
func guardOwnedName(kind ItemKind, verb, name string) error {
	if kind.Prefix != "" {
		return nil
	}
	return guardPlainSecret(verb, name)
}
