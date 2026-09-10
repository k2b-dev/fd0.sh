package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/tui"
)

// Local aliases keep call sites readable without exposing tui internals.
type tuiPickerItem = tui.PickerItem

func runPicker(prompt string, items []tuiPickerItem) (tui.PickerResult, error) {
	return tui.RunPicker(prompt, items)
}

// RunScopeCreate creates a new (personal) scope. The user becomes the sole
// member; a fresh OEK is wrapped to themselves.
func RunScopeCreate(ctx context.Context, label string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	// Build genesis member.change. Author is our super_pub. The OEK is a
	// fresh 32-byte key sealed-boxed to our X25519 pub.
	pubKey := s.UserSuperPub
	// We need ed25519.PrivateKey for signing — but we don't have it. Use the
	// agent's Sign over the SignedInput. We construct the event via a
	// signing variant.
	ev, oek, scopeID, err := chain.BuildScopeGenesis(AgentSigner{Agent: s.Agent}, pubKey)
	if err != nil {
		return err
	}
	defer wipe(oek)

	// Persist locally.
	chainPath := s.Paths.ScopeChain(scopeID)
	if err := chain.AppendScope(chainPath, ev); err != nil {
		return err
	}
	// Compute chain_tip.
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)

	// Update vault: add scope entry with current OEK and chain_tip.
	// Wave C-1: BuildScopeGenesis returns proto.ScopeID; vault map and
	// internal helpers still use the underlying string form. Cast at
	// the boundary — scopeID.String() is free and the audit-grep
	// signal stays clear ("scopeID.String()" → ScopeID escapes the
	// type-safe surface).
	scopeIDStr := scopeID.String()
	if s.Body.Scopes == nil {
		s.Body.Scopes = map[string]proto.ScopeVaultData{}
	}
	s.Body.Scopes[scopeIDStr] = proto.ScopeVaultData{
		Label:    label,
		OEKs:     []proto.OEKEntry{{Version: 1, Key: append([]byte(nil), oek...)}},
		ChainTip: proto.ChainTip{Seq: 0, Hash: tipHash[:]},
	}
	if err := s.ReSeal(); err != nil {
		return err
	}
	// Persist the label as a shared `_meta` secret so other members will
	// see it on discovery (cf. internal/cli/meta.go).
	if label != "" {
		if err := s.writeScopeMeta(scopeIDStr, map[string]string{MetaKeyLabel: label}); err != nil {
			return fmt.Errorf("write _meta: %w", err)
		}
	}
	if label != "" {
		fmt.Fprintf(os.Stderr, "✓ scope '%s' created (%s)\n", label, shortScopeID(scopeIDStr))
	} else {
		fmt.Fprintf(os.Stderr, "✓ scope created (%s)\n", shortScopeID(scopeIDStr))
	}
	hintSync()
	return nil
}

// RunScopeList prints every subscribed scope. Scopes that we have left
// but whose leave event hasn't yet reached the server (Leaving=true)
// are filtered out — to the user the scope appears already gone.
func RunScopeList(ctx context.Context) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	visible := make([]string, 0, len(s.Body.Scopes))
	for id, sd := range s.Body.Scopes {
		if sd.Leaving {
			continue
		}
		visible = append(visible, id)
	}
	if len(visible) == 0 {
		fmt.Println("(no scopes)")
		return nil
	}
	sort.Strings(visible)
	for _, id := range visible {
		sd := s.Body.Scopes[id]
		label := sd.Label
		if label == "" {
			label = "(unnamed)"
		}
		label = terminalSafe(label)
		fmt.Printf("%-20s  %-12s  oek=v%d  tip=%d\n", label, shortScopeID(id), sd.OEKs[len(sd.OEKs)-1].Version, sd.ChainTip.Seq)
	}
	return nil
}

// RunSecretSet adds or updates a secret in the given (or default) scope.
//
// If value == "-" the secret value is read from stdin until EOF. A
// trailing single newline is stripped (so `printf 'foo' | fd0 set X -`
// and `printf 'foo\n' | fd0 set X -` both store "foo"); embedded newlines
// are preserved verbatim. This avoids leaking secrets into shell
// history.
func RunSecretSet(ctx context.Context, scopeID, name, value string) error {
	if err := guardPlainSecret("set", name); err != nil {
		return err
	}
	if value == "-" {
		buf, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("set: read stdin: %w", err)
		}
		// Trim a single trailing newline; embedded newlines stay.
		if n := len(buf); n > 0 && buf[n-1] == '\n' {
			buf = buf[:n-1]
		}
		value = string(buf)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	// Catch up vault on "ahead" chain: replay produced a newer tip and (if
	// member.change crossed) newer OEKs that the vault hasn't recorded yet.
	sd := s.Body.Scopes[scopeID]
	if mm := chain.CompareScopeTip(scopeID, sd.ChainTip, st); mm != nil && mm.Direction == "ahead" {
		sd.ChainTip = proto.ChainTip{Seq: st.TipSeq, Hash: st.TipHash}
		if k, ok := st.OEKs[st.CurrentOEKVer]; ok {
			sd.OEKs = upsertOEK(sd.OEKs, st.CurrentOEKVer, k)
		}
		s.Body.Scopes[scopeID] = sd
		if err := s.ReSeal(); err != nil {
			return err
		}
	}
	if len(sd.OEKs) == 0 {
		return fmt.Errorf("scope %s: no OEK in vault", scopeName(s, scopeID))
	}
	var curOEK proto.OEKEntry
	for _, e := range sd.OEKs {
		if e.Version == st.CurrentOEKVer {
			curOEK = e
			break
		}
	}
	if curOEK.Version == 0 {
		return fmt.Errorf("scope %s: no OEK v%d in vault", scopeName(s, scopeID), st.CurrentOEKVer)
	}
	// Find existing id by name; else mint a new one.
	var sid string
	var previous *proto.SecretRecord
	for id, cur := range st.SecretIndex {
		if cur.Record != nil && cur.Record.Name == name {
			sid = id
			previous = cur.Record
			break
		}
	}
	if sid == "" {
		sid = "s_" + ulid.Make().String()
	}
	body := &proto.SecretBody{
		ID:     sid,
		Record: preservedRecord(previous, name, "kv.string", value),
	}
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, body)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ %s set in %s\n", name, scopeName(s, scopeID))
	hintSyncForPeers()
	return nil
}

// RunSecretGet returns one secret value to stdout.
//
//	out=true (default) → print value to stdout
func RunSecretGet(ctx context.Context, scopeID, name string) (string, error) {
	if err := guardPlainSecret("get", name); err != nil {
		return "", err
	}
	s, err := Open(ctx)
	if err != nil {
		return "", err
	}
	defer s.Close()
	return s.GetSecretByName(scopeID, name)
}

// GetSecretByName looks up one secret in an already-open session.
//
// scopeOrLabel empty → search every subscribed scope. Otherwise resolves
// the label-or-id via resolveScopeID; ambiguous labels error.
func (s *Session) GetSecretByName(scopeOrLabel, name string) (string, error) {
	if scopeOrLabel == "" {
		return s.findSecretAcrossScopes(name)
	}
	scopeID, err := s.resolveScopeID(scopeOrLabel)
	if err != nil {
		return "", err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return "", err
	}
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
			continue
		}
		if cur.Record.Name == name {
			return secretToString(cur.Record.Payload), nil
		}
	}
	return "", fmt.Errorf("secret %q not found in scope %s", name, scopeName(s, scopeID))
}

// findSecretAcrossScopes searches every subscribed scope. Errors when the
// name resolves to multiple secrets in different scopes.
func (s *Session) findSecretAcrossScopes(name string) (string, error) {
	type hit struct {
		scope string
		val   string
	}
	var hits []hit
	for scopeID := range s.Body.Scopes {
		st, err := s.replayAndCheckScope(scopeID)
		if err != nil {
			return "", err
		}
		for id, cur := range st.SecretIndex {
			if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
				continue
			}
			if cur.Record.Name == name {
				hits = append(hits, hit{scope: scopeID, val: secretToString(cur.Record.Payload)})
			}
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("secret %q not found", name)
	case 1:
		return hits[0].val, nil
	default:
		names := make([]string, 0, len(hits))
		for _, h := range hits {
			names = append(names, scopeName(s, h.scope))
		}
		return "", fmt.Errorf("secret %q exists in multiple scopes (%s); pass --scope", name, strings.Join(names, ", "))
	}
}

func secretToString(p any) string {
	if v, ok := p.(string); ok {
		return v
	}
	return fmt.Sprintf("%v", p)
}

// replayAndCheckScope replays a scope chain, enforces the vault tip binding,
// and refreshes the in-memory scope label from the _meta secret if present.
// In-memory only — caller's next ReSeal will persist the label.
//
// Returns chain.ErrRollback when the local chain is behind/diverged vs.
// the vault binding.
func (s *Session) replayAndCheckScope(scopeID string) (*chain.ScopeState, error) {
	return s.replayObservedAndCheckScope(scopeID, nil)
}

// replayObservedAndCheckScope is replayAndCheckScope with an optional
// per-version observer threaded into replay. Every check below is the same
// code both entry points run — the observer only watches.
//
// Lazy legacy migration: a chain written by the retired v1 compactor fails
// replay with chain.ErrScopeHistoryNonContiguous. That rejection is correct
// and stays, but it is not the end of the story — if (and only if) the file
// carries the compactor's exact signature, scope_migrate.go can restore the
// missing span from the server and prove the result against the vault's own
// sealed tip. So we try once, then re-run the SAME replay. The retry is a
// full re-verification, not a bypass: nothing is exposed that ReplayScope
// did not accept.
func (s *Session) replayObservedAndCheckScope(scopeID string, observe chain.SecretObserver) (*chain.ScopeState, error) {
	st, err := replayScopeObservedViaAgent(
		s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)),
		s.UserSuperPub, s.UserX25519Pub, s.Agent, observe,
	)
	if err != nil && errors.Is(err, chain.ErrScopeHistoryNonContiguous) {
		migrated, mErr := s.migrateLegacyScopeOnRead(scopeID)
		if mErr != nil {
			// The actionable "old vault, needs a one-time repair" error
			// replaces the raw non-contiguity text.
			return nil, mErr
		}
		if migrated {
			st, err = replayScopeObservedViaAgent(
				s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)),
				s.UserSuperPub, s.UserX25519Pub, s.Agent, observe,
			)
		}
	}
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("scope chain empty")
	}
	sd := s.Body.Scopes[scopeID]
	if mm := chain.CompareScopeTip(scopeID, sd.ChainTip, st); mm != nil && (mm.Direction == "behind" || mm.Direction == "diverged") {
		return nil, fmt.Errorf("%w: %s", chain.ErrRollback, mm)
	}
	// Pick up shared label from the _meta secret. Cheap; in-memory only.
	if metaLabel := metaLabelFromIndex(st.SecretIndex); metaLabel != "" && metaLabel != sd.Label {
		sd.Label = metaLabel
		s.Body.Scopes[scopeID] = sd
	}
	return st, nil
}

// SecretEntry is one row for the searcher / list output.
type SecretEntry struct {
	ScopeID    string
	ScopeLabel string
	ID         string
	Name       string
	Type       string
	Tags       map[string]string
}

// CollectAllSecrets enumerates secrets across every subscribed scope. Used by
// `fd0 ls` and the interactive `fd0 get` searcher. The returned Session is
// the caller's responsibility to Close — reusing it for follow-up reads
// avoids re-acquiring the flock.
func CollectAllSecrets(ctx context.Context) ([]SecretEntry, *Session, error) {
	s, err := Open(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []SecretEntry
	for scopeID, sdInit := range s.Body.Scopes {
		// Skip scopes pending leave: the user has called `scope leave`
		// but the leave event hasn't yet propagated through sync.
		if sdInit.Leaving {
			continue
		}
		st, err := s.replayAndCheckScope(scopeID)
		if err != nil {
			s.Close()
			return nil, nil, err
		}
		// Re-read sd: replayAndCheckScope may have refreshed Label from _meta.
		sd := s.Body.Scopes[scopeID]
		for id, cur := range st.SecretIndex {
			if cur.Record == nil {
				continue
			}
			if isMetaSecret(id, cur.Record.Name) {
				continue
			}
			out = append(out, SecretEntry{
				ScopeID: scopeID, ScopeLabel: terminalSafe(sd.Label), ID: id,
				Name: cur.Record.Name, Type: cur.Record.Type, Tags: cur.Record.Tags,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, s, nil
}

// RunSecretRemove tombstones a secret in scopeID by writing a secret.set
// event with record=nil. The id stays referenced in the chain (replay sets
// SecretIndex[id].Record = nil) so subsequent reads return "not found" and
// listings skip it.
func RunSecretRemove(ctx context.Context, scopeID, name string, yes bool) error {
	if err := guardPlainSecret("rm", name); err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scopeID, err = s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	// Resolve name → id, refusing to tombstone the reserved _meta entry.
	var sid string
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
			continue
		}
		if cur.Record.Name == name {
			sid = id
			break
		}
	}
	if sid == "" {
		return fmt.Errorf("secret %q not found in scope %s", name, scopeName(s, scopeID))
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove secret %q from %s?", name, scopeName(s, scopeID))); err != nil {
		return err
	}
	sd := s.Body.Scopes[scopeID]
	var curOEK proto.OEKEntry
	for _, e := range sd.OEKs {
		if e.Version == st.CurrentOEKVer {
			curOEK = e
			break
		}
	}
	body := &proto.SecretBody{ID: sid, Record: nil}
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub, proto.MustParseScopeID(scopeID),
		st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, body)
	if err != nil {
		return err
	}
	if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
		return err
	}
	prefix, _ := ev.PrevHashInput()
	tipHash := proto.HashPrefix(prefix)
	sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
	s.Body.Scopes[scopeID] = sd
	if err := s.ReSeal(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ %s removed from %s\n", name, scopeName(s, scopeID))
	hintSyncForPeers()
	return nil
}

// secretListRow is the machine-readable shape of one secret in a listing.
//
// The value is deliberately absent: a listing says what exists, reading it is
// `fd0 secret get`. Keeping the row explicit rather than marshalling
// SecretEntry means a field added to the internal struct cannot leak into a
// public interface by accident.
type secretListRow struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Scope   string `json:"scope,omitempty"`
	ScopeID string `json:"scopeId"`
}

// RunSecretList prints every secret across every scope.
// RunSecretList lists plain secrets.
//
// Records owned by another module — hosts, keys, pass items, clusters, Talos
// contexts — are left to that module's own list, so `fd0 secret ls` answers
// "what secrets do I have" rather than dumping every record in the vault.
// `--all` restores the unfiltered view for the rare case someone wants it.
func RunSecretList(ctx context.Context, jsonOut, all bool) error {
	entries, s, err := CollectAllSecrets(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if !all {
		plain := make([]SecretEntry, 0, len(entries))
		for _, e := range entries {
			if _, owned := kindOwning(e.Name); !owned {
				plain = append(plain, e)
			}
		}
		hidden := len(entries) - len(plain)
		entries = plain
		if hidden > 0 && !jsonOut {
			defer stderrln("\n(%d record(s) owned by other modules hidden; use --all to include them)", hidden)
		}
	}
	if jsonOut {
		rows := make([]secretListRow, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, secretListRow{
				Name:    e.Name,
				Type:    e.Type,
				Scope:   e.ScopeLabel,
				ScopeID: e.ScopeID,
			})
		}
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(entries) == 0 {
		fmt.Println("(no secrets)")
		return nil
	}
	for _, e := range entries {
		fmt.Printf("%-30s  %s\n", e.Name, scopeDisplay(e))
	}
	return nil
}

// scopeDisplay returns the scope label or a shortened scope_id.
func scopeDisplay(e SecretEntry) string {
	if e.ScopeLabel != "" {
		return terminalSafe(e.ScopeLabel)
	}
	return shortScopeID(e.ScopeID)
}

// scopeName returns the human-readable name of a scope, given a session and
// a scope_id. Used in every user-facing message.
func scopeName(s *Session, scopeID string) string {
	if s != nil {
		if sd, ok := s.Body.Scopes[scopeID]; ok && sd.Label != "" {
			return fmt.Sprintf("%s (%s)", terminalSafe(sd.Label), shortScopeID(scopeID))
		}
	}
	return shortScopeID(scopeID)
}

// scopeLabelOf returns a scope's bare label, for machine-readable output.
//
// Unlike scopeName it does not append "(s_abc…)": JSON rows carry the full
// scope id in a field of its own, so the human disambiguator would only be
// noise a consumer has to parse back out. Empty when the scope is unnamed.
func scopeLabelOf(s *Session, scopeID string) string {
	if s == nil {
		return ""
	}
	return s.Body.Scopes[scopeID].Label
}

// shortScopeID renders e.g. "s_h72fyhrp…" from "s_h72fyhrpp6oq7olpc26r2sywti".
func shortScopeID(scopeID string) string {
	if len(scopeID) <= 11 {
		return scopeID
	}
	return scopeID[:10] + "…"
}

// resolveScopeID returns the canonical scope_id for a user-supplied
// identifier, which may be either a scope_id ("s_xxx…") or a label ("work").
//
//	scopeOrLabel == ""        → return the only scope, or prompt a picker
//	scopeOrLabel == "s_xxx…"  → exact id match
//	scopeOrLabel == "work"    → unique label lookup; ambiguous label errors
func (s *Session) resolveScopeID(scopeOrLabel string) (string, error) {
	// Filter scopes pending leave from all resolution paths: a scope
	// the user has just left should appear gone everywhere except in
	// the sync's push iteration (which uses a different traversal).
	visible := func(id string, sd proto.ScopeVaultData) bool { return !sd.Leaving }
	if scopeOrLabel != "" {
		// Direct id match.
		if sd, ok := s.Body.Scopes[scopeOrLabel]; ok && visible(scopeOrLabel, sd) {
			return scopeOrLabel, nil
		}
		// Label match (case-sensitive). Reject ambiguous labels.
		var matches []string
		for id, sd := range s.Body.Scopes {
			if !visible(id, sd) {
				continue
			}
			if sd.Label == scopeOrLabel {
				matches = append(matches, id)
			}
		}
		switch len(matches) {
		case 1:
			return matches[0], nil
		case 0:
			return "", fmt.Errorf("unknown scope %q", scopeOrLabel)
		default:
			return "", fmt.Errorf("label %q matches %d scopes; use scope id", scopeOrLabel, len(matches))
		}
	}
	live := 0
	var soleID string
	for id, sd := range s.Body.Scopes {
		if !visible(id, sd) {
			continue
		}
		live++
		soleID = id
	}
	if live == 0 {
		return "", fmt.Errorf("no scopes — run `fd0 scope create --label <name>` first")
	}
	if live == 1 {
		return soleID, nil
	}
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return "", fmt.Errorf("--scope is required (you have %d scopes)", live)
	}
	return s.promptScopePicker()
}

// promptScopePicker shows a TUI picker over all known scopes.
// Scopes pending leave (Leaving=true) are filtered out.
func (s *Session) promptScopePicker() (string, error) {
	ids := make([]string, 0, len(s.Body.Scopes))
	for id, sd := range s.Body.Scopes {
		if sd.Leaving {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	items := make([]tuiPickerItem, 0, len(ids))
	for _, id := range ids {
		sd := s.Body.Scopes[id]
		label := sd.Label
		if label == "" {
			label = "(unnamed)"
		}
		items = append(items, tuiPickerItem{ID: id, Label: terminalSafe(label), Hint: id})
	}
	res, err := runPicker("Scope?", items)
	if err != nil {
		return "", err
	}
	if res.ID == "" {
		return "", fmt.Errorf("no scope selected")
	}
	return res.ID, nil
}

// ReSeal asks the agent to atomic-rewrite vault.enc with the current Body.
//
// In the new API the agent re-encrypts the body under its cached, stable
// payload_key; the on-disk wraps array is preserved unchanged. Credential
// rotation (add/remove wraps) goes through agent.AddWrap / agent.RemoveWrap.
func (s *Session) ReSeal() error {
	body := *s.Body
	body.SuperPriv = make([]byte, ed25519.PrivateKeySize)
	rb, err := proto.Marshal(body)
	if err != nil {
		return err
	}
	return s.Agent.ReSeal(s.Paths.Vault, rb)
}

// wipe is a tiny helper around crypto.Wipe to avoid extra import noise.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SavePlainSecret writes a literal value for trusted clients without interpreting
// '-' as stdin or JSON-encoding the string like a typed item payload.
func (s *Session) SavePlainSecret(ctx context.Context, scope, name, value string, create bool) error {
	if err := ValidatePlainSecretName(name); err != nil {
		return err
	}
	expectedType := "kv.string"
	if create {
		expectedType = ""
	}
	return s.writeTypedSecretPayload(ctx, scope, name, "kv.string", value, create, expectedType)
}
