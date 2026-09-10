package cli

// Typed-secret helpers. fd0's "everything is a secret" principle means
// keys and SSH hosts are stored as regular vault secrets, distinguished
// only by their SecretRecord.Type discriminator and a structured JSON
// payload. The helpers here factor the typed-set / typed-get / list
// logic out of cli/key.go and cli/ssh.go so the shape is consistent
// across consumer subcommands.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strings"

	"github.com/oklog/ulid/v2"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ErrTypedSecretNotFound is returned (wrapped) by GetTypedSecret when
// the requested name doesn't exist. Callers should use errors.Is to
// detect it rather than string-matching the message, which would be
// brittle and led to a real silent-overwrite footgun in the typed-
// inventory helper.
var ErrTypedSecretNotFound = errors.New("typed secret not found")

// TypedRecord is one structured secret as observed by the typed
// helpers. Payload is the raw `any` from the vault — callers parse it
// via json.Unmarshal into the type-specific shape (sshkey.JSON,
// sshhost.JSON, …).
type TypedRecord struct {
	ID               string
	SchemaVersion    uint64
	RecordTags       map[string]string
	OrganizationTags []string
	Revision         string
	ScopeID          string
	Name             string
	Type             string
	Payload          any
}

// SetTypedSecret writes a structured secret in the given scope. The
// payload must marshal to JSON (we serialise it to a JSON string and
// store it as the Record.Payload; readers do the inverse).
//
// This intentionally re-implements the inner mechanics of RunSecretSet
// because we need to set a custom Type and we want a single round-trip
// per call. Most of the bookkeeping is shared verbatim.
func (s *Session) SetTypedSecret(ctx context.Context, scopeID, name, secretType string, payload any) error {
	return s.setTypedSecret(ctx, scopeID, name, secretType, payload, false, "")
}

// CreateTypedSecret writes only when no current record uses name.
func (s *Session) CreateTypedSecret(ctx context.Context, scopeID, name, secretType string, payload any) error {
	return s.setTypedSecret(ctx, scopeID, name, secretType, payload, true, "")
}

// UpdateTypedSecret writes only when name currently has expectedType.
func (s *Session) UpdateTypedSecret(ctx context.Context, scopeID, name, expectedType, secretType string, payload any) error {
	if expectedType == "" {
		return errors.New("typed secret: expected type required")
	}
	return s.setTypedSecret(ctx, scopeID, name, secretType, payload, false, expectedType)
}

func (s *Session) setTypedSecret(
	ctx context.Context,
	scopeID, name, secretType string,
	payload any,
	requireMissing bool,
	expectedType string,
) error {
	// JSON-encode the typed payload so it survives CBOR's `any`
	// round-trip without surprising type coercion.
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("set typed: marshal payload: %w", err)
	}
	return s.writeTypedSecretPayload(ctx, scopeID, name, secretType, string(raw), requireMissing, expectedType)
}

// writeTypedSecretPayload is the shared typed-secret write. `payload` is
// stored verbatim as SecretRecord.Payload — callers that hold a Go value
// encode it first (setTypedSecret), callers that already hold the stored
// representation (RestoreSecretVersion) pass it through unchanged so a
// round-trip cannot double-encode it.
func (s *Session) writeTypedSecretPayload(
	ctx context.Context,
	scopeID, name, secretType string,
	payload any,
	requireMissing bool,
	expectedType string,
	metadata ...*proto.SecretRecord,
) error {
	if err := s.checkOrganizationWrite(); err != nil {
		return err
	}
	scopeID, err := s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	// Catch up vault on "ahead" chain (mirrors secret.go behaviour).
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
	// Find existing id by name; mint a new one otherwise.
	var sid string
	var current *proto.SecretRecord
	for id, cur := range st.SecretIndex {
		if cur.Record != nil && cur.Record.Name == name {
			sid = id
			current = cur.Record
			break
		}
	}
	if err := checkTypedWriteTarget(name, current, requireMissing, expectedType); err != nil {
		return err
	}
	if sid == "" {
		sid = "s_" + ulid.Make().String()
	}
	base := current
	if len(metadata) > 0 {
		base = metadata[0]
	}
	record := preservedRecord(base, name, secretType, payload)
	body := &proto.SecretBody{
		ID:     sid,
		Record: record,
	}
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, body)
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
	return nil
}

func checkTypedWriteTarget(name string, current *proto.SecretRecord, requireMissing bool, expectedType string) error {
	switch {
	case current != nil && requireMissing:
		return fmt.Errorf("typed secret %q already exists", name)
	case current != nil && expectedType != "" && current.Type != expectedType:
		return fmt.Errorf("typed secret %q has type %q, want %q", name, current.Type, expectedType)
	case current == nil && expectedType != "":
		return fmt.Errorf("typed secret %q not found", name)
	default:
		return nil
	}
}

// ListTypedSecrets enumerates every secret of the given Type across
// every subscribed scope. If scopeID is non-empty the search is
// restricted to that one scope. Results are sorted by scope, then by
// name, so CLI listings are deterministic.
func (s *Session) ListTypedSecrets(scopeID, secretType string) ([]TypedRecord, error) {
	scopes := []string{}
	if scopeID != "" {
		resolved, err := s.resolveScopeID(scopeID)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, resolved)
	} else {
		for sc := range s.Body.Scopes {
			scopes = append(scopes, sc)
		}
		sort.Strings(scopes)
	}
	var out []TypedRecord
	for _, sc := range scopes {
		st, err := s.replayAndCheckScope(sc)
		if err != nil {
			return nil, err
		}
		for id, cur := range st.SecretIndex {
			if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
				continue
			}
			if secretType != "" && cur.Record.Type != secretType {
				continue
			}
			tags, err := organizationTagsFromIndex(st.SecretIndex, id)
			if err != nil {
				return nil, err
			}
			out = append(out, TypedRecord{
				ID: id, SchemaVersion: cur.Record.SchemaVersion, RecordTags: maps.Clone(cur.Record.Tags), OrganizationTags: tags, Revision: cur.EventID,
				ScopeID: sc,
				Name:    cur.Record.Name,
				Type:    cur.Record.Type,
				Payload: cur.Record.Payload,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// GetTypedSecret finds one typed secret by name; matches across every
// subscribed scope unless scopeID is set. Returns an error on multiple
// matches (so the caller surfaces "ambiguous, pass --scope").
func (s *Session) GetTypedSecret(scopeID, name string) (*TypedRecord, error) {
	all, err := s.ListTypedSecrets(scopeID, "")
	if err != nil {
		return nil, err
	}
	var hits []TypedRecord
	for _, r := range all {
		if r.Name == name {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("typed secret %q: %w", name, ErrTypedSecretNotFound)
	case 1:
		return &hits[0], nil
	default:
		var scopes []string
		for _, h := range hits {
			scopes = append(scopes, scopeName(s, h.ScopeID))
		}
		return nil, fmt.Errorf("name %q exists in scopes [%s] — pass --scope", name, strings.Join(scopes, ", "))
	}
}

// RemoveTypedSecret tombstones a typed secret by name in scopeID.
// Inlined here rather than calling RunSecretRemove so we don't have
// to reopen the session.
func (s *Session) RemoveTypedSecret(ctx context.Context, scopeID, name string) error {
	return s.removeTypedSecret(ctx, scopeID, name, "")
}

// RemoveTypedSecretOfType tombstones a record only when its current type
// matches expectedType. This binds rename cleanup to the object that the caller
// validated instead of letting an untrusted old name delete another record.
func (s *Session) RemoveTypedSecretOfType(ctx context.Context, scopeID, name, expectedType string) error {
	if expectedType == "" {
		return errors.New("typed secret: expected type required")
	}
	return s.removeTypedSecret(ctx, scopeID, name, expectedType)
}

func (s *Session) removeTypedSecret(ctx context.Context, scopeID, name, expectedType string) error {
	if err := s.checkOrganizationWrite(); err != nil {
		return err
	}
	scopeID, err := s.resolveScopeID(scopeID)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		return err
	}
	var sid string
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || isMetaSecret(id, cur.Record.Name) {
			continue
		}
		if cur.Record.Name == name {
			if expectedType != "" && cur.Record.Type != expectedType {
				return fmt.Errorf("typed secret %q has type %q, want %q", name, cur.Record.Type, expectedType)
			}
			sid = id
			break
		}
	}
	if sid == "" {
		return fmt.Errorf("typed secret %q not found in scope %s", name, scopeName(s, scopeID))
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
	ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub,
		proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, curOEK.Key, curOEK.Version, body)
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
	return s.ReSeal()
}

// PayloadJSON returns the payload as the JSON bytes that were stored.
// The typed setters always store `string(json.Marshal(payload))`; this
// helper undoes that opaquely so callers don't have to switch on the
// concrete `any` type.
func (r *TypedRecord) PayloadJSON() ([]byte, error) {
	return payloadJSON(r.Payload)
}

// payloadJSON is the shared decode of a stored SecretRecord.Payload back into
// the JSON bytes the typed setters wrote. Kept separate from TypedRecord so
// history entries (which hold a *proto.SecretRecord, not a TypedRecord) use
// exactly the same rules.
func payloadJSON(payload any) ([]byte, error) {
	switch p := payload.(type) {
	case string:
		return []byte(p), nil
	case []byte:
		return p, nil
	default:
		// Fallback for older entries stored without JSON wrapping.
		buf, err := json.Marshal(p)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}
}

// stderrln is a tiny helper for consistent line-ended status output.
func stderrln(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// Ordinary writes preserve fields owned by other features or newer writers.
func preservedRecord(base *proto.SecretRecord, name, kind string, payload any) *proto.SecretRecord {
	r := &proto.SecretRecord{Name: name, Type: kind, SchemaVersion: 1, Payload: payload, Tags: map[string]string{}}
	if base != nil {
		r.SchemaVersion = base.SchemaVersion
		r.Tags = maps.Clone(base.Tags)
	}
	return r
}

func (r TypedRecord) metadata() *proto.SecretRecord {
	return &proto.SecretRecord{SchemaVersion: r.SchemaVersion, Tags: r.RecordTags}
}
