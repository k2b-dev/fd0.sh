package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
)

const moveMarker = "fd0.organization.move"

type OrganizationMove struct {
	Replace       bool   `json:"replace,omitempty"`
	ScopeID       string `json:"scopeId"`
	Name          string `json:"name"`
	TargetScopeID string `json:"targetScopeId"`
}
type moveEntry struct {
	OrganizationMove
	SourceID         string   `json:"sourceId"`
	SourceEvent      string   `json:"sourceEvent"`
	Tags             []string `json:"tags"`
	TargetTagsBefore []string `json:"targetTagsBefore,omitempty"`
	TargetBefore     string   `json:"targetBefore,omitempty"`
	TargetID         string   `json:"targetId,omitempty"`
	Archived         bool     `json:"archived"`
}
type moveJournal struct {
	RequestID string      `json:"requestId"`
	Version   int         `json:"version"`
	ID        string      `json:"id"`
	Entries   []moveEntry `json:"entries"`
	Complete  bool        `json:"complete"`
}

func (s *Session) moveJournalPath(id string) string {
	return filepath.Join(s.Paths.Home, "organization", "moves", id+".json")
}
func (s *Session) saveMove(j *moveJournal) error {
	path := s.moveJournalPath(j.RequestID)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0600)
}

// MoveOrganizationItems copies the whole group before removing any sources.
// Journal files contain references and metadata only, never stored values.
func (s *Session) MoveOrganizationItems(ctx context.Context, moves []OrganizationMove) error {
	return s.moveOrganizationItems(ctx, moves, (*Session).confirmMoveDestinations)
}
func (s *Session) moveOrganizationItems(ctx context.Context, moves []OrganizationMove, confirm func(*Session, context.Context, *moveJournal) error) error {
	if len(moves) == 0 || len(moves) > 100 {
		return errors.New("move requires 1–100 items")
	}
	moves = slices.Clone(moves)
	for i := range moves {
		var err error
		moves[i].ScopeID, err = s.resolveScopeID(moves[i].ScopeID)
		if err != nil {
			return err
		}
		moves[i].TargetScopeID, err = s.resolveScopeID(moves[i].TargetScopeID)
		if err != nil {
			return err
		}
		if moves[i].ScopeID == moves[i].TargetScopeID {
			return errors.New("source and destination scopes are the same")
		}
	}
	slices.SortFunc(moves, func(a, b OrganizationMove) int {
		return strings.Compare(a.ScopeID+"/"+a.Name+"/"+a.TargetScopeID, b.ScopeID+"/"+b.Name+"/"+b.TargetScopeID)
	})
	raw, _ := json.Marshal(moves)
	id := fmt.Sprintf("%x", sha256.Sum256(raw))
	j := moveJournal{Version: 1, ID: rand.Text(), RequestID: id}
	journalRaw, readErr := os.ReadFile(s.moveJournalPath(id))
	if readErr == nil {
		if err := json.Unmarshal(journalRaw, &j); err != nil || j.Version != 1 || j.RequestID != id || len(j.Entries) != len(moves) {
			return errors.New("invalid move journal")
		}
		for i, entry := range j.Entries {
			if entry.OrganizationMove != moves[i] {
				return errors.New("move journal does not match request")
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	if j.Complete {
		active := false
		for _, move := range moves {
			_, err := s.GetTypedSecret(move.ScopeID, move.Name)
			if err == nil {
				active = true
			} else if !errors.Is(err, ErrTypedSecretNotFound) {
				return err
			}
		}
		// A restored or newly created source is a new operation. Never reuse the
		// old marker to adopt the destination from a previous completed move.
		if active {
			j = moveJournal{Version: 1, ID: rand.Text(), RequestID: id}
		}
	}
	if len(j.Entries) == 0 {
		seen := map[string]bool{}
		targets := map[string]bool{}
		for _, move := range moves {
			if seen[move.ScopeID+"/"+move.Name] || targets[move.TargetScopeID+"/"+move.Name] {
				return errors.New("duplicate move source or destination")
			}
			seen[move.ScopeID+"/"+move.Name] = true
			targets[move.TargetScopeID+"/"+move.Name] = true
			r, err := s.GetTypedSecret(move.ScopeID, move.Name)
			if err != nil {
				return err
			}
			if _, err := OrganizationKind(r.Type); err != nil {
				return err
			}
			before := ""
			var beforeTags []string
			existing, err := s.GetTypedSecret(move.TargetScopeID, move.Name)
			if err == nil {
				if !move.Replace {
					return errors.New("destination item already exists")
				}
				before = existing.Revision
				beforeTags = slices.Clone(existing.OrganizationTags)
			} else if !errors.Is(err, ErrTypedSecretNotFound) {
				return err
			}

			for _, scope := range []string{move.ScopeID, move.TargetScopeID} {
				st, err := s.replayAndCheckScope(scope)
				if err != nil {
					return err
				}
				if st.Left || s.Body.Scopes[scope].Leaving || !slices.ContainsFunc(st.MemberSet, func(pub []byte) bool { return bytes.Equal(pub, s.UserSuperPub) }) {
					return errors.New("scope membership does not permit this move")
				}
			}
			j.Entries = append(j.Entries, moveEntry{OrganizationMove: move, SourceID: r.ID, SourceEvent: r.Revision, TargetBefore: before, TargetTagsBefore: beforeTags, Tags: slices.Clone(r.OrganizationTags)})
		}
		if err := s.checkMoveReferences(&j); err != nil {
			return err
		}
		if err := s.saveMove(&j); err != nil {
			return err
		}
	}
	// Source history is the durable content snapshot. It stays in its old scope.
	sources := make([]*TypedRecord, len(j.Entries))
	for i := range j.Entries {
		entry := &j.Entries[i]
		r, err := s.moveSource(*entry)
		if err != nil {
			return err
		}
		sources[i] = r
		if err = s.checkMoveSourceCurrent(*entry); err != nil {
			return err
		}
		if entry.Archived {
			continue
		}
		target, err := s.GetTypedSecret(entry.TargetScopeID, entry.Name)
		if errors.Is(err, ErrTypedSecretNotFound) || (err == nil && entry.Replace && target.Revision == entry.TargetBefore && target.RecordTags[moveMarker] != j.ID) {
			meta := r.metadata()
			meta.Tags = maps.Clone(meta.Tags)
			if meta.Tags == nil {
				meta.Tags = map[string]string{}
			}
			meta.Tags[moveMarker] = j.ID
			if err = s.writeTypedSecretPayload(ctx, entry.TargetScopeID, entry.Name, r.Type, r.Payload, entry.TargetBefore == "", "", meta); err != nil {
				return fmt.Errorf("destination write failed; sources retained: %w", err)
			}
			target, err = s.GetTypedSecret(entry.TargetScopeID, entry.Name)
		}
		if err != nil {
			return err
		}
		if target.RecordTags[moveMarker] != j.ID {
			return errors.New("destination conflict; sources retained")
		}
		if !reflect.DeepEqual(target.Payload, r.Payload) || (!slices.Equal(target.OrganizationTags, r.OrganizationTags) && !(entry.TargetID == "" && slices.Equal(target.OrganizationTags, entry.TargetTagsBefore))) {
			return errors.New("move destination changed; sources retained")
		}
		if err = s.copyOrganizationTags(r, entry.TargetScopeID, entry.Name); err != nil {
			return err
		}
		entry.TargetID = target.ID
		if err = s.saveMove(&j); err != nil {
			return err
		}
	}
	if err := s.verifyMoveTargets(&j, sources); err != nil {
		return err
	}
	if j.Complete {
		return nil
	}
	if err := confirm(s, ctx, &j); err != nil {
		return fmt.Errorf("destination not confirmed; sources retained; repeat the same move to resume: %w", err)
	}
	if err := s.verifyMoveTargets(&j, sources); err != nil {
		return err
	}
	if err := s.checkMoveReferences(&j); err != nil {
		return err
	}
	// Recheck all sources before the first tombstone, including after sync released
	// the lock. A concurrent edit must not be removed by a stale move.
	for _, entry := range j.Entries {
		if err := s.checkMoveSourceCurrent(entry); err != nil {
			return err
		}
	}
	for i := range j.Entries {
		entry := &j.Entries[i]
		if entry.Archived {
			continue
		}
		_, currentErr := s.GetTypedSecret(entry.ScopeID, entry.Name)
		if currentErr != nil && !errors.Is(currentErr, ErrTypedSecretNotFound) {
			return currentErr
		}
		if currentErr == nil {
			if err := s.RemoveTypedSecret(ctx, entry.ScopeID, entry.Name); err != nil {
				return fmt.Errorf("source archive incomplete; repeat the same move to resume: %w", err)
			}
		}
		entry.Archived = true
		if err := s.saveMove(&j); err != nil {
			return err
		}
	}
	j.Complete = true
	if err := s.saveMove(&j); err != nil {
		return err
	}
	kinds := map[string]ItemKind{}
	for _, r := range sources {
		kind, _ := OrganizationKind(r.Type)
		kinds[kind.Command] = kind
	}
	for _, kind := range kinds {
		hooksFor(kind).after(s)
	}
	return nil
}

func (s *Session) moveSource(entry moveEntry) (*TypedRecord, error) {
	history, err := s.SecretHistory(entry.ScopeID, entry.Name)
	if err != nil {
		return nil, err
	}
	for _, version := range history {
		if version.EventID == entry.SourceEvent && version.SecretID == entry.SourceID && version.Record != nil {
			r := version.Record
			return &TypedRecord{ID: entry.SourceID, ScopeID: entry.ScopeID, Name: r.Name, Type: r.Type, Payload: r.Payload, SchemaVersion: r.SchemaVersion, RecordTags: maps.Clone(r.Tags), OrganizationTags: slices.Clone(entry.Tags), Revision: entry.SourceEvent}, nil
		}
	}
	return nil, errors.New("move source history is unavailable")
}
func (s *Session) checkMoveSourceCurrent(entry moveEntry) error {
	r, err := s.GetTypedSecret(entry.ScopeID, entry.Name)
	if errors.Is(err, ErrTypedSecretNotFound) {
		// A crash can happen after the tombstone but before journal persistence.
		if entry.TargetID != "" {
			return nil
		}
		return errors.New("move source disappeared before copying")
	}
	if err != nil {
		return err
	}
	if entry.Archived || r.ID != entry.SourceID || r.Revision != entry.SourceEvent || !slices.Equal(r.OrganizationTags, entry.Tags) {
		return errors.New("move source changed; no further sources archived")
	}
	return nil
}
func (s *Session) verifyMoveTargets(j *moveJournal, sources []*TypedRecord) error {
	for i, entry := range j.Entries {
		r, err := s.GetTypedSecret(entry.TargetScopeID, entry.Name)
		if err != nil {
			return errors.New("move destination is unavailable; sources retained")
		}
		expected := sources[i]
		tags := maps.Clone(r.RecordTags)
		delete(tags, moveMarker)
		expectedTags := maps.Clone(expected.RecordTags)
		delete(expectedTags, moveMarker)
		if r.ID != entry.TargetID || r.RecordTags[moveMarker] != j.ID || r.Type != expected.Type || r.SchemaVersion != expected.SchemaVersion || !reflect.DeepEqual(r.Payload, expected.Payload) || !maps.Equal(tags, expectedTags) || !slices.Equal(r.OrganizationTags, expected.OrganizationTags) {
			return errors.New("move destination changed; sources retained")
		}
	}
	return nil
}

func (s *Session) checkMoveReferences(j *moveJournal) error {
	// Inventory exposes just host key/proxy names, not credentials. Check each
	// source scope so unrelated scopes are not read by a restricted operation.
	inventories := map[string][]OrganizationItem{}
	for _, entry := range j.Entries {
		for _, scope := range []string{entry.ScopeID, entry.TargetScopeID} {
			if _, ok := inventories[scope]; !ok {
				items, err := s.OrganizationInventory(OrganizationFilter{Scope: scope})
				if err != nil {
					return err
				}
				inventories[scope] = items
			}
		}
	}
	destination := func(scope, name string) string {
		for _, entry := range j.Entries {
			if entry.ScopeID == scope && entry.Name == name {
				return entry.TargetScopeID
			}
		}
		return scope
	}
	for scope, items := range inventories {
		for _, item := range items {
			for _, ref := range item.References {
				hostScope := destination(scope, item.Name)
				keyScope := destination(scope, ref)
				if hostScope == keyScope {
					continue
				}
				found := false
				for _, candidate := range inventories[hostScope] {
					if candidate.Name == ref && destination(hostScope, ref) == hostScope {
						found = true
					}
				}
				for _, entry := range j.Entries {
					if entry.Name == ref && entry.TargetScopeID == hostScope {
						found = true
					}
				}
				if !found {
					return errors.New("move would break a host key or jump-host reference; include related entries in the same move")
				}
				expected, err := s.GetTypedSecret(scope, ref)
				if errors.Is(err, ErrTypedSecretNotFound) {
					for _, entry := range j.Entries {
						if entry.ScopeID == scope && entry.Name == ref {
							expected, err = s.moveSource(entry)
							break
						}
					}
				}
				if err != nil {
					return errors.New("host dependency cannot be verified")
				}
				actual, actualErr := s.GetTypedSecret(hostScope, ref)
				for _, entry := range j.Entries {
					if entry.TargetScopeID == hostScope && entry.Name == ref {
						actual, actualErr = s.moveSource(entry)
						break
					}
				}
				if actualErr != nil || actual.Type != expected.Type || !reflect.DeepEqual(actual.Payload, expected.Payload) {
					return errors.New("destination has a different host dependency; resolve it before moving")
				}

			}
		}
	}
	return nil
}

func (s *Session) confirmMoveDestinations(ctx context.Context, j *moveJournal) error {
	scopes := map[string]bool{}
	synced := false
	for _, entry := range j.Entries {
		scopes[entry.TargetScopeID] = true
		for _, scope := range []string{entry.ScopeID, entry.TargetScopeID} {
			sd := s.Body.Scopes[scope]
			if len(sd.PerServer) > 0 || sd.PushFloor > 0 || len(sd.LastSTH) > 0 {
				synced = true
			}
		}
	}
	if !synced {
		return nil
	}
	server, err := ResolvePrimary("")
	if err != nil {
		return err
	}
	primary, err := canon.ParseURL(server)
	if err != nil {
		return err
	}
	if _, ok := s.Body.PinnedServers[primary.String()]; !ok {
		return errors.New("primary is not already trusted; sync explicitly before moving")
	}
	guard := s.organizationCheck
	s.Close()
	budget := &syncRunBudget{scopes: scopes}
	syncErr := runSyncBatches(ctx, server, budget, runSyncRound)
	// Reopen even after failure, so callers cannot continue with a stale session.
	reopenCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	fresh, err := Open(reopenCtx)
	if err != nil {
		return fmt.Errorf("could not reopen vault after sync: %w", err)
	}
	*s = *fresh
	s.organizationCheck = guard
	s.ctx = ctx
	if syncErr != nil {
		return syncErr
	}
	for scope := range scopes {
		sd := s.Body.Scopes[scope]
		if sd.PushFloorFor(primary.String()) <= sd.ChainTip.Seq {
			return errors.New("primary has not acknowledged the complete destination")
		}
	}
	return nil
}
