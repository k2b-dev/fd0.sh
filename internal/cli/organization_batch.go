package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// OrganizationBatch is for trusted CLI/Desktop callers. Restricted agents use
// immutable proposals and independent approval instead.
type OrganizationBatch struct {
	Scopes        []OrganizationScopePolicy `json:"scopes,omitempty"`
	Items         []OrganizationItem        `json:"items"`
	Operation     string                    `json:"operation"`
	Tags          []string                  `json:"tags,omitempty"`
	TargetScopeID string                    `json:"targetScopeId,omitempty"`
	Resume        bool                      `json:"resume,omitempty"`
	DryRun        bool                      `json:"dryRun"`
}
type OrganizationBatchResult struct {
	Scopes    []OrganizationScopePolicy `json:"scopes,omitempty"`
	Items     []OrganizationItem        `json:"items"`
	Completed []string                  `json:"completed"`
	DryRun    bool                      `json:"dryRun"`
}

func (s *Session) ApplyOrganizationBatch(ctx context.Context, request OrganizationBatch) (OrganizationBatchResult, error) {
	result := OrganizationBatchResult{Items: []OrganizationItem{}, Completed: []string{}, DryRun: request.DryRun}
	if len(request.Items) == 0 || len(request.Items) > 100 {
		return result, errors.New("select 1–100 items")
	}
	if len(request.Scopes) > 0 {
		if err := s.checkOrganizationPolicies(request.Scopes); err != nil {
			return result, err
		}
		guard := s.organizationCheck
		s.organizationCheck = func() error {
			if guard != nil {
				if err := guard(); err != nil {
					return err
				}
			}
			return s.checkOrganizationPolicies(request.Scopes)
		}
		defer func() { s.organizationCheck = guard }()
	}
	if request.Resume {
		if request.Operation != "move" || request.DryRun {
			return result, errors.New("resume requires a saved move request without --dry-run")
		}
		target, err := s.resolveScopeID(request.TargetScopeID)
		if err != nil {
			return result, err
		}
		moves := []OrganizationMove{}
		for _, item := range request.Items {
			moves = append(moves, OrganizationMove{ScopeID: item.ScopeID, Name: item.Name, TargetScopeID: target})
		}
		slices.SortFunc(moves, func(a, b OrganizationMove) int {
			return strings.Compare(a.ScopeID+"/"+a.Name+"/"+a.TargetScopeID, b.ScopeID+"/"+b.Name+"/"+b.TargetScopeID)
		})
		raw, _ := json.Marshal(moves)
		id := fmt.Sprintf("%x", sha256.Sum256(raw))
		var journal moveJournal
		if err := readOrganizationJSON(s.moveJournalPath(id), &journal); err != nil {
			return result, errors.New("no matching pending move journal")
		}
		for _, item := range request.Items {
			index := slices.IndexFunc(journal.Entries, func(entry moveEntry) bool {
				return entry.ScopeID == item.ScopeID && entry.Name == item.Name && entry.SourceID == item.ID
			})
			if index < 0 {
				return result, errors.New("request does not match the pending move")
			}
			source, err := s.moveSource(journal.Entries[index])
			if err != nil {
				return result, err
			}
			tags, err := source.ItemTags()
			if err != nil || organizationRevision(source.Revision, tags) != item.Revision {
				return result, errors.New("reviewed revision does not match pending move")
			}
		}
		if journal.Complete {
			for _, entry := range journal.Entries {
				if err := s.checkMoveSourceCurrent(entry); err != nil {
					return result, err
				}
			}
			sources := make([]*TypedRecord, len(journal.Entries))
			for i, entry := range journal.Entries {
				source, err := s.moveSource(entry)
				if err != nil {
					return result, err
				}
				sources[i] = source
			}
			if err := s.verifyMoveTargets(&journal, sources); err != nil {
				return result, err
			}
			for _, item := range request.Items {
				result.Completed = append(result.Completed, item.ID)
			}
			return result, nil
		}
		if err := s.MoveOrganizationItems(ctx, moves); err != nil {
			return result, err
		}
		for _, item := range request.Items {
			result.Completed = append(result.Completed, item.ID)
		}
		return result, nil
	}

	if !slices.Contains([]string{"add", "remove", "set", "clear", "move"}, request.Operation) {
		return result, errors.New("unsupported batch operation")
	}
	inventory := map[string][]OrganizationItem{}
	seen := map[string]bool{}
	moves := []OrganizationMove{}
	journal := moveJournal{}
	for _, expected := range request.Items {
		if expected.ScopeID == "" || expected.ID == "" || expected.Revision == "" {
			return result, errors.New("each item requires an explicit scope, ID and revision")
		}
		key := expected.ScopeID + "/" + expected.ID
		if seen[key] {
			return result, errors.New("duplicate item")
		}
		seen[key] = true
		if _, ok := inventory[expected.ScopeID]; !ok {
			var err error
			inventory[expected.ScopeID], err = s.OrganizationInventory(OrganizationFilter{Scope: expected.ScopeID})
			if err != nil {
				return result, err
			}
		}
		index := slices.IndexFunc(inventory[expected.ScopeID], func(item OrganizationItem) bool { return item.ID == expected.ID && item.Revision == expected.Revision })
		if index < 0 {
			return result, errors.New("item changed; refresh the selection before applying")
		}
		item := inventory[expected.ScopeID][index]
		if request.Operation == "move" {
			target, err := s.resolveScopeID(request.TargetScopeID)
			if err != nil {
				return result, err
			}
			if target == item.ScopeID {
				return result, errors.New("source and destination scopes are the same")
			}
			if _, err := s.GetTypedSecret(target, item.Name); err == nil {
				return result, errors.New("destination item already exists")
			} else if !errors.Is(err, ErrTypedSecretNotFound) {
				return result, err
			}
			move := OrganizationMove{ScopeID: item.ScopeID, Name: item.Name, TargetScopeID: target}
			moves = append(moves, move)
			source, err := s.GetTypedSecret(item.ScopeID, item.Name)
			if err != nil {
				return result, err
			}
			journal.Entries = append(journal.Entries, moveEntry{OrganizationMove: move, SourceID: source.ID, SourceEvent: source.Revision, Tags: source.OrganizationTags})
			item.ScopeID = target
			item.Scope = s.Body.Scopes[target].Label
		} else {
			var err error
			item.Tags, err = changedItemTags(item.Kind, item.Tags, request.Operation, request.Tags)
			if err != nil {
				return result, err
			}
		}
		result.Items = append(result.Items, item)
	}
	if request.Operation == "move" {
		if err := s.checkMoveReferences(&journal); err != nil {
			return result, err
		}
	}
	checkedScopes := map[string]bool{}
	for _, item := range request.Items {
		checkedScopes[item.ScopeID] = true
	}
	if request.Operation == "move" {
		target, err := s.resolveScopeID(request.TargetScopeID)
		if err != nil {
			return result, err
		}
		checkedScopes[target] = true
	}
	for scope := range checkedScopes {
		policy, err := s.organizationScopePolicy(scope)
		if err != nil {
			return result, err
		}
		result.Scopes = append(result.Scopes, policy)
	}
	slices.SortFunc(result.Scopes, func(a, b OrganizationScopePolicy) int { return strings.Compare(a.ID, b.ID) })
	previousGuard := s.organizationCheck
	s.organizationCheck = func() error {
		if previousGuard != nil {
			if err := previousGuard(); err != nil {
				return err
			}
		}
		return s.checkOrganizationPolicies(result.Scopes)
	}
	defer func() { s.organizationCheck = previousGuard }()

	if request.DryRun {
		return result, nil
	}
	if request.Operation == "move" {
		if err := s.MoveOrganizationItems(ctx, moves); err != nil {
			return result, err
		}
		for _, item := range request.Items {
			result.Completed = append(result.Completed, item.ID)
		}
		return result, nil
	}
	for i, expected := range request.Items {
		if err := s.ChangeItemTags(ctx, expected.ScopeID, result.Items[i].Name, "set", result.Items[i].Tags); err != nil {
			return result, err
		}
		result.Completed = append(result.Completed, expected.ID)
	}
	return result, nil
}
