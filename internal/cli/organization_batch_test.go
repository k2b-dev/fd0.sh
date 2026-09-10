package cli

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestOrganizationBatchPreflightAndDryRun(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		for _, name := range []string{"one", "two"} {
			if err := s.SetTypedSecret(ctx, scope, name, "kv.string", "BATCH_CANARY"); err != nil {
				t.Fatal(err)
			}
		}
		items, err := s.OrganizationInventory(OrganizationFilter{Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		request := OrganizationBatch{Items: items, Operation: "add", Tags: []string{"Prod"}, DryRun: true}
		result, err := s.ApplyOrganizationBatch(ctx, request)
		if err != nil || len(result.Completed) != 0 || !slices.Equal(result.Items[0].Tags, []string{"Prod"}) {
			t.Fatal(result, err)
		}
		unchanged, _ := s.OrganizationInventory(OrganizationFilter{Scope: scope})
		if len(unchanged[0].Tags) != 0 {
			t.Fatal("dry run wrote tags")
		}
		if err := s.ChangeItemTags(ctx, scope, items[1].Name, "add", []string{"Later"}); err != nil {
			t.Fatal(err)
		}
		request.DryRun = false
		if _, err := s.ApplyOrganizationBatch(ctx, request); err == nil {
			t.Fatal("stale batch accepted")
		}
		first, _ := s.GetTypedSecret(scope, items[0].Name)
		if len(first.OrganizationTags) != 0 {
			t.Fatal("batch wrote before checking all entries")
		}
		request.Items, _ = s.OrganizationInventory(OrganizationFilter{Scope: scope})
		result, err = s.ApplyOrganizationBatch(ctx, request)
		if err != nil || len(result.Completed) != 2 {
			t.Fatal(result, err)
		}
	})
}

func TestOrganizationBatchResumesOnlyItsReviewedMove(t *testing.T) {
	ctx, scope := newTestVault(t)
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		for _, name := range []string{"one", "two"} {
			if err := s.SetTypedSecret(ctx, scope, name, "kv.string", "RESUME_CANARY"); err != nil {
				t.Fatal(err)
			}
		}
		items, _ := s.OrganizationInventory(OrganizationFilter{Scope: scope})
		request := OrganizationBatch{Items: items, Operation: "move", TargetScopeID: "destination", Resume: true}
		if _, err := s.ApplyOrganizationBatch(ctx, request); err == nil {
			t.Fatal("resume started a new move")
		}
		moves := []OrganizationMove{}
		for _, item := range items {
			moves = append(moves, OrganizationMove{ScopeID: scope, Name: item.Name, TargetScopeID: "destination"})
		}
		if err := s.moveOrganizationItems(ctx, moves, func(*Session, context.Context, *moveJournal) error { return errors.New("offline") }); err == nil {
			t.Fatal("move should be pending")
		}
		result, err := s.ApplyOrganizationBatch(ctx, request)
		if err != nil || len(result.Completed) != 2 {
			t.Fatal(result, err)
		}
		if _, err := s.ApplyOrganizationBatch(ctx, request); err != nil {
			t.Fatal("completed retry failed", err)
		}
		if err := s.SavePlainSecret(ctx, scope, "one", "RESTORED_CANARY", true); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApplyOrganizationBatch(ctx, request); err == nil {
			t.Fatal("completed resume accepted a recreated source")
		}
		restored, err := s.GetTypedSecret(scope, "one")
		if err != nil || restored.Payload != "RESTORED_CANARY" {
			t.Fatal("completed resume moved a new source", err)
		}
	})
}
