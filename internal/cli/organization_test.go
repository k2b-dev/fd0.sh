package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

func TestOrganizationPreservesMetadataAndHidesContent(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		base := &proto.SecretRecord{SchemaVersion: 7, Tags: map[string]string{"future": "keep"}}
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "CANARY_NEVER_IN_METADATA", false, "", base); err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeItemTags(ctx, scope, "token", "add", []string{"Prod", "Team A"}); err != nil {
			t.Fatal(err)
		}
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "SECOND_CANARY", false, ""); err != nil {
			t.Fatal(err)
		}
		record, err := s.GetTypedSecret(scope, "token")
		if err != nil {
			t.Fatal(err)
		}
		if record.SchemaVersion != 7 || record.RecordTags["future"] != "keep" {
			t.Fatal("ordinary write lost metadata")
		}
		items, err := s.OrganizationInventory(OrganizationFilter{Scope: scope, Tags: []string{"prod"}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(items)
		if len(items) != 1 || strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "future") {
			t.Fatal("organization output leaked or filtered incorrectly", string(raw))
		}
		oldID := items[0].ID
		oldRevision := items[0].Revision
		// Simulate the old writer's empty record Tags map. Supplemental tags are
		// independent, preserved in the existing encrypted scope metadata record.
		if err := s.writeTypedSecretPayload(ctx, scope, "token", "kv.string", "LEGACY_CANARY", false, "", &proto.SecretRecord{SchemaVersion: 1}); err != nil {
			t.Fatal(err)
		}
		items, err = s.OrganizationInventory(OrganizationFilter{Scope: scope, Tags: []string{"prod"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].ID != oldID || items[0].Revision == oldRevision {
			t.Fatal("identity or legacy tag preservation failed")
		}
		record, err = s.GetTypedSecret(scope, "token")
		if err != nil {
			t.Fatal(err)
		}
		if err = s.RenameOrganizationItem(ctx, record, "renamed"); err != nil {
			t.Fatal(err)
		}
		renamed, err := s.GetTypedSecret(scope, "renamed")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(renamed.OrganizationTags, []string{"Prod", "Team A"}) {
			t.Fatal(renamed.OrganizationTags)
		}
		if err = s.ChangeItemTags(ctx, scope, "renamed", "remove", []string{"PROD"}); err != nil {
			t.Fatal(err)
		}
		items, err = s.OrganizationInventory(OrganizationFilter{Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || !reflect.DeepEqual(items[0].Tags, []string{"Team A"}) {
			t.Fatal(items)
		}
	})
}

func TestOrganizationTagSemantics(t *testing.T) {
	tags, err := changedItemTags("ssh", []string{"Prod", "prod"}, "remove", []string{"Prod"})
	if err != nil || !reflect.DeepEqual(tags, []string{"prod"}) {
		t.Fatal(tags, err)
	}
	if _, err := changedItemTags("ssh", nil, "add", []string{"a,b"}); err == nil {
		t.Fatal("CSV injection accepted")
	}
	tags, err = changedItemTags("key", []string{"Prod"}, "add", []string{"prod"})
	if err != nil || len(tags) != 1 {
		t.Fatal(tags, err)
	}
	tags, err = changedItemTags("key", []string{"Prod"}, "clear", nil)
	if err != nil || len(tags) != 0 {
		t.Fatal(tags, err)
	}
}

func TestOrganizationUsesExistingInfrastructureTags(t *testing.T) {
	ctx, scope := newTestVault(t)
	isolation := shortTempDir(t)
	t.Setenv("HOME", isolation)
	t.Setenv("FD0_KUBE_CONFIG_PATH", isolation+"/kube.conf")
	t.Setenv("FD0_TALOS_CONFIG_PATH", isolation+"/talos.conf")
	t.Setenv("FD0_KUBE_USER_CONFIG", isolation+"/user-kube.conf")
	t.Setenv("FD0_TALOS_USER_CONFIG", isolation+"/user-talos.conf")
	withSession(t, ctx, func(s *Session) {
		tags := []string{"Prod", "prod", "a,b"}
		fixtures := []struct {
			name, kind string
			payload    any
		}{
			{"kube:cluster", kubeconfig.TypeKubeconfig, (&kubeconfig.Kubeconfig{Name: "cluster", Server: "https://example.invalid", InsecureSkipTLSVerify: true, Token: "NATIVE_CANARY", Tags: tags}).Marshal()},
			{"talos:cluster", talosctx.TypeTalosContext, (&talosctx.TalosContext{Name: "cluster", Endpoints: []string{"example.invalid"}, CA: "Y2E=", Crt: "Y3J0", Key: "a2V5", Tags: tags}).Marshal()},
		}
		for _, fixture := range fixtures {
			kind := fixture.kind
			raw, _ := json.Marshal(fixture.payload)
			payload := map[string]any{}
			if err := json.Unmarshal(raw, &payload); err != nil {
				t.Fatal(err)
			}
			payload["future"] = "NATIVE_CANARY"

			if err := s.SetTypedSecret(ctx, scope, fixture.name, kind, payload); err != nil {
				t.Fatal(err)
			}
			if err := s.ChangeItemTags(ctx, scope, fixture.name, "remove", []string{"Prod"}); err != nil {
				t.Fatal(err)
			}
			record, err := s.GetTypedSecret(scope, fixture.name)
			if err != nil {
				t.Fatal(err)
			}
			tags, err := record.ItemTags()
			if err != nil || !reflect.DeepEqual(tags, []string{"prod", "a,b"}) {
				t.Fatal(tags, err)
			}
			raw, _ = record.PayloadJSON()
			if !strings.Contains(string(raw), "NATIVE_CANARY") {
				t.Fatal("unknown field removed")
			}
			if len(record.OrganizationTags) != 0 {
				t.Fatal("parallel supplemental tags created")
			}
		}
	})
}

func TestOrganizationPlainSecretEditPreservesLiteralValuesAndTags(t *testing.T) {
	ctx, scope := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SavePlainSecret(ctx, scope, "token", "-", true); err != nil {
			t.Fatal(err)
		}
		if err := s.ChangeItemTags(ctx, scope, "token", "add", []string{"Prod"}); err != nil {
			t.Fatal(err)
		}
		record, err := s.GetTypedSecret(scope, "token")
		if err != nil || record.Payload != "-" {
			t.Fatal("literal value changed", err)
		}
		if err := s.RenameOrganizationItem(ctx, record, "new-name"); err != nil {
			t.Fatal(err)
		}
		if err := s.SavePlainSecret(ctx, scope, "new-name", "new\nvalue", false); err != nil {
			t.Fatal(err)
		}
		record, err = s.GetTypedSecret(scope, "new-name")
		if err != nil || record.Payload != "new\nvalue" || !reflect.DeepEqual(record.OrganizationTags, []string{"Prod"}) {
			t.Fatal("edit changed content or tags", err)
		}
	})
}
