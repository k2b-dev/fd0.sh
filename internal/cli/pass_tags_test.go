package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

func TestPassTagCatalogAndFilters(t *testing.T) {
	newRow := func(scope string, tags []string) passRow {
		item := passitem.New("Login", nil)
		_, _ = item.SetTags(tags)
		return passRow{ScopeID: scope, Name: "pass:Login", Item: item}
	}
	rows := []passRow{newRow("a", []string{"Work", "Team A"}), newRow("a", []string{"work"}), newRow("b", []string{"Work"}), newRow("a", nil)}
	catalog := passTagCatalog(rows)
	if !reflect.DeepEqual(catalog, []passTagRow{{ScopeID: "a", Tag: "Team A", Count: 1}, {ScopeID: "a", Tag: "Work", Count: 2}, {ScopeID: "b", Tag: "Work", Count: 1}}) {
		t.Fatal(catalog)
	}
	if len(filterPassTags(rows, PassTagFilter{Tags: []string{"work", "team a"}})) != 1 {
		t.Fatal("AND filter")
	}
	if len(filterPassTags(rows, PassTagFilter{Untagged: true})) != 1 {
		t.Fatal("untagged filter")
	}
	if _, err := (PassTagFilter{Tags: []string{"Work"}, Untagged: true}).validate(); err == nil {
		t.Fatal("ambiguous filter accepted")
	}
	if !passMatches(rows[0].Item, "team a", "") {
		t.Fatal("tag search")
	}
	if passMatches(rows[0].Item, "", "https://work") {
		t.Fatal("tags must not affect URL matching")
	}
	raw, _ := json.Marshal(passSummaryRows(nil, rows))
	var output []struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &output); err != nil || len(output[0].Tags) != 2 {
		t.Fatal(string(raw), err)
	}
	empty, _ := json.Marshal(passTagCatalog(nil))
	if string(empty) != "[]" {
		t.Fatal(string(empty))
	}
}

func TestPassTagIsolatedWriteCompatibility(t *testing.T) {
	// All state and IPC belong to this test's in-process agent. No installed
	// binary, SSH configuration, agent process, or production vault is used.
	isolation := shortTempDir(t)
	t.Setenv("FD0_SSH_CONFIG_PATH", filepath.Join(isolation, "ssh.conf"))
	t.Setenv("FD0_SSH_SOCK", filepath.Join(isolation, "ssh.sock"))
	t.Setenv("FD0_AGENT_SYNC_DISABLED", "1")
	t.Setenv("FD0_AGENT_BIN", filepath.Join(isolation, "no-agent-process"))
	ctx, scope := newTestVault(t)
	if err := RunPassAdd(ctx, PassAddOpts{Name: "Login", Scope: scope, URL: []string{"https://example.com"}, Tags: []string{"Work"}}); err != nil {
		t.Fatal(err)
	}
	if err := RunPassFieldSet(ctx, PassFieldSetOpts{Item: "Login", Scope: scope, Path: "password", Value: "synthetic-only", Secret: true}); err != nil {
		t.Fatal(err)
	}
	read := func(name string) (*passitem.Item, int) {
		t.Helper()
		var item *passitem.Item
		var count int
		withSession(t, ctx, func(s *Session) {
			record, err := s.GetTypedSecret(scope, "pass:"+name)
			if err != nil {
				t.Fatal(err)
			}
			item, err = decodePassRecord(*record)
			if err != nil {
				t.Fatal(err)
			}
			history, err := s.SecretHistory(scope, "pass:"+name)
			if err != nil {
				t.Fatal(err)
			}
			count = len(history)
		})
		return item, count
	}
	_, before := read("Login")
	for _, change := range []struct {
		op   string
		tags []string
	}{{"add", []string{"work"}}, {"rm", []string{"missing"}}} {
		if err := RunPassTagsChange(ctx, scope, "Login", change.op, change.tags); err != nil {
			t.Fatal(err)
		}
	}
	_, after := read("Login")
	if before != after {
		t.Fatal("idempotent tags created revisions")
	}
	if err := RunPassTagsChange(ctx, scope, "Login", "add", []string{"Server"}); err != nil {
		t.Fatal(err)
	}
	item, _ := read("Login")
	if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
		t.Fatal(item.Tags())
	}
	title := "Edited"
	if err := RunPassEdit(ctx, PassEditOpts{Name: "Login", Scope: scope, Title: &title}); err != nil {
		t.Fatal(err)
	}
	credentials, err := BrowserCredentialsForOrigin(ctx, "https://example.com")
	if err != nil || len(credentials) != 1 {
		t.Fatal(credentials, err)
	}
	_, err = UpdateBrowserLogin(ctx, BrowserUpdateLoginInput{Origin: "https://example.com", CredentialID: credentials[0].ID, Revision: credentials[0].Revision, Title: "Browser edit", Username: "test", Password: "synthetic-only"})
	if err != nil {
		t.Fatal(err)
	}
	item, _ = read("Login")
	if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
		t.Fatal("browser edit lost tags", item.Meta)
	}
	// Optional historical CLI built from the release tag, never PATH's fd0.
	if legacy := os.Getenv("FD0_TAGS_LEGACY_CLI"); legacy != "" {
		if !filepath.IsAbs(legacy) {
			t.Fatal("historical CLI must have an explicit absolute path")
		}
		cmd := exec.CommandContext(ctx, legacy, "pass", "edit", "Login", "--scope", scope, "--title", "Legacy edit")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("legacy edit: %v: %s", err, out)
		}
		item, _ = read("Login")
		if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
			t.Fatal("legacy edit lost tags")
		}
	}
	if legacy := os.Getenv("FD0_TAGS_LEGACY_BRIDGE"); legacy != "" {
		if !filepath.IsAbs(legacy) {
			t.Fatal("historical bridge must have an explicit absolute path")
		}
		t.Setenv("FD0_DESKTOP_MODE", "isolated")
		if err := os.WriteFile(filepath.Join(os.Getenv("FD0_HOME"), ".desktop-isolated"), []byte("fd0-desktop-isolated-v1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		request, err := json.Marshal(map[string]any{
			"version": 1, "id": "legacy-tags", "method": "pass.save",
			"params": map[string]any{"scopeId": scope, "recordName": "Login", "item": map[string]any{"title": "Login", "urls": item.URLs, "fields": item.Fields}},
		})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, legacy)
		cmd.Stdin = bytes.NewReader(append(request, '\n'))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("legacy bridge: %v", err)
		}
		var response struct {
			Error  json.RawMessage `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(out, &response); err != nil || len(response.Result) == 0 || (len(response.Error) != 0 && string(response.Error) != "null") {
			t.Fatalf("legacy bridge response: %s: %v", out, err)
		}
		item, _ = read("Login")
		if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
			t.Fatal("legacy desktop edit lost tags")
		}
	}
	if err := RunPassRename(ctx, scope, "Login", "Renamed", false); err != nil {
		t.Fatal(err)
	}
	item, _ = read("Renamed")
	if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
		t.Fatal("rename lost tags")
	}
	if err := RunScopeCreate(ctx, "destination"); err != nil {
		t.Fatal(err)
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.MoveItem(ctx, KindPass, "Renamed", scope, "destination", false); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		destination, err := s.resolveScopeID("destination")
		if err != nil {
			t.Fatal(err)
		}
		scope = destination
	})
	item, _ = read("Renamed")
	if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
		t.Fatal("move lost tags")
	}
	var restoreSeq uint64
	withSession(t, ctx, func(s *Session) {
		history, err := s.SecretHistory(scope, "pass:Renamed")
		if err != nil {
			t.Fatal(err)
		}
		restoreSeq = history[0].Seq
	})
	if err := RunPassTagsChange(ctx, scope, "Renamed", "clear", nil); err != nil {
		t.Fatal(err)
	}
	item, _ = read("Renamed")
	if len(item.Tags()) != 0 {
		t.Fatal("clear failed")
	}
	if err := RunItemRestore(ctx, KindPass, scope, "Renamed", restoreSeq); err != nil {
		t.Fatal(err)
	}
	item, _ = read("Renamed")
	if !reflect.DeepEqual(item.Tags(), []string{"Work", "Server"}) {
		t.Fatal("history restore lost tags")
	}
}
