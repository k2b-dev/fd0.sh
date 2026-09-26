package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// newTestVault builds a throwaway fd0 home under t.TempDir() with a real
// in-process agent, an unlocked vault and one scope. Everything the history
// path touches (agent-routed signing, agent-routed sealed-box opening, the
// flock, the on-disk chain) is the production code path — only HOME moves.
// The production ~/.fd0 is never involved.
func newTestVault(t *testing.T) (context.Context, string) {
	ctx, scope, _ := newTestVaultWithAgent(t)
	return ctx, scope
}

func newTestVaultWithAgent(t *testing.T) (context.Context, string, *agent.Server) {
	t.Helper()
	home := shortTempDir(t)
	t.Setenv("FD0_HOME", home)
	t.Setenv("FD0_LOCK_WAIT", "5s")
	ctx := context.Background()

	passphrase := []byte("correct horse battery staple")
	if _, err := InitWithPassphrase(ctx, passphrase); err != nil {
		t.Fatal(err)
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	server, err := agent.Listen(paths, agent.Config{IdleTimeout: time.Hour, MaxLifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	serveCtx, cancel := context.WithCancel(ctx)
	go func() { _ = server.Serve(serveCtx) }()
	t.Cleanup(func() {
		cancel()
		server.Close()
	})
	client := agent.NewClient(paths.AgentSock)
	if !waitAgentReady(client) {
		t.Fatal("agent did not become ready")
	}
	if _, err := client.Unlock(paths.Vault, paths.UserChain, proto.AuthPassphrase,
		agent.UnlockCredential{Passphrase: passphrase}); err != nil {
		t.Fatal(err)
	}
	if err := RunScopeCreate(ctx, "history-test"); err != nil {
		t.Fatal(err)
	}
	session, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var scopeID string
	for id := range session.Body.Scopes {
		scopeID = id
	}
	if scopeID == "" {
		t.Fatal("no scope was created")
	}
	return ctx, scopeID, server
}

// shortTempDir is t.TempDir() with TMPDIR pinned to /tmp when available. The
// agent listens on a unix socket inside the fd0 home, and macOS caps a socket
// path at ~104 bytes — the default per-test TMPDIR there is long enough to
// blow that budget on its own. Still a t.TempDir(): the OS cleans it up and
// nothing outside it is touched.
func shortTempDir(t *testing.T) string {
	t.Helper()
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		t.Setenv("TMPDIR", "/tmp")
	}
	return t.TempDir()
}

func waitAgentReady(client *agent.Client) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if client.IsRunning() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// withSession runs fn against a freshly opened session, closing it after.
// Each call is a separate CLI invocation, which is how the desktop bridge
// uses the session too.
func withSession(t *testing.T, ctx context.Context, fn func(*Session)) {
	t.Helper()
	session, err := Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	fn(session)
}

func passItemWithPassword(t *testing.T, title, password string) *passitem.Item {
	t.Helper()
	item := passitem.New(title, []string{"https://example.test"})
	field, err := passitem.NewStringField(passitem.FieldSecret, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("password", field); err != nil {
		t.Fatal(err)
	}
	return item
}

func scopeEventCount(t *testing.T, scopeID string) int {
	t.Helper()
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	events, err := chain.ReadScopeEvents(paths.ScopeChain(proto.MustParseScopeID(scopeID)))
	if err != nil {
		t.Fatal(err)
	}
	return len(events)
}

// TestSecretHistoryOrdersNewestFirstAndFlagsTombstones covers the listing
// contract: newest first, one entry per write, a deletion present and marked.
func TestSecretHistoryOrdersNewestFirstAndFlagsTombstones(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		for _, value := range []string{"v1", "v2", "v3"} {
			if err := s.SetTypedSecret(ctx, scopeID, "API_KEY", "kv.string", value); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.RemoveTypedSecret(ctx, scopeID, "API_KEY"); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 {
			t.Fatalf("history has %d entries, want 4: %+v", len(entries), entries)
		}
		if !entries[0].Tombstone() {
			t.Fatalf("newest entry should be the deletion: %+v", entries[0])
		}
		for i := 1; i < len(entries); i++ {
			if entries[i-1].Seq <= entries[i].Seq {
				t.Fatalf("entries are not newest-first: %d then %d", entries[i-1].Seq, entries[i].Seq)
			}
		}
		wantPayloads := []string{`"v3"`, `"v2"`, `"v1"`}
		for i, want := range wantPayloads {
			entry := entries[i+1]
			if entry.Tombstone() {
				t.Fatalf("entry %d unexpectedly a tombstone", i+1)
			}
			if entry.Record.Payload != want {
				t.Fatalf("entry %d payload=%v want %v", i+1, entry.Record.Payload, want)
			}
			if entry.Name != "API_KEY" || entry.EventID == "" || len(entry.Author) != 32 {
				t.Fatalf("entry %d metadata incomplete: %+v", i+1, entry)
			}
		}
		// All versions of one record share a single secret id.
		for _, entry := range entries {
			if entry.SecretID != entries[0].SecretID {
				t.Fatalf("history spans multiple secret ids: %q vs %q", entry.SecretID, entries[0].SecretID)
			}
		}
	})
}

func TestListDeletedTypedSecretsReturnsOnlyCurrentTombstones(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "gone", "kv.string", "before"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetTypedSecret(ctx, scopeID, "alive", "kv.string", "still here"); err != nil {
			t.Fatal(err)
		}
		if err := s.RemoveTypedSecret(ctx, scopeID, "gone"); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		deleted, err := s.ListDeletedTypedSecrets()
		if err != nil {
			t.Fatal(err)
		}
		if len(deleted) != 1 {
			t.Fatalf("deleted = %+v, want one item", deleted)
		}
		if deleted[0].ScopeID != scopeID || deleted[0].Name != "gone" || deleted[0].Type != "kv.string" {
			t.Fatalf("deleted item = %+v", deleted[0])
		}
		if deleted[0].DeletedSeq <= deleted[0].RestoreSeq {
			t.Fatalf("sequences = deleted %d restore %d", deleted[0].DeletedSeq, deleted[0].RestoreSeq)
		}
	})
}

// TestSecretHistoryFollowsIDAcrossRename pins the id-vs-name choice: history
// follows the secret ID, so versions written under the previous name stay in
// the list with their historical Name, and the old name no longer resolves.
func TestSecretHistoryFollowsIDAcrossRename(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "OLD_NAME", "kv.string", "v1"); err != nil {
			t.Fatal(err)
		}
	})
	// Rename in place: same secret id, new record name. This is what the
	// chain sees when a record is renamed without minting a new id.
	renameInPlace(t, ctx, scopeID, "OLD_NAME", "NEW_NAME", "v2")
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "NEW_NAME")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatalf("history has %d entries, want 2: %+v", len(entries), entries)
		}
		if entries[0].Name != "NEW_NAME" {
			t.Fatalf("newest entry name=%q", entries[0].Name)
		}
		if entries[1].Name != "OLD_NAME" {
			t.Fatalf("older entry should keep its historical name, got %q", entries[1].Name)
		}
		if entries[0].SecretID != entries[1].SecretID {
			t.Fatal("rename split the history across ids")
		}
		if _, err := s.SecretHistory(scopeID, "OLD_NAME"); !errors.Is(err, ErrTypedSecretNotFound) {
			t.Fatalf("old name still resolves: %v", err)
		}
	})
}

// renameInPlace rewrites the record under the same secret id with a new name,
// mirroring what a rename that reuses the id looks like on the chain.
func renameInPlace(t *testing.T, ctx context.Context, scopeID, oldName, newName, payload string) {
	t.Helper()
	withSession(t, ctx, func(s *Session) {
		st, err := s.replayAndCheckScope(scopeID)
		if err != nil {
			t.Fatal(err)
		}
		var sid string
		for id, cur := range st.SecretIndex {
			if cur.Record != nil && cur.Record.Name == oldName {
				sid = id
				break
			}
		}
		if sid == "" {
			t.Fatalf("record %q not found", oldName)
		}
		sd := s.Body.Scopes[scopeID]
		var oek proto.OEKEntry
		for _, entry := range sd.OEKs {
			if entry.Version == st.CurrentOEKVer {
				oek = entry
				break
			}
		}
		body := &proto.SecretBody{ID: sid, Record: &proto.SecretRecord{
			Name: newName, Type: "kv.string", SchemaVersion: 1, Payload: payload, Tags: map[string]string{},
		}}
		ev, err := chain.BuildSecretSet(AgentSigner{Agent: s.Agent}, s.UserSuperPub,
			proto.MustParseScopeID(scopeID), st.TipSeq, st.TipHash, oek.Key, oek.Version, body)
		if err != nil {
			t.Fatal(err)
		}
		if err := chain.AppendScope(s.Paths.ScopeChain(proto.MustParseScopeID(scopeID)), ev); err != nil {
			t.Fatal(err)
		}
		prefix, _ := ev.PrevHashInput()
		tipHash := proto.HashPrefix(prefix)
		sd.ChainTip = proto.ChainTip{Seq: st.TipSeq + 1, Hash: tipHash[:]}
		s.Body.Scopes[scopeID] = sd
		if err := s.ReSeal(); err != nil {
			t.Fatal(err)
		}
	})
}

// TestSecretHistoryReportsPassItemRevisionAndTimestamp checks that the
// per-version revision/updated_at come from inside the payload — the event
// envelope carries no timestamp at all.
func TestSecretHistoryReportsPassItemRevisionAndTimestamp(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	item := passItemWithPassword(t, "GitHub", "first-password")
	firstRevision, ok := metaRevision(item.Meta)
	if !ok {
		t.Fatal("fixture item has no revision")
	}
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, item.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	item.Touch()
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, item.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "pass:GitHub")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatalf("history has %d entries, want 2", len(entries))
		}
		if !entries[1].HasRevision || entries[1].Revision != firstRevision {
			t.Fatalf("older revision=%d has=%v want %d", entries[1].Revision, entries[1].HasRevision, firstRevision)
		}
		if !entries[0].HasRevision || entries[0].Revision != firstRevision+1 {
			t.Fatalf("newest revision=%d has=%v want %d", entries[0].Revision, entries[0].HasRevision, firstRevision+1)
		}
		for i, entry := range entries {
			if entry.UpdatedAt == "" {
				t.Fatalf("entry %d has no updated_at", i)
			}
		}
	})
}

// TestSecretHistoryOfKVStringHasNoRevision confirms a record type that does
// not track its own mtime reports "unknown" rather than a fabricated one.
func TestSecretHistoryOfKVStringHasNoRevision(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "PLAIN", "kv.string", "v1"); err != nil {
			t.Fatal(err)
		}
		entries, err := s.SecretHistory(scopeID, "PLAIN")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("entries=%d", len(entries))
		}
		if entries[0].HasRevision || entries[0].Revision != 0 || entries[0].UpdatedAt != "" {
			t.Fatalf("kv.string invented version metadata: %+v", entries[0])
		}
	})
}

// TestRestoreSecretVersionAppendsExactlyOneEvent is the core restore
// contract: the chain grows by one, history is preserved, and the current
// value equals the restored payload.
func TestRestoreSecretVersionAppendsExactlyOneEvent(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		for _, value := range []string{"v1", "v2", "v3"} {
			if err := s.SetTypedSecret(ctx, scopeID, "API_KEY", "kv.string", value); err != nil {
				t.Fatal(err)
			}
		}
	})
	var targetSeq uint64
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		targetSeq = entries[2].Seq // the oldest, "v1"
	})
	before := scopeEventCount(t, scopeID)
	withSession(t, ctx, func(s *Session) {
		if err := s.RestoreSecretVersion(ctx, scopeID, "API_KEY", targetSeq); err != nil {
			t.Fatal(err)
		}
	})
	after := scopeEventCount(t, scopeID)
	if after != before+1 {
		t.Fatalf("chain length %d → %d, want exactly one new event", before, after)
	}
	withSession(t, ctx, func(s *Session) {
		record, err := s.GetTypedSecret(scopeID, "API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := record.PayloadJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `"v1"` {
			t.Fatalf("restored payload=%s, want \"v1\"", raw)
		}
		entries, err := s.SecretHistory(scopeID, "API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 {
			t.Fatalf("history has %d entries after restore, want 4", len(entries))
		}
		// Every prior version is still listed, unmodified.
		payloads := []any{}
		for _, entry := range entries {
			payloads = append(payloads, entry.Record.Payload)
		}
		want := []any{`"v1"`, `"v3"`, `"v2"`, `"v1"`}
		for i := range want {
			if payloads[i] != want[i] {
				t.Fatalf("history payloads=%v want %v", payloads, want)
			}
		}
		if entries[0].SecretID != entries[3].SecretID {
			t.Fatal("restore minted a new secret id")
		}
	})
}

// TestRestoreSecretVersionRoundTripsPassItemPayload guards against
// double-encoding: the restored payload must decode as a pass item again.
func TestRestoreSecretVersionRoundTripsPassItemPayload(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	first := passItemWithPassword(t, "GitHub", "first-password")
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, first.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	second := passItemWithPassword(t, "GitHub", "second-password")
	second.Meta = first.Meta
	second.Touch()
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, second.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	var oldestSeq uint64
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "pass:GitHub")
		if err != nil {
			t.Fatal(err)
		}
		oldestSeq = entries[len(entries)-1].Seq
	})
	withSession(t, ctx, func(s *Session) {
		if err := s.RestoreSecretVersion(ctx, scopeID, "pass:GitHub", oldestSeq); err != nil {
			t.Fatal(err)
		}
	})
	withSession(t, ctx, func(s *Session) {
		record, err := s.GetTypedSecret(scopeID, "pass:GitHub")
		if err != nil {
			t.Fatal(err)
		}
		if record.Type != passitem.TypePassItem {
			t.Fatalf("restored type=%q", record.Type)
		}
		raw, err := record.PayloadJSON()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := passitem.Decode(raw)
		if err != nil {
			t.Fatalf("restored payload no longer decodes as a pass item: %v", err)
		}
		field, err := restored.Field("password")
		if err != nil {
			t.Fatal(err)
		}
		value, err := passitem.StringValue(*field)
		if err != nil {
			t.Fatal(err)
		}
		if value != "first-password" {
			t.Fatalf("restored password=%q, want the first one", value)
		}
	})
}

// TestRestoreSecretVersionRefusesTombstoneAndUnknownSeq checks the loud
// failures: restoring a deletion, and naming a sequence that is not a version
// of this record.
func TestRestoreSecretVersionRefusesTombstoneAndUnknownSeq(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "API_KEY", "kv.string", "v1"); err != nil {
			t.Fatal(err)
		}
		if err := s.RemoveTypedSecret(ctx, scopeID, "API_KEY"); err != nil {
			t.Fatal(err)
		}
	})
	before := scopeEventCount(t, scopeID)
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "API_KEY")
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 || !entries[0].Tombstone() {
			t.Fatalf("expected a tombstoned record's history, got %+v", entries)
		}
		if err := s.RestoreSecretVersion(ctx, scopeID, "API_KEY", entries[0].Seq); !errors.Is(err, ErrSecretVersionTombstone) {
			t.Fatalf("restoring a deletion: err=%v", err)
		}
		if err := s.RestoreSecretVersion(ctx, scopeID, "API_KEY", 9999); !errors.Is(err, ErrSecretVersionNotFound) {
			t.Fatalf("restoring an unknown seq: err=%v", err)
		}
	})
	if after := scopeEventCount(t, scopeID); after != before {
		t.Fatalf("a refused restore still wrote to the chain: %d → %d", before, after)
	}
}

// TestSecretHistoryNeverTouchesProductionHome is a guard for the test suite
// itself: every path used above must live under the temporary FD0_HOME.
func TestSecretHistoryNeverTouchesProductionHome(t *testing.T) {
	ctx, scopeID := newTestVault(t)
	paths, err := fdhome.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no user home in this environment")
	}
	production := filepath.Clean(filepath.Join(userHome, ".fd0"))
	for _, path := range []string{paths.Home, paths.Vault, paths.ScopeChain(proto.MustParseScopeID(scopeID))} {
		if strings.HasPrefix(filepath.Clean(path), production) {
			t.Fatalf("test path %q is inside the production home", path)
		}
	}
	withSession(t, ctx, func(s *Session) {
		if _, err := s.SecretHistory(scopeID, "missing"); !errors.Is(err, ErrTypedSecretNotFound) {
			t.Fatalf("err=%v", err)
		}
	})
}

// TestRestoreSecretVersionAdvancesRevision pins the rule that restoring rolls
// the CONTENT back but not the clock: the revision counter and updated_at must
// keep moving forward, or the history list shows a lower revision sitting above
// a higher one.
func TestRestoreSecretVersionAdvancesRevision(t *testing.T) {
	ctx, scopeID := newTestVault(t)

	first := passItemWithPassword(t, "GitHub", "first-password")
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, first.Marshal()); err != nil {
			t.Fatal(err)
		}
	})
	second := passItemWithPassword(t, "GitHub", "second-password")
	second.Meta = first.Meta
	second.Touch()
	withSession(t, ctx, func(s *Session) {
		if err := s.SetTypedSecret(ctx, scopeID, "pass:GitHub", passitem.TypePassItem, second.Marshal()); err != nil {
			t.Fatal(err)
		}
	})

	var oldestSeq uint64
	var revisionBefore float64
	withSession(t, ctx, func(s *Session) {
		entries, err := s.SecretHistory(scopeID, "pass:GitHub")
		if err != nil {
			t.Fatal(err)
		}
		oldestSeq = entries[len(entries)-1].Seq
		revisionBefore = revisionOf(t, entries[0].Record)
	})

	withSession(t, ctx, func(s *Session) {
		if err := s.RestoreSecretVersion(ctx, scopeID, "pass:GitHub", oldestSeq); err != nil {
			t.Fatal(err)
		}
	})

	withSession(t, ctx, func(s *Session) {
		record, err := s.GetTypedSecret(scopeID, "pass:GitHub")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := record.PayloadJSON()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := passitem.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		// Content came from the oldest version.
		field, err := restored.Field("password")
		if err != nil {
			t.Fatal(err)
		}
		value, err := passitem.StringValue(*field)
		if err != nil {
			t.Fatal(err)
		}
		if value != "first-password" {
			t.Fatalf("restored password=%q, want the oldest version's value", value)
		}
		// The revision did not roll back with it.
		revisionAfter, ok := restored.Meta["revision"].(float64)
		if !ok {
			t.Fatalf("restored item has no numeric revision: %#v", restored.Meta["revision"])
		}
		if revisionAfter <= revisionBefore {
			t.Fatalf("revision went from %v to %v; a restore must advance it", revisionBefore, revisionAfter)
		}
	})
}

func revisionOf(t *testing.T, record *proto.SecretRecord) float64 {
	t.Helper()
	raw, err := payloadJSON(record.Payload)
	if err != nil {
		t.Fatal(err)
	}
	item, err := passitem.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := item.Meta["revision"].(float64)
	if !ok {
		t.Fatalf("history entry has no numeric revision: %#v", item.Meta["revision"])
	}
	return value
}
