package desktopbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func historyFixture(t *testing.T, author []byte) []cli.SecretVersionEntry {
	t.Helper()
	item := passitem.New("GitHub", []string{"https://github.com"})
	password, err := passitem.NewStringField(passitem.FieldSecret, "super-secret-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("password", password); err != nil {
		t.Fatal(err)
	}
	username, err := passitem.NewStringField(passitem.FieldText, "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("username", username); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	record := &proto.SecretRecord{
		Name:          "pass:GitHub",
		Type:          passitem.TypePassItem,
		SchemaVersion: 1,
		Payload:       string(raw),
		Tags:          map[string]string{},
	}
	// Newest first, as SecretHistory returns them.
	return []cli.SecretVersionEntry{
		{SecretID: "s_a", Seq: 5, EventID: "e_five", Author: author},
		{
			SecretID: "s_a", Seq: 4, EventID: "e_four", Author: author, Record: record,
			Name: "pass:GitHub", Type: passitem.TypePassItem,
			Revision: 7, HasRevision: true, UpdatedAt: "2026-01-02T03:04:05Z",
		},
		{
			SecretID: "s_a", Seq: 3, EventID: "e_three", Author: author, Record: record,
			Name: "pass:GitHub", Type: passitem.TypePassItem,
		},
		{
			SecretID: "s_a", Seq: 2, EventID: "e_two", Author: author,
			Record: &proto.SecretRecord{Name: "OLD", Type: "kv.string", SchemaVersion: 1, Payload: `"v1"`},
			Name:   "OLD", Type: "kv.string",
		},
	}
}

// TestBuildHistoryResultPagesNewestFirst covers the paging contract the 1 MiB
// frame limit forces on item.history.
func TestBuildHistoryResultPagesNewestFirst(t *testing.T) {
	self := bytes.Repeat([]byte{1}, 32)
	versions := historyFixture(t, self)

	first := buildHistoryResult(versions, nil, self, 2, 0)
	if first.Total != 4 || first.Limit != 2 || first.Offset != 0 || len(first.Entries) != 2 {
		t.Fatalf("first page=%+v", first)
	}
	if first.Entries[0].Seq != 5 || first.Entries[1].Seq != 4 {
		t.Fatalf("first page is not newest-first: %+v", first.Entries)
	}
	second := buildHistoryResult(versions, nil, self, 2, 2)
	if second.Total != 4 || len(second.Entries) != 2 {
		t.Fatalf("second page=%+v", second)
	}
	if second.Entries[0].Seq != 3 || second.Entries[1].Seq != 2 {
		t.Fatalf("second page=%+v", second.Entries)
	}
	past := buildHistoryResult(versions, nil, self, 2, 99)
	if past.Total != 4 || len(past.Entries) != 0 {
		t.Fatalf("out-of-range offset=%+v", past)
	}
	if past.Entries == nil {
		t.Fatal("entries must serialize as [] not null")
	}
}

// TestBuildHistoryResultFlagsTombstonesAndRevisions checks the per-entry
// fields the UI renders, including "revision unknown" staying absent rather
// than being reported as zero.
func TestBuildHistoryResultFlagsTombstonesAndRevisions(t *testing.T) {
	self := bytes.Repeat([]byte{1}, 32)
	result := buildHistoryResult(historyFixture(t, self), nil, self, 50, 0)
	if len(result.Entries) != 4 {
		t.Fatalf("entries=%d", len(result.Entries))
	}
	deletion := result.Entries[0]
	if !deletion.Tombstone || deletion.Summary != "Deleted" {
		t.Fatalf("tombstone entry=%+v", deletion)
	}
	if deletion.Revision != 0 || deletion.UpdatedAt != "" {
		t.Fatalf("tombstone carries version metadata: %+v", deletion)
	}
	withRevision := result.Entries[1]
	if withRevision.Tombstone || withRevision.Revision != 7 || withRevision.UpdatedAt != "2026-01-02T03:04:05Z" {
		t.Fatalf("revision entry=%+v", withRevision)
	}
	if withRevision.Summary != "2 fields" {
		t.Fatalf("summary=%q, want the field count", withRevision.Summary)
	}
	if withRevision.ID != "e_four" {
		t.Fatalf("stable id=%q, want the chain event id", withRevision.ID)
	}
	withoutRevision := result.Entries[2]
	if withoutRevision.Revision != 0 || withoutRevision.UpdatedAt != "" {
		t.Fatalf("unknown revision was invented: %+v", withoutRevision)
	}
	encoded, err := json.Marshal(withoutRevision)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "revision") || strings.Contains(string(encoded), "updatedAt") {
		t.Fatalf("unknown metadata leaked into the wire shape: %s", encoded)
	}
	if result.Entries[3].Summary != "Secret value" {
		t.Fatalf("kv.string summary=%q", result.Entries[3].Summary)
	}
}

// TestHistoryEntriesNeverCarryFieldValues is the disclosure guard for the
// listing: a summary describes shape only.
func TestHistoryEntriesNeverCarryFieldValues(t *testing.T) {
	self := bytes.Repeat([]byte{1}, 32)
	result := buildHistoryResult(historyFixture(t, self), nil, self, 50, 0)
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret-password", "octocat"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("history listing leaked %q: %s", secret, encoded)
		}
	}
}

// TestHistoryAuthorLabelsMatchScopeMembers pins that item.history resolves an
// author exactly like scope.members resolves a member, and never renders a
// full fingerprint.
func TestHistoryAuthorLabelsMatchScopeMembers(t *testing.T) {
	self := bytes.Repeat([]byte{1}, 32)
	benny := bytes.Repeat([]byte{2}, 32)
	unknown := bytes.Repeat([]byte{3}, 32)
	pinned := map[string]proto.PinnedIdentity{"Benny": {SuperPub: benny, Label: "Benny"}}
	trusted := trustedLabelIndex(pinned)

	if got := memberDisplayLabel(trusted, self, self); got != "You" {
		t.Fatalf("self label=%q", got)
	}
	if got := memberDisplayLabel(trusted, benny, self); got != "Benny" {
		t.Fatalf("trusted label=%q", got)
	}
	got := memberDisplayLabel(trusted, unknown, self)
	if !strings.HasPrefix(got, "Unknown member (") {
		t.Fatalf("unknown label=%q", got)
	}
	full := shortFingerprint(unknown)
	if !strings.Contains(got, full) {
		t.Fatalf("unknown label %q lost its short fingerprint", got)
	}
	// Never the raw full fingerprint.
	members := scopeMembers(pinned, [][]byte{unknown}, self, nil)
	if len(members) != 1 {
		t.Fatalf("members=%+v", members)
	}
	if strings.Contains(got, members[0].Fingerprint) && len(members[0].Fingerprint) > 12 {
		t.Fatalf("label leaked a long fingerprint: %q", got)
	}
	if got := memberDisplayLabel(trusted, []byte("short"), self); got != "Unknown member" {
		t.Fatalf("malformed key label=%q", got)
	}
}

// TestHistoryPageClampsLimit locks the default and the hard cap that keeps a
// response inside the 1 MiB frame.
func TestHistoryPageClampsLimit(t *testing.T) {
	limit, offset, err := historyPage(0, 0)
	if err != nil || limit != defaultHistoryLimit || offset != 0 {
		t.Fatalf("default limit=%d offset=%d err=%v", limit, offset, err)
	}
	limit, _, err = historyPage(maxHistoryLimit*10, 0)
	if err != nil || limit != maxHistoryLimit {
		t.Fatalf("capped limit=%d err=%v", limit, err)
	}
	limit, offset, err = historyPage(10, 3)
	if err != nil || limit != 10 || offset != 3 {
		t.Fatalf("explicit page limit=%d offset=%d err=%v", limit, offset, err)
	}
	for _, bad := range [][2]int{{-1, 0}, {0, -1}} {
		if _, _, err := historyPage(bad[0], bad[1]); err == nil {
			t.Fatalf("negative page %v accepted", bad)
		}
	}
}

// TestItemVersionMasksSensitiveFields is the central disclosure test for
// item.version: it renders through the SAME detailFields projection as
// item.detail, so a secret, TOTP or file field carries shape but no value.
func TestItemVersionMasksSensitiveFields(t *testing.T) {
	item := passitem.New("GitHub", []string{"https://github.com"})
	password, err := passitem.NewStringField(passitem.FieldSecret, "super-secret-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("password", password); err != nil {
		t.Fatal(err)
	}
	username, err := passitem.NewStringField(passitem.FieldText, "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("username", username); err != nil {
		t.Fatal(err)
	}
	totp, err := passitem.NewTOTPField(passitem.TOTPValue{Secret: "JBSWY3DPEHPK3PXP"})
	if err != nil {
		t.Fatal(err)
	}
	if err := item.SetField("2fa", totp); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	ref := RecordRef{ScopeID: "s_aaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "pass:GitHub"}
	version := &cli.SecretVersionEntry{
		SecretID: "s_a", Seq: 4, EventID: "e_four",
		Name: "pass:GitHub", Type: passitem.TypePassItem,
		Record: &proto.SecretRecord{
			Name: "pass:GitHub", Type: passitem.TypePassItem, SchemaVersion: 1,
			Payload: string(raw), Tags: map[string]string{},
		},
	}
	record, err := historicalTypedRecord(ref, version)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := detailFields(*record, ref.Raw)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "super-secret-password") {
		t.Fatalf("historical detail leaked the password: %s", encoded)
	}
	if strings.Contains(string(encoded), "JBSWY3DPEHPK3PXP") {
		t.Fatalf("historical detail leaked the TOTP seed: %s", encoded)
	}
	var secret, totpView, plain *FieldView
	for i := range fields {
		switch fields[i].Path {
		case "password":
			secret = &fields[i]
		case "2fa":
			totpView = &fields[i]
		case "username":
			plain = &fields[i]
		}
	}
	if secret == nil || secret.Value != "" || !secret.Sensitive || !secret.Copyable {
		t.Fatalf("secret field=%+v", secret)
	}
	if totpView == nil || totpView.Value != "" || !totpView.Sensitive {
		t.Fatalf("totp field=%+v", totpView)
	}
	// Non-sensitive fields still render their value, exactly as in item.detail.
	if plain == nil || plain.Value != "octocat" {
		t.Fatalf("text field=%+v", plain)
	}
}

// TestItemVersionRefusesTombstone: there is nothing to render for a deletion,
// and the caller must be told rather than shown an empty item.
func TestItemVersionRefusesTombstone(t *testing.T) {
	ref := RecordRef{ScopeID: "s_aaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "pass:GitHub"}
	_, err := historicalTypedRecord(ref, &cli.SecretVersionEntry{Seq: 5})
	var methodErr *methodError
	if !errors.As(err, &methodErr) || methodErr.bridge.Code != "not_found" {
		t.Fatalf("err=%v", err)
	}
}

// TestMapHistoryErrorsAreActionable keeps the domain errors from leaking as
// raw Go text to the desktop.
func TestMapHistoryErrorsAreActionable(t *testing.T) {
	cases := map[error]string{
		cli.ErrTypedSecretNotFound:    "not_found",
		cli.ErrSecretVersionNotFound:  "not_found",
		cli.ErrSecretVersionTombstone: "unsupported",
	}
	for domain, wantCode := range cases {
		err := mapHistoryError(domain)
		var methodErr *methodError
		if !errors.As(err, &methodErr) || methodErr.bridge.Code != wantCode {
			t.Fatalf("%v mapped to %v, want %q", domain, err, wantCode)
		}
	}
	if mapHistoryError(nil) != nil {
		t.Fatal("nil error must map to nil")
	}
}

// TestHistoryMethodsAreRegistered proves the three methods reach a handler
// (they fail on the locked/absent vault, not on dispatch) and are advertised
// in the handshake.
func TestHistoryMethodsAreRegistered(t *testing.T) {
	t.Setenv("FD0_HOME", t.TempDir())
	service := &Service{Mode: "system"}
	handshake, err := service.Handle(context.Background(), "bridge.handshake", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := handshake.(HandshakeResult)
	if !ok {
		t.Fatalf("handshake=%T", handshake)
	}
	for _, capability := range []string{"item-history", "item-version", "item-restore"} {
		found := false
		for _, have := range result.Capabilities {
			if have == capability {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("handshake does not advertise %q: %v", capability, result.Capabilities)
		}
	}
	params := json.RawMessage(`{"scopeId":"s_aaaaaaaaaaaaaaaaaaaaaaaaaa","name":"pass:GitHub","seq":3}`)
	for _, method := range []string{"item.history", "item.version", "item.restore"} {
		body := params
		if method == "item.history" {
			body = json.RawMessage(`{"scopeId":"s_aaaaaaaaaaaaaaaaaaaaaaaaaa","name":"pass:GitHub","limit":10}`)
		}
		_, err := service.Handle(context.Background(), method, body)
		var methodErr *methodError
		if errors.As(err, &methodErr) && methodErr.bridge.Code == "unknown_method" {
			t.Fatalf("%s is not registered in the dispatch switch", method)
		}
	}
}

// TestFieldValueParamsAcceptOptionalSeq documents the wire extension: absent
// seq must decode as "live read", so today's clients are unaffected.
func TestFieldValueParamsAcceptOptionalSeq(t *testing.T) {
	var live FieldValueParams
	if err := decodeParams(json.RawMessage(`{"scopeId":"s_x","name":"n","path":"password"}`), &live); err != nil {
		t.Fatal(err)
	}
	if live.Seq != nil {
		t.Fatalf("absent seq decoded as %v", *live.Seq)
	}
	var historical FieldValueParams
	if err := decodeParams(json.RawMessage(`{"scopeId":"s_x","name":"n","path":"password","seq":7}`), &historical); err != nil {
		t.Fatal(err)
	}
	if historical.Seq == nil || *historical.Seq != 7 {
		t.Fatalf("seq=%v", historical.Seq)
	}
	// item.restore takes no rendering mode; a stray field is rejected rather
	// than silently ignored.
	var restore ItemRestoreParams
	if err := decodeParams(json.RawMessage(`{"scopeId":"s_x","name":"n","seq":7,"raw":true}`), &restore); err == nil {
		t.Fatal("item.restore accepted an unknown field")
	}
}

// TestFieldAttachmentRejectsHistoricalSeq: file.value shares the params
// struct, so an ignored seq would silently hand back the CURRENT attachment.
func TestFieldAttachmentRejectsHistoricalSeq(t *testing.T) {
	t.Setenv("FD0_HOME", t.TempDir())
	seq := uint64(3)
	service := &Service{Mode: "system"}
	_, err := service.fieldAttachment(context.Background(), FieldValueParams{
		RecordRef: RecordRef{ScopeID: "s_aaaaaaaaaaaaaaaaaaaaaaaaaa", Name: "pass:GitHub"},
		Path:      "notes/file.pem",
		Seq:       &seq,
	})
	var methodErr *methodError
	if !errors.As(err, &methodErr) || methodErr.bridge.Code != "unsupported" {
		t.Fatalf("err=%v", err)
	}
}
