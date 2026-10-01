package desktopbridge

import (
	"context"
	"errors"
	"strconv"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/service"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

const (
	// defaultHistoryLimit / maxHistoryLimit page item.history. The cap
	// exists because a response must fit the 1 MiB frame limit: an
	// append-only chain can hold thousands of versions of one record, and
	// an unpaged listing would eventually exceed the frame and fail the
	// whole call instead of returning a usable first page.
	defaultHistoryLimit   = 50
	maxHistoryLimit       = 200
	historyResponseBudget = MaxFrameBytes * 3 / 4
)

type ItemHistoryParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Limit   int    `json:"limit,omitempty"`
	Offset  int    `json:"offset,omitempty"`
}

// ItemVersionParams mirrors RecordRef plus the sequence to render. Raw has
// the same meaning as on item.detail.
type ItemVersionParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Seq     uint64 `json:"seq"`
	Raw     bool   `json:"raw,omitempty"`
}

// ItemRestoreParams is deliberately separate from ItemVersionParams: a
// restore has no rendering mode, and DisallowUnknownFields then rejects a
// stray `raw` instead of silently ignoring it.
type ItemRestoreParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"`
	Seq     uint64 `json:"seq"`
}

type ItemHistoryEntry struct {
	ID        string `json:"id"`
	Seq       uint64 `json:"seq"`
	Revision  int64  `json:"revision,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
	Author    string `json:"author"`
	Tombstone bool   `json:"tombstone,omitempty"`
	Summary   string `json:"summary"`
}

type ItemHistoryResult struct {
	Total     int                `json:"total"`
	Limit     int                `json:"limit"`
	Offset    int                `json:"offset"`
	Entries   []ItemHistoryEntry `json:"entries"`
	Truncated bool               `json:"truncated,omitempty"`
}

type DeletedItem struct {
	Item       ItemSummary `json:"item"`
	RestoreSeq uint64      `json:"restoreSeq"`
}

type DeletedItemsResult struct {
	Items []DeletedItem `json:"items"`
}

func (s *Service) deletedItems(ctx context.Context) (DeletedItemsResult, error) {
	session, err := cli.Open(ctx)
	if err != nil {
		return DeletedItemsResult{}, mapDomainError(err)
	}
	defer session.Close()
	records, err := session.ListDeletedTypedSecrets()
	if err != nil {
		return DeletedItemsResult{}, mapDomainError(err)
	}
	result := DeletedItemsResult{Items: []DeletedItem{}}
	for _, deleted := range records {
		summary, err := summarizeRecord(session, cli.TypedRecord{
			ScopeID: deleted.ScopeID,
			Name:    deleted.Name,
			Type:    deleted.Type,
			Payload: deleted.Payload,
		})
		if err != nil {
			continue
		}
		result.Items = append(result.Items, DeletedItem{
			Item:       boundItemSummary(summary),
			RestoreSeq: deleted.RestoreSeq,
		})
	}
	return result, nil
}

func (p ItemHistoryParams) ref() RecordRef {
	return RecordRef{ScopeID: p.ScopeID, Name: p.Name}
}

func (p ItemVersionParams) ref() RecordRef {
	return RecordRef{ScopeID: p.ScopeID, Name: p.Name, Raw: p.Raw}
}

func (p ItemRestoreParams) ref() RecordRef {
	return RecordRef{ScopeID: p.ScopeID, Name: p.Name}
}

func (s *Service) itemHistory(ctx context.Context, params ItemHistoryParams) (ItemHistoryResult, error) {
	ref := params.ref()
	if err := ref.Validate(); err != nil {
		return ItemHistoryResult{}, err
	}
	limit, offset, err := historyPage(params.Limit, params.Offset)
	if err != nil {
		return ItemHistoryResult{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return ItemHistoryResult{}, mapDomainError(err)
	}
	defer session.Close()
	versions, err := session.SecretHistory(ref.ScopeID, ref.Name)
	if err != nil {
		return ItemHistoryResult{}, mapHistoryError(err)
	}
	trusted := trustedLabelIndex(session.Body.PinnedIdentities)
	return buildHistoryResult(versions, trusted, session.UserSuperPub, limit, offset), nil
}

// buildHistoryResult pages an already-ordered (newest-first) version list into
// the wire shape. Total always reports the full history so a UI can page even
// when a page was cut short by the frame budget.
func buildHistoryResult(
	versions []cli.SecretVersionEntry,
	trusted map[string]string,
	self []byte,
	limit, offset int,
) ItemHistoryResult {
	result := ItemHistoryResult{Total: len(versions), Limit: limit, Offset: offset, Entries: []ItemHistoryEntry{}}
	if offset >= len(versions) {
		return result
	}
	used := 1024
	for _, version := range versions[offset:] {
		if len(result.Entries) >= limit {
			break
		}
		entry := ItemHistoryEntry{
			ID:        version.EventID,
			Seq:       version.Seq,
			UpdatedAt: boundedInventoryText(version.UpdatedAt),
			Author:    boundedInventoryText(memberDisplayLabel(trusted, version.Author, self)),
			Tombstone: version.Tombstone(),
			Summary:   boundedInventoryText(versionSummary(version)),
		}
		if version.HasRevision {
			entry.Revision = version.Revision
		}
		size := encodedSize(entry)
		if used+size > historyResponseBudget {
			result.Truncated = true
			break
		}
		result.Entries = append(result.Entries, entry)
		used += size
	}
	return result
}

// historyPage validates and clamps the paging window. A negative value is a
// client bug, not something to silently reinterpret.
func historyPage(limit, offset int) (int, int, error) {
	if limit < 0 || offset < 0 {
		return 0, 0, fail("validation", "That history page request is invalid.", "", false)
	}
	if limit == 0 {
		limit = defaultHistoryLimit
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}
	return limit, offset, nil
}

// versionSummary is a short, non-revealing description of what a version
// holds. It never includes a field VALUE — only shapes and counts.
func versionSummary(version cli.SecretVersionEntry) string {
	if version.Tombstone() {
		return "Deleted"
	}
	switch version.Type {
	case passitem.TypePassItem:
		raw, err := payloadJSONOf(version)
		if err != nil {
			return "Password item"
		}
		item, err := passitem.Decode(raw)
		if err != nil {
			return "Password item"
		}
		count := countPassFields(item.Fields)
		return strconv.Itoa(count) + " " + pluralFields(count)
	case sshhost.TypeHost:
		return "SSH host"
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		return "SSH key"
	case kubeconfig.TypeKubeconfig:
		return "Kubernetes context"
	case talosctx.TypeTalosContext:
		return "Talos context"
	case service.TypeService:
		raw, err := payloadJSONOf(version)
		if err != nil {
			return "Service"
		}
		svc, err := service.Decode(raw)
		if err != nil {
			return "Service"
		}
		return strconv.Itoa(len(svc.Fields)) + " " + pluralFields(len(svc.Fields))
	default:
		return "Secret value"
	}
}

func pluralFields(count int) string {
	if count == 1 {
		return "field"
	}
	return "fields"
}

// countPassFields counts leaf fields, descending into sections. Sections are
// containers, not data, so counting them would inflate the number the user
// sees against the detail view.
func countPassFields(fields []passitem.Field) int {
	total := 0
	for _, field := range fields {
		if field.Type == passitem.FieldSection {
			total += countPassFields(field.Fields)
			continue
		}
		total++
	}
	return total
}

func payloadJSONOf(version cli.SecretVersionEntry) ([]byte, error) {
	if version.Record == nil {
		return nil, errors.New("history: version has no record")
	}
	record := cli.TypedRecord{Payload: version.Record.Payload}
	return record.PayloadJSON()
}

// itemVersion renders one historical version through the SAME projection as
// item.detail (summarizeRecord + detailFields), so the UI renders a version
// exactly like the live item — including the masking: detailFields never
// carries a secret, TOTP or file value, only its shape.
func (s *Service) itemVersion(ctx context.Context, params ItemVersionParams) (ItemDetail, error) {
	ref := params.ref()
	if err := ref.Validate(); err != nil {
		return ItemDetail{}, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return ItemDetail{}, mapDomainError(err)
	}
	defer session.Close()
	version, err := session.SecretVersionAt(ref.ScopeID, ref.Name, params.Seq)
	if err != nil {
		return ItemDetail{}, mapHistoryError(err)
	}
	record, err := historicalTypedRecord(ref, version)
	if err != nil {
		return ItemDetail{}, err
	}
	summary, err := summarizeRecord(session, *record)
	if err != nil {
		return ItemDetail{}, err
	}
	fields, err := detailFields(*record, ref.Raw)
	if err != nil {
		return ItemDetail{}, err
	}
	return ItemDetail{Item: summary, Fields: fields}, nil
}

// historicalTypedRecord adapts a chain version to the TypedRecord shape the
// detail projection consumes. The record keeps the CURRENT name so its
// derived item id matches the live item the user is looking at; the type and
// payload are the historical ones.
func historicalTypedRecord(ref RecordRef, version *cli.SecretVersionEntry) (*cli.TypedRecord, error) {
	if version.Tombstone() {
		return nil, fail("not_found", "That version is a deletion and has nothing to show.", "Choose a version from before the item was deleted.", false)
	}
	return &cli.TypedRecord{
		ScopeID: ref.ScopeID,
		Name:    ref.Name,
		Type:    version.Type,
		Payload: version.Record.Payload,
	}, nil
}

func (s *Service) itemRestore(ctx context.Context, params ItemRestoreParams) (map[string]bool, error) {
	ref := params.ref()
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	if err := session.RestoreSecretVersion(ctx, ref.ScopeID, ref.Name, params.Seq); err != nil {
		return nil, mapHistoryError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func mapHistoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, cli.ErrTypedSecretNotFound):
		return fail("not_found", "That item has no history in this vault.", "Refresh the vault and try again.", false)
	case errors.Is(err, cli.ErrSecretVersionNotFound):
		return fail("not_found", "That version is no longer part of this item's history.", "Refresh the history and try again.", false)
	case errors.Is(err, cli.ErrSecretVersionTombstone):
		return fail("unsupported", "That version is a deletion and cannot be restored.", "Choose a version from before the item was deleted.", false)
	default:
		return mapDomainError(err)
	}
}

// historicalRecordFor resolves the record a reveal should read: the live one
// when seq is absent, the historical one otherwise. Both feed the identical
// downstream field lookup, so a historical reveal cannot pick up different
// limits or masking than a live one.
func historicalRecordFor(session *cli.Session, ref RecordRef, seq *uint64) (*cli.TypedRecord, error) {
	if seq == nil {
		record, err := session.GetTypedSecret(ref.ScopeID, ref.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		return record, nil
	}
	version, err := session.SecretVersionAt(ref.ScopeID, ref.Name, *seq)
	if err != nil {
		return nil, mapHistoryError(err)
	}
	return historicalTypedRecord(ref, version)
}
