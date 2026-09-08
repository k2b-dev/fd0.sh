package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

type PassTagFilter struct {
	Tags     []string
	Untagged bool
}

func (f PassTagFilter) validate() (PassTagFilter, error) {
	if f.Untagged && len(f.Tags) != 0 {
		return f, errors.New("--tag and --untagged cannot be combined")
	}
	tags, err := passitem.NormalizeTags(f.Tags)
	f.Tags = tags
	return f, err
}

func filterPassTags(rows []passRow, filter PassTagFilter) []passRow {
	out := make([]passRow, 0, len(rows))
	for _, row := range rows {
		if row.Item.MatchesTags(filter.Tags, filter.Untagged) {
			out = append(out, row)
		}
	}
	return out
}

func changePassTags(item *passitem.Item, operation string, tags []string) (bool, error) {
	current := item.Tags()
	switch operation {
	case "add":
		current = append(current, tags...)
	case "rm":
		current = slices.DeleteFunc(current, func(tag string) bool {
			return slices.ContainsFunc(tags, func(remove string) bool { return passitem.TagKey(tag) == passitem.TagKey(remove) })
		})
	case "clear":
		current = []string{}
	default:
		return false, errors.New("unknown tag operation")
	}
	changed, err := item.SetTags(current)
	if changed {
		item.Touch()
	}
	return changed, err
}

func RunPassTagsChange(ctx context.Context, scope, name, operation string, tags []string) error {
	name, err := normalizePassName(name)
	if err != nil {
		return err
	}
	tags, err = passitem.NormalizeTags(tags)
	if err != nil {
		return err
	}
	return EditItem(ctx, KindPass, scope, name, decodePassRecord,
		func(item *passitem.Item) (bool, error) { return changePassTags(item, operation, tags) },
		func(item *passitem.Item) error { return item.Validate() },
		func(item *passitem.Item) (string, any) { return passitem.TypePassItem, item.Marshal() },
	)
}

type passTagRow struct {
	ScopeID string `json:"scopeId"`
	Scope   string `json:"scope"`
	Tag     string `json:"tag"`
	Count   int    `json:"count"`
}

func passTagCatalog(rows []passRow) []passTagRow {
	type key struct{ scope, tag string }
	counts := make(map[key]passTagRow)
	for _, row := range rows {
		for _, tag := range row.Item.Tags() {
			k := key{row.ScopeID, passitem.TagKey(tag)}
			entry := counts[k]
			entry.ScopeID = row.ScopeID
			if entry.Tag == "" || tag < entry.Tag {
				entry.Tag = tag
			}
			entry.Count++
			counts[k] = entry
		}
	}
	out := make([]passTagRow, 0, len(counts))
	for _, entry := range counts {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return passitem.TagKey(out[i].Tag) < passitem.TagKey(out[j].Tag)
	})
	return out
}

func RunPassTagsList(ctx context.Context, scope string, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	items, err := loadPassItems(s, scope)
	if err != nil {
		return err
	}
	rows := passTagCatalog(items)
	for i := range rows {
		rows[i].Scope = scopeLabelOf(s, rows[i].ScopeID)
	}
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(rows) == 0 {
		stderrln("no password tags")
		return nil
	}
	for _, row := range rows {
		fmt.Printf("%-24s  %-12s  %d\n", terminalSafe(row.Tag), terminalSafe(row.Scope), row.Count)
	}
	return nil
}
