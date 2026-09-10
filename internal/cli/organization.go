package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

// Supplemental tags live in the existing encrypted scope metadata, keyed by
// record ID, so older content writers cannot silently erase them. Password and
// host tags retain their native representation and matching semantics.
const organizationTagPrefix = "item.tags."

func organizationTagsFromIndex(index map[string]chain.ScopeSecret, id string) ([]string, error) {
	value := metaFieldsFromIndex(index)[organizationTagPrefix+id]
	if value == "" {
		return nil, nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(value), &tags); err != nil {
		return nil, errors.New("invalid item tag metadata")
	}
	return passitem.NormalizeTags(tags)
}

func OrganizationKind(recordType string) (ItemKind, error) {
	switch recordType {
	case "kv.string":
		return KindSecret, nil
	case passitem.TypePassItem:
		return KindPass, nil
	case sshhost.TypeHost:
		return KindHost, nil
	case string(sshkey.TypeEd25519), string(sshkey.TypeRSA), string(sshkey.TypeECDSA):
		return KindKey, nil
	case kubeconfig.TypeKubeconfig:
		return KindKube, nil
	case talosctx.TypeTalosContext:
		return KindTalos, nil
	default:
		return ItemKind{}, errors.New("unsupported item type")
	}
}

func (r TypedRecord) ItemTags() ([]string, error) {
	switch r.Type {
	case passitem.TypePassItem:
		item, err := decodePassRecord(r)
		if err != nil {
			return nil, err
		}
		return item.Tags(), nil
	case kubeconfig.TypeKubeconfig:
		entry, err := decodeKubeconfig(r)
		if err != nil {
			return nil, err
		}
		return slices.Clone(entry.Tags), nil
	case talosctx.TypeTalosContext:
		entry, err := decodeTalosContext(r)
		if err != nil {
			return nil, err
		}
		return slices.Clone(entry.Tags), nil
	case sshhost.TypeHost:
		host, err := decodeHost(r)
		if err != nil {
			return nil, err
		}
		return slices.Clone(host.Tags), nil
	default:
		return slices.Clone(r.OrganizationTags), nil
	}
}

func tagMatches(kind, left, right string) bool {
	if kind == "ssh" || kind == "kube" || kind == "talos" {
		return left == right
	}
	return passitem.TagKey(left) == passitem.TagKey(right)
}

// normalizeHostTags preserves case-sensitive SSH selectors and rejects commas
// (the SSH config metadata is CSV). Existing casing is never folded away.
func normalizeHostTags(tags []string) ([]string, error) {
	return normalizeInfrastructureTags(tags, true)
}
func normalizeInfrastructureTags(tags []string, host bool) ([]string, error) {
	if len(tags) > passitem.MaxTags {
		return nil, errors.New("too many host tags")
	}
	out := []string{}
	for _, tag := range tags {
		normalized, err := passitem.NormalizeTags([]string{tag})
		if err != nil {
			return nil, err
		}
		tag = normalized[0]
		if host && strings.Contains(tag, ",") {
			return nil, errors.New("host tags cannot contain commas")
		}
		if !slices.Contains(out, tag) {
			out = append(out, tag)
		}
	}
	return out, nil
}

func changedItemTags(kind string, current []string, operation string, tags []string) ([]string, error) {
	normalize := passitem.NormalizeTags
	if kind == "ssh" {
		normalize = normalizeHostTags
	} else if kind == "kube" || kind == "talos" {
		normalize = func(tags []string) ([]string, error) { return normalizeInfrastructureTags(tags, false) }
	}
	tags, err := normalize(tags)
	if err != nil {
		return nil, err
	}
	switch operation {
	case "add":
		current = append(slices.Clone(current), tags...)
	case "remove", "rm":
		current = slices.DeleteFunc(slices.Clone(current), func(tag string) bool {
			return slices.ContainsFunc(tags, func(remove string) bool { return tagMatches(kind, tag, remove) })
		})
	case "set":
		current = tags
	case "clear":
		current = []string{}
	default:
		return nil, errors.New("unknown tag operation")
	}
	return normalize(current)
}

func (s *Session) ChangeItemTags(ctx context.Context, scope, name, operation string, tags []string) error {
	r, err := s.GetTypedSecret(scope, name)
	if err != nil {
		return err
	}
	kind, err := OrganizationKind(r.Type)
	if err != nil {
		return err
	}
	current, err := r.ItemTags()
	if err != nil {
		return err
	}
	next, err := changedItemTags(kind.Command, current, operation, tags)
	if err != nil {
		return err
	}
	if slices.Equal(current, next) {
		return nil
	}
	switch r.Type {
	case passitem.TypePassItem:
		item, err := decodePassRecord(*r)
		if err != nil {
			return err
		}
		if _, err = item.SetTags(next); err != nil {
			return err
		}
		item.Touch()
		return s.UpdateTypedSecret(ctx, r.ScopeID, r.Name, r.Type, r.Type, item.Marshal())
	case sshhost.TypeHost, kubeconfig.TypeKubeconfig, talosctx.TypeTalosContext:
		// Change just this field, retaining unknown JSON fields from newer clients.
		raw, err := r.PayloadJSON()
		if err != nil {
			return err
		}
		fields := map[string]json.RawMessage{}
		if err = json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		field := "t"
		if r.Type == sshhost.TypeHost {
			field = "tags"
		}
		fields[field], err = json.Marshal(next)
		if err != nil {
			return err
		}
		if err = s.UpdateTypedSecret(ctx, r.ScopeID, r.Name, r.Type, r.Type, fields); err != nil {
			return err
		}
		hooksFor(kind).after(s)
		return nil
	default:
		raw, err := json.Marshal(next)
		if err != nil {
			return err
		}
		return s.writeScopeMeta(r.ScopeID, map[string]string{organizationTagPrefix + r.ID: string(raw)})
	}
}

// OrganizationItem is an allowlist, not a redacted detail response. Never add
// payload, subtitle, notes, usernames, URLs or secret field previews here.
type OrganizationItem struct {
	ID         string   `json:"id"`
	ScopeID    string   `json:"scopeId"`
	Scope      string   `json:"scope"`
	Name       string   `json:"name"`
	Title      string   `json:"title"`
	Kind       string   `json:"kind"`
	Tags       []string `json:"tags"`
	Revision   string   `json:"revision"`
	References []string `json:"references,omitempty"`
}

type OrganizationFilter struct {
	Scope    string
	Kind     string
	Query    string
	Tags     []string
	Untagged bool
}

func (s *Session) OrganizationInventory(filter OrganizationFilter) ([]OrganizationItem, error) {
	if filter.Untagged && len(filter.Tags) > 0 {
		return nil, errors.New("--tag and --untagged cannot be combined")
	}
	records, err := s.ListTypedSecrets(filter.Scope, "")
	if err != nil {
		return nil, err
	}
	out := []OrganizationItem{}
	for _, r := range records {
		kind, err := OrganizationKind(r.Type)
		if err != nil {
			continue
		}
		if filter.Kind != "" && filter.Kind != kind.Command {
			continue
		}
		tags, err := r.ItemTags()
		if err != nil {
			return nil, errors.New("could not read item metadata")
		}
		if tags == nil {
			tags = []string{}
		}
		if filter.Untagged && len(tags) != 0 {
			continue
		}

		matches := true
		for _, required := range filter.Tags {
			if !slices.ContainsFunc(tags, func(tag string) bool { return tagMatches(kind.Command, tag, required) }) {
				matches = false
			}
		}
		if !matches {
			continue
		}
		entry := OrganizationItem{ID: r.ID, ScopeID: r.ScopeID, Scope: scopeName(s, r.ScopeID), Name: r.Name, Title: strings.TrimPrefix(r.Name, kind.Prefix), Kind: kind.Command, Tags: tags, Revision: organizationRevision(r.Revision, tags)}
		if kind.Command == "pass" {
			item, err := decodePassRecord(r)
			if err != nil {
				return nil, errors.New("could not read item metadata")
			}
			entry.Title = item.Title
		}
		if kind.Command == "ssh" {
			host, err := decodeHost(r)
			if err != nil {
				return nil, errors.New("could not read host metadata")
			}
			entry.Title = host.Alias
			if host.KeyName != "" {
				entry.References = append(entry.References, "ssh:"+host.KeyName)
			}
			if host.ProxyJump != "" {
				entry.References = append(entry.References, "host:"+host.ProxyJump)
			}
		}
		haystack := strings.Join(append([]string{entry.Name, entry.Title, entry.Scope}, tags...), " ")
		if filter.Query != "" && !strings.Contains(strings.ToLower(haystack), strings.ToLower(filter.Query)) {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

func (s *Session) copyOrganizationTags(source *TypedRecord, scope, name string) error {
	if source.Type == passitem.TypePassItem || source.Type == sshhost.TypeHost || source.Type == kubeconfig.TypeKubeconfig || source.Type == talosctx.TypeTalosContext {
		return nil
	}
	target, err := s.GetTypedSecret(scope, name)
	if err != nil {
		return err
	}
	if slices.Equal(source.OrganizationTags, target.OrganizationTags) {
		return nil
	}
	tags, err := json.Marshal(source.OrganizationTags)
	if err != nil {
		return err
	}
	return s.writeScopeMeta(target.ScopeID, map[string]string{organizationTagPrefix + target.ID: string(tags)})
}

func (s *Session) RenameOrganizationItem(ctx context.Context, record *TypedRecord, name string) error {
	items, err := s.OrganizationInventory(OrganizationFilter{Scope: record.ScopeID})
	if err != nil {
		return err
	}
	for _, item := range items {
		if slices.Contains(item.References, record.Name) {
			return errors.New("item is referenced by a host; update its references before renaming")
		}
	}
	kind, err := OrganizationKind(record.Type)
	if err != nil {
		return err
	}
	var retitle func([]byte, string) ([]byte, error)
	switch kind.Command {
	case "ssh", "kube", "talos":
		retitle = func(raw []byte, name string) ([]byte, error) {
			fields := map[string]json.RawMessage{}
			if err := json.Unmarshal(raw, &fields); err != nil {
				return nil, err
			}
			key := "n"
			if kind.Command == "ssh" {
				key = "alias"
			}
			fields[key], _ = json.Marshal(name)
			next, err := json.Marshal(fields)
			if err != nil {
				return nil, err
			}
			changed := *record
			changed.Payload = string(next)
			switch kind.Command {
			case "ssh":
				host, err := decodeHost(changed)
				if err != nil {
					return nil, err
				}
				if err = host.Validate(); err != nil {
					return nil, err
				}
			case "kube":
				item, err := kubeconfig.Unmarshal(next)
				if err != nil {
					return nil, err
				}
				if err = item.Validate(); err != nil {
					return nil, err
				}
			case "talos":
				item, err := talosctx.Unmarshal(next)
				if err != nil {
					return nil, err
				}
				if err = item.Validate(); err != nil {
					return nil, err
				}
			}
			return next, nil
		}
	}
	return s.RenameItem(ctx, kind, record.ScopeID, strings.TrimPrefix(record.Name, kind.Prefix), name, false, retitle)
}

func organizationRevision(event string, tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	raw, _ := json.Marshal(tags)
	return fmt.Sprintf("%s:%x", event, sha256.Sum256(raw))
}

// SetOrganizationTitle edits only a password's public title. Its lookup name
// and all field contents remain unchanged.
func (s *Session) SetOrganizationTitle(ctx context.Context, scope, name, title string) error {
	if strings.TrimSpace(title) == "" || len(title) > 4096 {
		return errors.New("invalid password title")
	}
	record, err := s.GetTypedSecret(scope, name)
	if err != nil {
		return err
	}
	if record.Type != passitem.TypePassItem {
		return errors.New("only passwords have a separate title")
	}
	item, err := decodePassRecord(*record)
	if err != nil {
		return err
	}
	if item.Title == title {
		return nil
	}
	raw, err := record.PayloadJSON()
	if err != nil {
		return err
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	fields["title"], _ = json.Marshal(title)
	return s.UpdateTypedSecret(ctx, scope, name, record.Type, record.Type, fields)
}
