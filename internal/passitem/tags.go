package passitem

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const MaxTags = 32
const MaxTagRunes = 64

// TagKey uses single-code-point case mappings, independent of the user's locale.
// Keep the Desktop implementation and shared tag fixtures in sync.
func TagKey(tag string) string {
	return strings.Map(func(r rune) rune { return unicode.ToLower(unicode.ToUpper(r)) }, norm.NFC.String(tag))
}

func NormalizeTags(tags []string) ([]string, error) {
	out := make([]string, 0, len(tags))
	seen := make(map[string]bool)
	for _, tag := range tags {
		tag = norm.NFC.String(strings.TrimSpace(tag))
		if !utf8.ValidString(tag) || tag == "" || utf8.RuneCountInString(tag) > MaxTagRunes {
			return nil, fmt.Errorf("each tag must contain 1–%d characters", MaxTagRunes)
		}
		if strings.ContainsFunc(tag, unicode.IsControl) {
			return nil, fmt.Errorf("tags cannot contain control characters")
		}
		key := TagKey(tag)
		if !seen[key] {
			seen[key] = true
			out = append(out, tag)
		}
		if len(out) > MaxTags {
			return nil, fmt.Errorf("an item can have at most %d tags", MaxTags)
		}
	}
	return out, nil
}

// ParseTags validates explicitly supplied metadata, including JSON-decoded arrays.
func ParseTags(value any) ([]string, error) {
	switch tags := value.(type) {
	case []string:
		return NormalizeTags(tags)
	case []any:
		out := make([]string, 0, len(tags))
		for _, value := range tags {
			tag, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("tags must be an array of strings")
			}
			out = append(out, tag)
		}
		return NormalizeTags(out)
	default:
		return nil, fmt.Errorf("tags must be an array of strings")
	}
}

// Tags is a tolerant projection: optional malformed metadata must not hide a login.
func (i *Item) Tags() []string {
	tags, _ := ParseTags(i.Meta["tags"])
	return tags
}

// SetTags does not touch revisions. The caller owns the containing item update.
func (i *Item) SetTags(tags []string) (bool, error) {
	normalized, err := NormalizeTags(tags)
	if err != nil {
		return false, err
	}
	old, oldErr := ParseTags(i.Meta["tags"])
	_, present := i.Meta["tags"]
	if slices.Equal(old, normalized) && (oldErr == nil || !present) {
		return false, nil
	}
	if i.Meta == nil {
		i.Meta = map[string]any{}
	}
	i.Meta["tags"] = normalized
	return true, nil
}

func (i *Item) MatchesTags(tags []string, untagged bool) bool {
	current := i.Tags()
	if untagged {
		return len(current) == 0
	}
	for _, tag := range tags {
		if !slices.ContainsFunc(current, func(value string) bool { return TagKey(value) == TagKey(tag) }) {
			return false
		}
	}
	return true
}
