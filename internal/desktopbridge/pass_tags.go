package desktopbridge

import "github.com/valentinkolb/fd0.sh/internal/passitem"

// The editor owns content and explicit tag edits, not the rest of the metadata.
// In particular, an old editor omitting tags must preserve current stored tags.
func preparePassSave(input, stored *passitem.Item) (*passitem.Item, error) {
	result := stored
	if result == nil {
		result = passitem.New(input.Title, input.URLs)
	}
	if value, present := input.Meta["tags"]; present {
		tags, err := passitem.ParseTags(value)
		if err != nil {
			return nil, err
		}
		if _, err := result.SetTags(tags); err != nil {
			return nil, err
		}
	}
	result.Title = input.Title
	result.URLs = input.URLs
	result.Fields = input.Fields
	return result, nil
}
