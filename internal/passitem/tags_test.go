package passitem

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestTagSharedFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/tags.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Input, Tags, Keys []string }
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		tags, err := NormalizeTags(tc.Input)
		if err != nil || !reflect.DeepEqual(tags, tc.Tags) {
			t.Fatalf("%v: %v %v", tc.Input, tags, err)
		}
		for i, tag := range tags {
			if TagKey(tag) != tc.Keys[i] {
				t.Fatalf("key %q: %q", tag, TagKey(tag))
			}
		}
	}
}

func TestTagsValidationAndTolerantRead(t *testing.T) {
	for _, value := range []any{nil, "Work", []any{"Work", 1}, []string{""}, []string{"a\nb"}, []string{strings.Repeat("x", 65)}} {
		item := &Item{Title: "Login", Meta: map[string]any{"tags": value, "future": true}}
		if _, err := ParseTags(value); err == nil {
			t.Fatalf("accepted %v", value)
		}
		if len(item.Tags()) != 0 {
			t.Fatalf("projected malformed %v", value)
		}
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Meta["future"] != true {
			t.Fatal("lost unknown metadata")
		}
	}
	tags := make([]string, 33)
	for i := range tags {
		tags[i] = string(rune('a' + i))
	}
	if _, err := NormalizeTags(tags); err == nil {
		t.Fatal("accepted too many tags")
	}
	if _, err := NormalizeTags([]string{strings.Repeat("🔑", 64)}); err != nil {
		t.Fatal(err)
	}
}

func TestTagsRoundTripAndFilter(t *testing.T) {
	i := New("Login", nil)
	i.Meta["favorite"] = true
	if changed, err := i.SetTags([]string{"Work", "Server"}); err != nil || !changed {
		t.Fatal(changed, err)
	}
	raw, _ := json.Marshal(i)
	i, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !i.MatchesTags([]string{"work", "server"}, false) || i.MatchesTags([]string{"missing"}, false) || i.MatchesTags(nil, true) {
		t.Fatal("filter semantics")
	}
	if changed, err := i.SetTags([]string{"Work", "Server"}); err != nil || changed {
		t.Fatal("unchanged write", err)
	}
	if changed, err := i.SetTags(nil); err != nil || !changed {
		t.Fatal("clear", err)
	}
	if tags, ok := i.Meta["tags"].([]string); !ok || tags == nil || len(tags) != 0 {
		t.Fatal("clear must store []")
	}
	if i.Meta["favorite"] != true || !i.MatchesTags(nil, true) {
		t.Fatal("metadata or empty filter")
	}
}
