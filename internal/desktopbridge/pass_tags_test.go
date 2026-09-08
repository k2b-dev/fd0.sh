package desktopbridge

import (
	"reflect"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
)

func TestPassSaveMergesOnlyExplicitTags(t *testing.T) {
	stored, err := passitem.Decode([]byte(`{"title":"Login","meta":{"tags":["Work"],"favorite":true,"revision":7,"future":"keep"},"future_key":true}`))
	if err != nil {
		t.Fatal(err)
	}
	// The released 0.3.1 Desktop editor omits meta entirely when saving.
	result, err := preparePassSave(&passitem.Item{Title: "Edited"}, stored)
	if err != nil || !reflect.DeepEqual(result.Tags(), []string{"Work"}) {
		t.Fatal(result, err)
	}
	result, err = preparePassSave(&passitem.Item{Title: "Edited", Meta: map[string]any{"tags": []any{"Server"}}}, result)
	if err != nil || !reflect.DeepEqual(result.Tags(), []string{"Server"}) {
		t.Fatal(result, err)
	}
	if result.Meta["favorite"] != true || result.Meta["future"] != "keep" || result.Meta["revision"] != float64(7) {
		t.Fatal(result.Meta)
	}
	result, err = preparePassSave(&passitem.Item{Title: "Edited", Meta: map[string]any{"tags": []any{}}}, result)
	if err != nil || len(result.Tags()) != 0 {
		t.Fatal(result, err)
	}
	if _, err := preparePassSave(&passitem.Item{Title: "Edited", Meta: map[string]any{"tags": "wrong"}}, result); err == nil {
		t.Fatal("invalid explicit tags accepted")
	}
}

func TestPassCreateWithTagsInitializesMetadata(t *testing.T) {
	result, err := preparePassSave(&passitem.Item{Title: "New", Meta: map[string]any{"tags": []string{"Work"}, "revision": 99, "favorite": true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Meta["revision"] != 1 || result.Meta["created_at"] == nil || result.Meta["favorite"] != nil {
		t.Fatal(result.Meta)
	}
	if !reflect.DeepEqual(result.Tags(), []string{"Work"}) {
		t.Fatal(result.Tags())
	}
}
