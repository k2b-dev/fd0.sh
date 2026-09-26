package chain

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestReadOnlyScopeReadDoesNotRepairPartialWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.cbor")
	prefix, err := proto.Marshal(&proto.ScopeEvent{})
	if err != nil {
		t.Fatal(err)
	}
	data := append(prefix, 0x78, 0x20) // incomplete CBOR text item
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadScopeEventsReadOnly(path); err == nil {
		t.Fatal("partial tail accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("read-only activation changed a writer's file", err)
	}
}
