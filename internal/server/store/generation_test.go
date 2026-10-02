package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreRefusesNewerGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(context.Background(), `UPDATE schema_state SET value = '99' WHERE key = 'store_generation'`); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer fd0-server") {
		t.Fatalf("opened a newer-generation database: %v", err)
	}
}
