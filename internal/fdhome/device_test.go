package fdhome

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestDeviceIDStableConcurrentAndPreservesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := "# my settings\nshort_id = \"abc\"\n[sync]\ninterval = \"1h\"\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	ids := make(chan string, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := EnsureDeviceID(path)
			if err != nil {
				t.Error(err)
			}
			ids <- id
		}()
	}
	wg.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if len(id) != 64 {
			t.Fatalf("bad ID %q", id)
		}
		if first == "" {
			first = id
		}
		if id != first {
			t.Fatal("concurrent identities differ")
		}
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), original) {
		t.Fatal("existing settings changed")
	}
	cfg, err := LoadConfig(path)
	if err != nil || cfg.DeviceID != first || cfg.Sync.Interval != "1h" {
		t.Fatal(cfg, err)
	}
	other, err := EnsureDeviceID(filepath.Join(t.TempDir(), "config.toml"))
	if err != nil || other == first {
		t.Fatal("new installation reused device ID", err)
	}
}

func TestDeviceIDRejectsInvalidAndReplacesEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(path, []byte("device_id = \"wrong\"\n"), 0600)
	if _, err := EnsureDeviceID(path); err == nil {
		t.Fatal("invalid ID silently replaced")
	}
	os.WriteFile(path, []byte("device_id = \"\" # unassigned\n[auth]\ndefault_method = \"passphrase\"\n"), 0600)
	if _, err := EnsureDeviceID(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil || cfg.Auth.DefaultMethod != "passphrase" {
		t.Fatal(cfg, err)
	}
}
