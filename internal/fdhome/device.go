package fdhome

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofrs/flock"
)

// EnsureDeviceID identifies this fd0 home, not its hardware or user identity.
// Copying the entire home copies the ID; a fresh installation gets a new one.
func EnsureDeviceID(configPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return "", err
	}
	lock := flock.New(configPath + ".lock")
	if err := lock.Lock(); err != nil {
		return "", err
	}
	defer lock.Unlock()
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return "", err
	}
	if cfg.DeviceID != "" {
		b, err := hex.DecodeString(cfg.DeviceID)
		if err != nil || len(b) != 32 {
			return "", errors.New("invalid device_id in fd0 config")
		}
		return cfg.DeviceID, nil
	}
	old, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	// Do not introduce a duplicate TOML key if an empty device_id was set.
	lines := strings.Split(string(old), "\n")
	for i, line := range lines {
		if isTOMLTableHeader(strings.TrimSpace(line)) {
			break
		}
		if isTOMLKey(strings.TrimSpace(line), "device_id") {
			lines[i] = ""
		}
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return "", err
	}
	id := hex.EncodeToString(idBytes)
	data := "device_id = \"" + id + "\"\n" + strings.Join(lines, "\n")
	f, err := os.CreateTemp(filepath.Dir(configPath), ".device-config-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := os.Rename(f.Name(), configPath); err != nil {
		return "", err
	}
	return id, nil
}
