package sftpclient

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// blockingReader returns one chunk, then waits until the test has inspected
// the half-written remote file.
type blockingReader struct {
	sent    bool
	written chan struct{}
	release chan struct{}
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "partial secret"), nil
	}
	close(r.written)
	<-r.release
	return 0, io.EOF
}

func TestUploadKeepsPartialContentPrivate(t *testing.T) {
	root := t.TempDir()
	client := testClient(t, root)
	defer client.Close()

	reader := &blockingReader{written: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := client.Upload(context.Background(), reader, "secret.txt", 0o640, -1, nil)
		done <- err
	}()
	<-reader.written
	info, err := os.Stat(filepath.Join(root, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("partial upload readable with mode %o", mode)
	}
	close(reader.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Join(root, "secret.txt"))
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("final mode %v, %v", info.Mode().Perm(), err)
	}
}

func TestRecursiveUploadAppliesDirectoryModes(t *testing.T) {
	root := t.TempDir()
	local := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(filepath.Join(local, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(local, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "nested", "key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := testClient(t, root)
	defer client.Close()
	if _, err := client.UploadPath(context.Background(), local, "bundle", TransferOptions{Recursive: true}, nil); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{"bundle": 0o750, "bundle/nested": 0o750, "bundle/nested/key": 0o600} {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Fatalf("%s mode %o, want %o", path, got, want)
		}
	}
}
