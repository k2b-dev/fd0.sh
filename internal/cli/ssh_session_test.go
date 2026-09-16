package cli

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

func TestSSHLockWaitCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	holder := flock.New(path)
	if err := holder.Lock(); err != nil {
		t.Fatal(err)
	}
	defer holder.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- acquireLockFor(ctx, flock.New(path), "1m") }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("lock wait ignored cancellation")
	}
}
