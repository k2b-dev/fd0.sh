package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInterruptWaitsForTrackedCleanup(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "partial")
	if err := os.WriteFile(artifact, []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	go func() {
		defer trackCleanup()()
		defer func() {
			time.Sleep(50 * time.Millisecond)
			_ = os.Remove(artifact)
		}()
		close(started)
		<-CommandContext().Done()
	}()
	<-started
	Interrupt(2 * time.Second)
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Fatalf("interrupt returned before cleanup: %v", err)
	}
}
