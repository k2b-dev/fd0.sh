package cli

import (
	"context"
	"sync"
	"time"
)

// Commands that stage credentials or partial transfers in temporary files
// mark that section with trackCleanup. On SIGINT or SIGTERM fd0 cancels the
// command context and waits briefly so their deferred cleanup can run before
// the process exits.
var (
	commandCtx, cancelCommands = context.WithCancel(context.Background())
	cleanupMu                  sync.Mutex
	cleanupsRunning            int
)

// CommandContext is the root context for CLI commands. It is cancelled when
// fd0 is interrupted.
func CommandContext() context.Context { return commandCtx }

func trackCleanup() func() {
	cleanupMu.Lock()
	cleanupsRunning++
	cleanupMu.Unlock()
	return func() {
		cleanupMu.Lock()
		cleanupsRunning--
		cleanupMu.Unlock()
	}
}

// InterruptCleanupWindow is how long an interrupt waits for tracked cleanup,
// such as a deploy saving the result of the target it was running.
const InterruptCleanupWindow = 20 * time.Second

// Interrupt cancels running commands and waits up to timeout for tracked
// cleanup to finish.
func Interrupt(timeout time.Duration) {
	cancelCommands()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cleanupMu.Lock()
		running := cleanupsRunning
		cleanupMu.Unlock()
		if running == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
