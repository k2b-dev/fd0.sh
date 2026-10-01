package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

func TestExitCodeSeparatesStatesScriptsMustHandle(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("get: %w", cli.ErrAgentLocked), 3},
		{cli.ErrAgentNotRunning, 3},
		{fmt.Errorf("open: %w at /x (waited 5s)", cli.ErrVaultBusy), 4},
		{errors.New("secret \"x\" not found"), 1},
	} {
		if got := exitCode(tc.err); got != tc.want {
			t.Fatalf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}
