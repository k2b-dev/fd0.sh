package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

// RunAgentStatus prints process-level agent health. `fd0 status` remains the
// compact vault status; this command is for lifecycle/debugging.
func RunAgentStatus(ctx context.Context) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	c := agent.NewClient(paths.AgentSock)
	if !c.IsRunning() {
		fmt.Println("agent: not running")
		printSocketState("agent socket", paths.AgentSock)
		printSSHSocketState()
		return nil
	}
	st, err := c.Status()
	if err != nil {
		return err
	}
	if st.Unlocked {
		fmt.Printf("agent: running, unlocked since %d\n", st.SinceUnix)
	} else {
		fmt.Println("agent: running, locked")
	}
	if st.Version != "" || st.Flavor != "" {
		fmt.Printf("version: %s %s\n", emptyAsUnknown(st.Version), emptyAsUnknown(st.Flavor))
	}
	fmt.Printf("pid file: %s\n", paths.AgentPID)
	fmt.Printf("agent socket: ok (%s)\n", paths.AgentSock)
	printSSHSocketState()
	return nil
}

// RunAgentStop stops the fd0-agent process recorded by this FD0_HOME.
func RunAgentStop(ctx context.Context) error {
	if handled, err := runDesktopManagedAgentCommand(ctx, "stop"); handled {
		return err
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	stopped, _, err := stopAgentProcess(paths)
	if err != nil {
		return err
	}
	cleanupStaleAgentFiles(paths)
	cleanupStaleSSHSocket()
	if stopped {
		fmt.Fprintln(os.Stderr, "✓ agent stopped")
	} else {
		fmt.Fprintln(os.Stderr, "agent is not running")
	}
	return nil
}

// RunAgentRestart replaces fd0-agent with the current fd0-agent binary. If the
// previous process held an unlocked vault and this invocation is interactive,
// it prompts once to unlock the fresh process.
func RunAgentRestart(ctx context.Context, agentBin string) error {
	if handled, err := runDesktopManagedAgentCommand(ctx, "restart"); handled {
		return err
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	_, wasUnlocked, err := stopAgentProcess(paths)
	if err != nil {
		return err
	}
	cleanupStaleAgentFiles(paths)
	cleanupStaleSSHSocket()
	if err := agent.Spawn(agentBin, paths.AgentLog); err != nil {
		return err
	}
	if err := agent.WaitReady(paths.AgentSock, agentReadyTimeout); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ agent restarted")
	if wasUnlocked {
		if IsTTY(os.Stdin) && IsTTY(os.Stderr) {
			return RunUnlock(ctx, agentBin, "", "")
		}
		fmt.Fprintln(os.Stderr, "vault is locked; run `fd0 unlock`")
	}
	return nil
}

func runDesktopManagedAgentCommand(ctx context.Context, command string) (bool, error) {
	if os.Getenv("FD0_DESKTOP_MANAGED") != "1" {
		return false, nil
	}
	if strings.TrimSpace(os.Getenv("FD0_HOME")) != "" || os.Getenv("FD0_SSH_SOCK") != "" {
		return false, nil
	}
	appPath := strings.TrimSpace(os.Getenv("FD0_DESKTOP_APP"))
	if appPath == "" {
		return true, errors.New("desktop-managed fd0 is missing FD0_DESKTOP_APP")
	}
	executable := appPath
	if runtime.GOOS == "darwin" && strings.HasSuffix(strings.ToLower(appPath), ".app") {
		executable = filepath.Join(appPath, "Contents", "MacOS", "fd0")
	}
	cmd := exec.CommandContext(ctx, executable, "--fd0-agent-service-"+command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return true, fmt.Errorf("desktop agent %s: %w", command, err)
	}
	verb := "stopped"
	if command == "restart" {
		verb = "restarted"
	}
	fmt.Fprintf(os.Stderr, "✓ agent %s by fd0 Desktop\n", verb)
	return true, nil
}

func stopAgentProcess(paths fdhome.Paths) (stopped, wasUnlocked bool, err error) {
	c := agent.NewClient(paths.AgentSock)
	if !c.IsRunning() {
		return false, false, nil
	}
	if st, serr := c.Status(); serr == nil {
		wasUnlocked = st.Unlocked
	}
	if _, statErr := os.Stat(paths.AgentPID); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return false, wasUnlocked, fmt.Errorf("agent is running but %s is missing; cannot stop it safely", paths.AgentPID)
		}
		return false, wasUnlocked, statErr
	}
	if err := agent.StopByPIDFile(paths.AgentPID, 2*time.Second); err != nil {
		return false, wasUnlocked, err
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !c.IsRunning() {
			return true, wasUnlocked, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false, wasUnlocked, errors.New("agent did not stop cleanly; inspect `fd0 agent status`")
}

func cleanupStaleAgentFiles(paths fdhome.Paths) {
	c := agent.NewClient(paths.AgentSock)
	if c.IsRunning() {
		return
	}
	_ = os.Remove(paths.AgentPID)
	removeSocketIfStale(paths.AgentSock)
}

func cleanupStaleSSHSocket() {
	if sshAgentSocketDisabledByEnv() {
		return
	}
	removeSocketIfStale(SSHSocketPathForRender())
}

func removeSocketIfStale(path string) {
	if path == "" {
		return
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		return
	}
	if checkSSHAgentSocket(path) == nil {
		return
	}
	_ = os.Remove(path)
}

func printSocketState(label, path string) {
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("%s: missing (%s)\n", label, path)
		return
	}
	if err != nil {
		fmt.Printf("%s: error: %v\n", label, err)
		return
	}
	if st.Mode()&os.ModeSocket == 0 {
		fmt.Printf("%s: not a socket (%s)\n", label, path)
		return
	}
	if checkSSHAgentSocket(path) == nil {
		fmt.Printf("%s: ok (%s)\n", label, path)
		return
	}
	fmt.Printf("%s: stale (%s)\n", label, path)
}

func emptyAsUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func printSSHSocketState() {
	if sshAgentSocketDisabledByEnv() {
		fmt.Println("ssh socket: disabled by FD0_SSH_SOCK")
		return
	}
	path := SSHSocketPathForRender()
	st, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Printf("ssh socket: missing (%s)\n", path)
		return
	}
	if err != nil {
		fmt.Printf("ssh socket: error: %v\n", err)
		return
	}
	if st.Mode()&os.ModeSocket == 0 {
		fmt.Printf("ssh socket: not a socket (%s)\n", path)
		return
	}
	if err := checkSSHAgentSocket(path); err != nil {
		fmt.Printf("ssh socket: unavailable (%s): %v\n", path, err)
		return
	}
	fmt.Printf("ssh socket: ok (%s)\n", path)
}
