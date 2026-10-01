package cli

import (
	"bufio"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awnumar/memguard"
	"github.com/creack/pty"
	"golang.org/x/term"
)

func TestTerminalSafeNeutralizesControlCharacters(t *testing.T) {
	input := "work\x1b]52;c;stolen\a\n\t\u0085safe"
	got := terminalSafe(input)
	want := "work?]52;c;stolen????safe"
	if got != want {
		t.Fatalf("terminalSafe(%q) = %q, want %q", input, got, want)
	}
}

func TestTerminalSafePreservesOrdinaryUnicode(t *testing.T) {
	const input = "Kolb Antik - Schlüssel"
	if got := terminalSafe(input); got != input {
		t.Fatalf("terminalSafe(%q) = %q", input, got)
	}
}

func TestInterruptedHiddenInputRestoresTerminal(t *testing.T) {
	if mode := os.Getenv("FD0_TEST_HIDDEN_INPUT_INTERRUPT"); mode != "" {
		memguard.CatchSignal(func(_ os.Signal) {
			RestoreTerminal()
		}, os.Interrupt)
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		switch mode {
		case "passphrase":
			_, _ = ReadPassphrase("Passphrase:\n")
		case "pin":
			_, _ = ReadOptionalPIN("YubiKey PIN:\n")
		default:
			os.Exit(2)
		}
		os.Exit(0)
	}

	for _, tt := range []struct {
		name   string
		mode   string
		prompt string
	}{
		{name: "passphrase", mode: "passphrase", prompt: "Passphrase:"},
		{name: "YubiKey PIN", mode: "pin", prompt: "YubiKey PIN:"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testInterruptedHiddenInputRestoresTerminal(t, tt.mode, tt.prompt)
		})
	}
}

func testInterruptedHiddenInputRestoresTerminal(t *testing.T, mode, prompt string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestInterruptedHiddenInputRestoresTerminal$")
	// CI=true stops the terminal-colour query at startup; outside CI its
	// reply lands in the pty and the prompt never arrives.
	cmd.Env = append(os.Environ(), "FD0_TEST_HIDDEN_INPUT_INTERRUPT="+mode, "CI=true")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatalf("start helper in pty: %v", err)
	}
	defer ptmx.Close()
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	initial, err := term.GetState(int(ptmx.Fd()))
	if err != nil {
		t.Fatalf("read initial terminal state: %v", err)
	}
	if _, err := ptmx.Write([]byte("\n")); err != nil {
		t.Fatalf("release helper: %v", err)
	}
	reader := bufio.NewReader(ptmx)
	promptReady := make(chan error, 1)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				promptReady <- err
				return
			}
			if strings.Contains(line, prompt) {
				promptReady <- nil
				return
			}
		}
	}()
	select {
	case err := <-promptReady:
		if err != nil {
			t.Fatalf("wait for hidden-input prompt: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for hidden-input prompt")
	}

	var hidden *term.State
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		hidden, err = term.GetState(int(ptmx.Fd()))
		if err == nil && !reflect.DeepEqual(hidden, initial) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hidden == nil || reflect.DeepEqual(hidden, initial) {
		t.Fatal("hidden input never disabled terminal echo")
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("interrupt helper: %v", err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("interrupt helper exited successfully, want interrupted exit")
	}
	restored, err := term.GetState(int(ptmx.Fd()))
	if err != nil {
		t.Fatalf("read restored terminal state: %v", err)
	}
	if !reflect.DeepEqual(restored, initial) {
		t.Fatal("terminal state was not restored after interrupt")
	}
}
