package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// Used by both unlock and fresh operation authorization. A saved preference
// preselects the interactive choice; only an explicit selector bypasses it.
func selectAuthenticationMethod(active []proto.AuthMethod, requested, preferred string, interactive bool, in io.Reader, out io.Writer) (proto.AuthMethod, error) {
	if requested != "" {
		return pickUnlockMethod(active, requested)
	}
	preferred = strings.TrimSpace(preferred)
	chosen, err := pickUnlockMethod(active, preferred)
	if err != nil && preferred != "" {
		fmt.Fprintln(out, "warn: auth default no longer matches an enrolled method; choose a new default with fd0 auth default")
		chosen, err = pickUnlockMethod(active, "")
	}
	if err != nil {
		return chosen, err
	}
	if interactive && len(active) > 1 {
		return promptUnlockMethod(active, in, out, chosen.MethodID)
	}
	if len(active) > 1 {
		fmt.Fprintf(out, "Authentication method: %s (override with --method=...)\n", unlockMethodLabel(chosen))
	}
	return chosen, nil
}

// The caller must wipe both credential fields after the operation.
func promptAuthentication(paths fdhome.Paths, active []proto.AuthMethod, requested string) (proto.AuthMethod, agent.UnlockCredential, error) {
	var credential agent.UnlockCredential
	preferred := ""
	if requested == "" {
		cfg, err := fdhome.LoadConfig(paths.Config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: load config: %v; ignoring auth default\n", err)
		} else {
			preferred = cfg.Auth.DefaultMethod
		}
	}
	method, err := selectAuthenticationMethod(active, requested, preferred, IsTTY(os.Stdin) && IsTTY(os.Stderr), os.Stdin, os.Stderr)
	if err != nil {
		return method, credential, err
	}
	switch method.MethodType {
	case proto.AuthPassphrase:
		credential.Passphrase, err = ReadPassphrase("Passphrase: ")
	case proto.AuthYubikey:
		credential.YubikeyPIN, err = readYubikeyUnlockPIN(method, ReadOptionalPIN)
		if err == nil {
			fmt.Fprintln(os.Stderr, "Touch your YubiKey if it blinks…")
		}
	default:
		err = fmt.Errorf("unknown method type %q on user chain", method.MethodType)
	}
	return method, credential, err
}
