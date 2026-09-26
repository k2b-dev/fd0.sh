package desktopbridge

import (
	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func authenticationCredential(method proto.AuthMethod, passphrase, pin []byte) (agent.UnlockCredential, error) {
	var credential agent.UnlockCredential
	switch method.MethodType {
	case proto.AuthPassphrase:
		if len(passphrase) == 0 {
			return agent.UnlockCredential{}, fail("validation", "Enter your vault passphrase.", "", false)
		}
		if len(pin) > 0 {
			return agent.UnlockCredential{}, fail("validation", "A YubiKey PIN cannot be used with passphrase unlock.", "", false)
		}
		credential.Passphrase = passphrase
	case proto.AuthYubikey:
		if len(passphrase) > 0 {
			return agent.UnlockCredential{}, fail("validation", "Your fd0 passphrase is not a YubiKey PIN.", "Choose Passphrase or clear the passphrase field.", false)
		}
		pinMode := yubikeyPINMode(method)
		if pinMode == "none" && len(pin) > 0 {
			return agent.UnlockCredential{}, fail("validation", "This YubiKey method is touch-only and does not use a PIN.", "Clear the PIN and try again.", false)
		}
		if pinMode == "required" && len(pin) == 0 {
			return agent.UnlockCredential{}, fail("validation", "Enter the YubiKey PIV PIN.", "", false)
		}
		if len(pin) > 0 && (len(pin) < 6 || len(pin) > 8) {
			return agent.UnlockCredential{}, fail("validation", "YubiKey PIV PINs are 6 to 8 characters.", "Do not enter your fd0 passphrase.", false)
		}
		credential.YubikeyPIN = pin
	default:
		return agent.UnlockCredential{}, fail("method_unavailable", "This unlock method is not supported by fd0 Desktop.", "Use the fd0 CLI for this method.", false)
	}
	return credential, nil
}
