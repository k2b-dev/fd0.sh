package desktopbridge

import (
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"testing"
)

func TestAuthenticationCredentialRules(t *testing.T) {
	for _, tc := range []struct {
		name, kind, policy, pass, pin string
		valid                         bool
	}{
		{"passphrase", proto.AuthPassphrase, "", "synthetic", "", true},
		{"missing passphrase", proto.AuthPassphrase, "", "", "", false},
		{"mixed passphrase", proto.AuthPassphrase, "", "synthetic", "123456", false},
		{"touch only", proto.AuthYubikey, "never", "", "", true},
		{"unexpected PIN", proto.AuthYubikey, "never", "", "123456", false},
		{"required PIN", proto.AuthYubikey, "always", "", "123456", true},
		{"missing PIN", proto.AuthYubikey, "always", "", "", false},
		{"short PIN", proto.AuthYubikey, "always", "", "123", false},
		{"legacy optional", proto.AuthYubikey, "", "", "", true},
		{"mixed key", proto.AuthYubikey, "never", "synthetic", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params, err := proto.Marshal(proto.YubikeyPublicParams{PinPolicy: tc.policy})
			if err != nil {
				t.Fatal(err)
			}
			credential, err := authenticationCredential(proto.AuthMethod{MethodType: tc.kind, PublicParams: params}, []byte(tc.pass), []byte(tc.pin))
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
			if tc.valid && (string(credential.Passphrase) != tc.pass || string(credential.YubikeyPIN) != tc.pin) {
				t.Fatal("credential changed")
			}
		})
	}
}
