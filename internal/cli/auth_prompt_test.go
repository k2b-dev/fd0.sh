package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

func TestAuthenticationMethodChoice(t *testing.T) {
	methods := []proto.AuthMethod{{MethodID: "am_a", MethodType: proto.AuthPassphrase}, {MethodID: "am_z", MethodType: proto.AuthYubikey}}
	for _, tc := range []struct {
		name, requested, preferred, input, want string
		interactive, prompt, warning            bool
	}{
		{"choose key", "", "", "2\n", "am_z", true, true, false},
		{"default is only preselected", "", "yubikey", "1\n", "am_a", true, true, false},
		{"enter accepts preference", "", "yubikey", "\n", "am_z", true, true, false},
		{"stale preference", "", "am_removed", "2\n", "am_z", true, true, true},
		{"explicit selector bypasses", "yubikey", "passphrase", "", "am_z", true, false, false},
		{"noninteractive preference", "", "yubikey", "", "am_z", false, false, false},
		{"noninteractive deterministic", "", "", "", "am_a", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := selectAuthenticationMethod(methods, tc.requested, tc.preferred, tc.interactive, strings.NewReader(tc.input), &out)
			if err != nil || got.MethodID != tc.want {
				t.Fatalf("got %v, %v", got, err)
			}
			if strings.Contains(out.String(), "Choose authentication method:") != tc.prompt {
				t.Fatal(out.String())
			}
			if strings.Contains(out.String(), "warn:") != tc.warning {
				t.Fatal(out.String())
			}
		})
	}
	if _, err := selectAuthenticationMethod(methods, "missing", "", true, strings.NewReader("1\n"), &bytes.Buffer{}); err == nil {
		t.Fatal("invalid explicit method silently fell back")
	}
	if _, err := selectAuthenticationMethod(methods, "", "", true, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("EOF authorized a default")
	}
}
