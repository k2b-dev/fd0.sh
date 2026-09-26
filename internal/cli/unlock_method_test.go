package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// pickUnlockMethod is the policy for choosing which auth method gets
// the credential prompt. The contract:
//   - explicit --method wins; if no enrolled method matches, error
//     names the offending request and the available types.
//   - empty --method picks the first method by method_id (sorted ASC)
//     so script-driven invocations are deterministic.

func TestPickUnlockMethod_NoActive(t *testing.T) {
	t.Parallel()
	_, err := pickUnlockMethod(nil, "")
	if err == nil {
		t.Fatalf("expected error for empty active list")
	}
}

func TestPickUnlockMethod_ExplicitRequest_Match(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_b", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	got, err := pickUnlockMethod(active, "yubikey")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_b" {
		t.Fatalf("got method_id=%s, want am_b", got.MethodID)
	}
}

func TestPickUnlockMethod_ExplicitRequest_MethodIDMatch(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_b", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	got, err := pickUnlockMethod(active, "am_a")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_a" || got.MethodType != proto.AuthPassphrase {
		t.Fatalf("got method_id=%s type=%s, want am_a/passphrase", got.MethodID, got.MethodType)
	}
}

func TestPickUnlockMethod_ExplicitRequest_NoMatch(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	_, err := pickUnlockMethod(active, "yubikey")
	if err == nil {
		t.Fatalf("expected error for unknown method type")
	}
	if !strings.Contains(err.Error(), "yubikey") {
		t.Fatalf("error should name the requested method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("error should list available methods, got: %v", err)
	}
	if !strings.Contains(err.Error(), "am_a") {
		t.Fatalf("error should list available method ids, got: %v", err)
	}
}

func TestPickUnlockMethod_DefaultPicksFirstByID(t *testing.T) {
	t.Parallel()
	// Order matters: the function must sort by method_id ASCENDING,
	// not pick the first slice element.
	active := []proto.AuthMethod{
		{MethodID: "am_z", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
		{MethodID: "am_m", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_a" {
		t.Fatalf("got method_id=%s, want am_a (smallest)", got.MethodID)
	}
}

func TestPickUnlockMethod_SingleMethodNoFlag(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_only", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "am_only" {
		t.Fatalf("got method_id=%s, want am_only", got.MethodID)
	}
}

func TestPromptUnlockMethod_SelectsSortedMethod(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_z", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	var output bytes.Buffer
	got, err := promptUnlockMethod(active, strings.NewReader("2\n"), &output, "")
	if err != nil {
		t.Fatalf("promptUnlockMethod: %v", err)
	}
	if got.MethodID != "am_z" {
		t.Fatalf("got method_id=%s, want am_z", got.MethodID)
	}
	text := output.String()
	if !strings.Contains(text, "1) Passphrase") || !strings.Contains(text, "2) YubiKey") {
		t.Fatalf("chooser did not render sorted methods:\n%s", text)
	}
}

func TestPromptUnlockMethod_EnterUsesFirstSortedMethod(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_z", MethodType: proto.AuthYubikey},
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
	}
	got, err := promptUnlockMethod(active, strings.NewReader("\n"), &bytes.Buffer{}, "")
	if err != nil {
		t.Fatalf("promptUnlockMethod: %v", err)
	}
	if got.MethodID != "am_a" {
		t.Fatalf("got method_id=%s, want am_a", got.MethodID)
	}
}

func TestPromptUnlockMethod_RepromptsAfterInvalidSelection(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
		{MethodID: "am_b", MethodType: proto.AuthYubikey},
	}
	var output bytes.Buffer
	got, err := promptUnlockMethod(active, strings.NewReader("nope\n3\n2\n"), &output, "")
	if err != nil {
		t.Fatalf("promptUnlockMethod: %v", err)
	}
	if got.MethodID != "am_b" {
		t.Fatalf("got method_id=%s, want am_b", got.MethodID)
	}
	if count := strings.Count(output.String(), "Enter a number between 1 and 2."); count != 2 {
		t.Fatalf("invalid selection messages=%d, want 2:\n%s", count, output.String())
	}
}

func TestPromptUnlockMethod_ClosedInputFails(t *testing.T) {
	t.Parallel()
	_, err := promptUnlockMethod([]proto.AuthMethod{
		{MethodID: "am_a", MethodType: proto.AuthPassphrase},
		{MethodID: "am_b", MethodType: proto.AuthYubikey},
	}, strings.NewReader(""), &bytes.Buffer{}, "")
	if err == nil {
		t.Fatal("expected closed input to fail")
	}
}

// pickUnlockMethod sorts by method_id ascending. Non-ULID method_ids
// (legacy fixtures, hand-edited chains, future-format keys) MUST
// still produce a deterministic, predictable choice. Specifically a
// short or non-prefix id like "0" or "x" should NOT silently
// dominate a normal "am_..." id without the user noticing — when the
// CLI auto-picks, it logs which id it took. We pin the deterministic
// behaviour here.
func TestPickUnlockMethod_NonULIDMethodID(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "am_01HVWZZ", MethodType: proto.AuthPassphrase},
		// "0" sorts before any "am_..." string lexicographically.
		// If it wins, the agent had better not crash — and the CLI
		// must surface the auto-pick logging so the user notices.
		{MethodID: "0", MethodType: proto.AuthYubikey},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "0" {
		t.Fatalf("got method_id=%s, want 0 (smallest by lexicographic sort)", got.MethodID)
	}
	if got.MethodType != proto.AuthYubikey {
		t.Fatalf("got method_type=%s, want yubikey", got.MethodType)
	}
}

// Empty method_id is an unusual case — fixture or corruption. The
// function should still terminate and pick something, not crash.
func TestPickUnlockMethod_EmptyMethodID(t *testing.T) {
	t.Parallel()
	active := []proto.AuthMethod{
		{MethodID: "", MethodType: proto.AuthYubikey},
		{MethodID: "am_b", MethodType: proto.AuthPassphrase},
	}
	got, err := pickUnlockMethod(active, "")
	if err != nil {
		t.Fatalf("pickUnlockMethod: %v", err)
	}
	if got.MethodID != "" {
		t.Fatalf("empty string sorts smallest; got %s want \"\"", got.MethodID)
	}
}

func TestDistinctMethodTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []proto.AuthMethod
		want int
	}{
		{"empty", nil, 0},
		{"single", []proto.AuthMethod{{MethodType: "passphrase"}}, 1},
		{"two distinct", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "yubikey"}}, 2},
		{"two same", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "passphrase"}}, 1},
		{"mixed dup", []proto.AuthMethod{{MethodType: "passphrase"}, {MethodType: "yubikey"}, {MethodType: "passphrase"}}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := distinctMethodTypes(c.in)
			if len(got) != c.want {
				t.Fatalf("got %d distinct, want %d (got %v)", len(got), c.want, got)
			}
		})
	}
}

func TestFriendlyUnlockErrorHidesAEADDetails(t *testing.T) {
	t.Parallel()
	err := friendlyUnlockError(errors.New("agent: vault: AEAD-open wrap am_123: cipher: message authentication failed"))
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "AEAD") || strings.Contains(err.Error(), "cipher") || strings.Contains(err.Error(), "am_123") {
		t.Fatalf("error leaked internals: %s", err)
	}
	if !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("error should explain likely cause: %s", err)
	}
}

func TestFriendlyUnlockErrorExplainsYubikeyAgentFlavor(t *testing.T) {
	t.Parallel()
	err := friendlyUnlockError(vault.ErrYubikeyNotConfigured)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "fd0-agent") || !strings.Contains(err.Error(), "yubikey flavor") {
		t.Fatalf("error should explain agent flavor mismatch: %s", err)
	}
}

func TestFriendlyUnlockErrorExplainsLongYubikeyPIN(t *testing.T) {
	t.Parallel()
	err := friendlyUnlockError(errors.New("agent: yubikey unlock: open card: yubikey: verify PIN: pin longer than 8 bytes"))
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"YubiKey PIV PINs", "6-8 ASCII", "touch-only", "fd0 passphrase"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing %q", msg, want)
		}
	}
}

func TestFriendlyUnlockErrorExplainsLateAgentCompletion(t *testing.T) {
	t.Parallel()
	err := friendlyUnlockError(errors.New("read unix ->/tmp/fd0.sock: i/o timeout"))
	const want = "unlock timed out; run `fd0 agent status` before retrying because the agent may already have completed the unlock"
	if err == nil || err.Error() != want {
		t.Fatalf("friendlyUnlockError()=%v want %q", err, want)
	}
}

func TestYubikeyPINPromptMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		pp   proto.YubikeyPublicParams
		want yubikeyPINPrompt
	}{
		{
			name: "touch-only skips prompt",
			pp: proto.YubikeyPublicParams{
				X25519Pub:     bytesOf('a', 32),
				SealedKUnlock: []byte("sealed"),
				Slot:          0x9d,
				PinPolicy:     "never",
				TouchPolicy:   "always",
			},
			want: yubikeyPINPromptNever,
		},
		{
			name: "pin once prompts",
			pp: proto.YubikeyPublicParams{
				X25519Pub:     bytesOf('b', 32),
				SealedKUnlock: []byte("sealed"),
				Slot:          0x9d,
				PinPolicy:     "once",
				TouchPolicy:   "always",
			},
			want: yubikeyPINPromptRequired,
		},
		{
			name: "legacy missing pin policy keeps optional prompt",
			pp: proto.YubikeyPublicParams{
				X25519Pub:     bytesOf('c', 32),
				SealedKUnlock: []byte("sealed"),
				Slot:          0x9d,
			},
			want: yubikeyPINPromptOptional,
		},
		{
			name: "future unknown pin policy keeps optional prompt",
			pp: proto.YubikeyPublicParams{
				X25519Pub:     bytesOf('d', 32),
				SealedKUnlock: []byte("sealed"),
				Slot:          0x9d,
				PinPolicy:     "future",
			},
			want: yubikeyPINPromptOptional,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			pp, err := proto.Marshal(c.pp)
			if err != nil {
				t.Fatal(err)
			}
			got := yubikeyPINPromptMode(proto.AuthMethod{
				MethodID:     "am_test",
				MethodType:   proto.AuthYubikey,
				PublicParams: pp,
			})
			if got != c.want {
				t.Fatalf("got prompt mode %d, want %d", got, c.want)
			}
		})
	}
}

func TestYubikeyPINPromptModeMalformedParamsAreLegacyOptional(t *testing.T) {
	t.Parallel()
	got := yubikeyPINPromptMode(proto.AuthMethod{
		MethodID:     "am_bad",
		MethodType:   proto.AuthYubikey,
		PublicParams: []byte{0xff},
	})
	if got != yubikeyPINPromptOptional {
		t.Fatalf("got prompt mode %d, want optional fallback", got)
	}
}

func TestReadYubikeyUnlockPINPromptPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		pinPolicy  string
		readPIN    []byte
		wantPIN    []byte
		wantPrompt string
		wantCalls  int
		wantErr    string
	}{
		{
			name:      "touch-only does not prompt",
			pinPolicy: "never",
			wantCalls: 0,
		},
		{
			name:       "pin-protected prompts clearly",
			pinPolicy:  "once",
			readPIN:    []byte("123456"),
			wantPIN:    []byte("123456"),
			wantPrompt: "YubiKey PIV PIN: ",
			wantCalls:  1,
		},
		{
			name:       "pin-protected rejects empty",
			pinPolicy:  "once",
			wantPrompt: "YubiKey PIV PIN: ",
			wantCalls:  1,
			wantErr:    "cannot be empty",
		},
		{
			name:       "legacy keeps optional prompt",
			pinPolicy:  "",
			wantPrompt: "YubiKey PIV PIN (press Enter for touch-only legacy methods): ",
			wantCalls:  1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			method := yubikeyAuthMethodForTest(t, c.pinPolicy)
			var prompts []string
			got, err := readYubikeyUnlockPIN(method, func(prompt string) ([]byte, error) {
				prompts = append(prompts, prompt)
				return append([]byte(nil), c.readPIN...), nil
			})
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error=%v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readYubikeyUnlockPIN: %v", err)
			}
			if string(got) != string(c.wantPIN) {
				t.Fatalf("PIN=%q, want %q", got, c.wantPIN)
			}
			if len(prompts) != c.wantCalls {
				t.Fatalf("prompt calls=%d, want %d (%v)", len(prompts), c.wantCalls, prompts)
			}
			if c.wantCalls > 0 && prompts[0] != c.wantPrompt {
				t.Fatalf("prompt=%q, want %q", prompts[0], c.wantPrompt)
			}
		})
	}
}

func TestYubikeyPolicyNamesForEnrollment(t *testing.T) {
	t.Parallel()
	if got := yubikeyPinPolicyName(nil); got != "never" {
		t.Fatalf("empty PIN policy = %q, want never", got)
	}
	if got := yubikeyPinPolicyName([]byte("123456")); got != "once" {
		t.Fatalf("non-empty PIN policy = %q, want once", got)
	}
	if got := yubikeyTouchPolicyName(0); got != "always" {
		t.Fatalf("default touch policy = %q, want always", got)
	}
}

func yubikeyAuthMethodForTest(t *testing.T, pinPolicy string) proto.AuthMethod {
	t.Helper()
	pp := proto.YubikeyPublicParams{
		X25519Pub:     bytesOf('y', 32),
		SealedKUnlock: []byte("sealed"),
		Slot:          0x9d,
		PinPolicy:     pinPolicy,
		TouchPolicy:   "always",
	}
	ppBytes, err := proto.Marshal(pp)
	if err != nil {
		t.Fatal(err)
	}
	return proto.AuthMethod{MethodID: "am_test", MethodType: proto.AuthYubikey, PublicParams: ppBytes}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
