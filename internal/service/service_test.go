package service

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func TestSetKeepsTypeAndStampsChanges(t *testing.T) {
	var s Service
	if _, err := s.Set("db-password", "", []byte("one"), "DB_PASSWORD", now); err != nil {
		t.Fatal(err)
	}
	f, _ := s.Field("db-password")
	if f.Type != FieldSecret || f.Revision != 1 || f.ChangedAt == "" {
		t.Fatalf("new field: %+v", f)
	}
	if changed, err := s.Set("db-password", "", []byte("one"), "", now.Add(time.Hour)); err != nil || changed {
		t.Fatalf("unchanged value reported a change: %v %v", changed, err)
	}
	if _, err := s.Set("db-password", "", []byte("two"), "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	f, _ = s.Field("db-password")
	if f.Type != FieldSecret || f.Revision != 2 || f.ChangedAt != "2026-10-01T13:00:00Z" || f.Env != "DB_PASSWORD" {
		t.Fatalf("update: %+v", f)
	}
	if _, err := s.Set("db-password", FieldText, []byte("three"), "", now); err == nil {
		t.Fatal("type change was accepted")
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	var s Service
	for _, tc := range []struct {
		name, typ, env string
		value          []byte
	}{
		{"../x", "", "", []byte("v")},
		{"ok", "", "lower", []byte("v")},
		{"ok", "bogus", "", []byte("v")},
		{"ok", FieldText, "", []byte("a\x00b")},
		{"ok", FieldFile, "FILE_ENV", []byte("x")},
		{"ok", FieldSecret, "", make([]byte, MaxValueBytes+1)},
	} {
		c := s
		if _, err := c.Set(tc.name, tc.typ, tc.value, tc.env, now); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	if _, err := s.Set("a", "", []byte("1"), "SAME", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("b", "", []byte("2"), "SAME", now); err == nil {
		t.Fatal("duplicate env name accepted")
	}
}

func TestFileFieldsKeepBytes(t *testing.T) {
	var s Service
	data := []byte{0, 1, 2, 255, '\n'}
	if _, err := s.Set("runtime.creds", FieldFile, data, "", now); err != nil {
		t.Fatal(err)
	}
	f, _ := s.Field("runtime.creds")
	got, err := f.Bytes()
	if err != nil || string(got) != string(data) {
		t.Fatalf("file round trip: %v %v", got, err)
	}
	if _, err := RenderEnv([]Field{*f}, DialectShell); err == nil {
		t.Fatal("file rendered as env")
	}
}

func TestEnvDialectsRoundTripThroughRealParsers(t *testing.T) {
	values := []string{`plain`, `with space`, `quote"double`, `quote'single`, `dollar $HOME $(id)`, "back\\slash", "tab\tinside"}
	var s Service
	for i, v := range values {
		if _, err := s.Set(string(rune('a'+i)), "", []byte(v), "V"+string(rune('A'+i)), now); err != nil {
			t.Fatal(err)
		}
	}
	fields, _ := s.Select(nil)
	sh, err := RenderEnv(fields, DialectShell)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "env.sh")
	if err := os.WriteFile(file, sh, 0o600); err != nil {
		t.Fatal(err)
	}
	for i, v := range values {
		out, err := exec.Command("sh", "-c", `. "$1"; printf %s "$2"`, "sh", file, "").Output()
		_ = out
		if err != nil {
			t.Fatal(err)
		}
		got, err := exec.Command("sh", "-c", `. "$1"; eval "printf %s \"\$$2\""`, "sh", file, "V"+string(rune('A'+i))).Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != v {
			t.Fatalf("sh round trip %q -> %q", v, got)
		}
	}
	systemd, err := RenderEnv(fields, DialectSystemd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(systemd), `VC="quote\"double"`) || !strings.Contains(string(systemd), `VF="back\\slash"`) {
		t.Fatalf("systemd escaping:\n%s", systemd)
	}
	if _, err := RenderEnv(fields, DialectDocker); err != nil {
		t.Fatalf("docker rejected representable values: %v", err)
	}
	var bad Service
	_, _ = bad.Set("x", "", []byte("line\nbreak"), "X", now)
	f, _ := bad.Select(nil)
	for _, d := range []string{DialectSystemd, DialectDocker} {
		if _, err := RenderEnv(f, d); err == nil {
			t.Fatalf("%s accepted a line break", d)
		}
	}
	if _, err := RenderEnv(f, DialectShell); err != nil {
		t.Fatalf("sh should hold a line break: %v", err)
	}
}

func TestRenderK8sSecret(t *testing.T) {
	var s Service
	_, _ = s.Set("db-password", "", []byte("synthetic"), "", now)
	_, _ = s.Set("ca.crt", FieldFile, []byte("-----BEGIN-----\n"), "", now)
	keys, err := ParseSecretKeys([]string{"db-password=DATABASE_PASSWORD", "ca.crt"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := RenderK8sSecret(&s, "pg-1", "org-app", "app-runtime", keys)
	if err != nil {
		t.Fatal(err)
	}
	want := "  DATABASE_PASSWORD: " + base64.StdEncoding.EncodeToString([]byte("synthetic"))
	if !strings.Contains(string(out), want) || !strings.Contains(string(out), `fd0.sh/service: "pg-1"`) || !strings.Contains(string(out), "type: Opaque") {
		t.Fatalf("manifest:\n%s", out)
	}
	if _, err := RenderK8sSecret(&s, "pg-1", "Bad_NS", "x", nil); err == nil {
		t.Fatal("invalid namespace accepted")
	}
	if _, err := RenderK8sSecret(&s, "pg-1", "ns", "x", []SecretKey{{"db-password", "a"}, {"ca.crt", "a"}}); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestParseEnvFile(t *testing.T) {
	pairs, err := ParseEnvFile([]byte("# c\nexport A=1\nB=\"two words\"\n\nC='x=y'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 3 || pairs[1][1] != "two words" || pairs[2][1] != "x=y" {
		t.Fatalf("pairs: %v", pairs)
	}
	for _, bad := range []string{"", "novalue\n", "lower=1\n", "A=1\nA=2\n"} {
		if _, err := ParseEnvFile([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if FieldNameForEnv("PG_REPLICATION_PASSWORD") != "pg-replication-password" {
		t.Fatal("field name derivation")
	}
}

func TestExecEnv(t *testing.T) {
	var s Service
	_, _ = s.Set("token", "", []byte("multi\nline"), "TOKEN", now)
	_, _ = s.Set("bin", "", []byte("a\x00b"), "BIN", now)
	ok, _ := s.Select([]string{"token"})
	if env, err := ExecEnv(ok); err != nil || len(env) != 1 || env[0] != "TOKEN=multi\nline" {
		t.Fatalf("exec env: %q %v", env, err)
	}
	nul, _ := s.Select([]string{"bin"})
	if _, err := ExecEnv(nul); err == nil {
		t.Fatal("NUL byte accepted")
	}
}
