package recipe

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/service"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func testService(t *testing.T) *service.Service {
	t.Helper()
	var s service.Service
	for _, f := range []struct{ name, typ, env, value string }{
		{"db-password", "", "DB_PASSWORD", "s3cret pw"},
		{"region", service.FieldText, "REGION", "eu"},
		{"ca.crt", service.FieldFile, "", "-----BEGIN-----\n"},
	} {
		if _, err := s.Set(f.name, f.typ, []byte(f.value), f.env, now); err != nil {
			t.Fatal(err)
		}
	}
	return &s
}

func valid() *Recipe {
	return &Recipe{Version: Version, Service: "shop-db", Command: []string{"/bin/sh", "-c", "cat"},
		Fields: []Mapping{{Field: "db-password", As: "DB_PASSWORD"}}, Input: InputSystemdEnv}
}

func TestValidateRejectsUnsafeDefinitions(t *testing.T) {
	for name, mutate := range map[string]func(*Recipe){
		"relative program":   func(r *Recipe) { r.Command[0] = "sh" },
		"no fields":          func(r *Recipe) { r.Fields = nil },
		"duplicate field":    func(r *Recipe) { r.Fields = append(r.Fields, Mapping{Field: "db-password"}) },
		"bad env name":       func(r *Recipe) { r.Fields[0].As = "lower" },
		"unknown input":      func(r *Recipe) { r.Input = "stdin:yaml" },
		"file with two":      func(r *Recipe) { r.Input = InputFile; r.Fields = append(r.Fields, Mapping{Field: "region"}) },
		"bad target":         func(r *Recipe) { r.Targets = []string{"app 1"} },
		"duplicate target":   func(r *Recipe) { r.Targets = []string{"a", "a"} },
		"relative dir":       func(r *Recipe) { r.Dir = "work" },
		"nul in argument":    func(r *Recipe) { r.Command = append(r.Command, "a\x00b") },
		"k8s without secret": func(r *Recipe) { r.Input = "stdin:k8s-secret:app" },
		"newer version":      func(r *Recipe) { r.Version = Version + 1 },
		"implicit env name":  func(r *Recipe) { r.Fields[0].As = "" },
		"reserved name":      func(r *Recipe) { r.Fields[0].As = "FD0_TARGET" },
		"duplicate name": func(r *Recipe) {
			r.Fields = append(r.Fields, Mapping{Field: "region", As: "DB_PASSWORD"})
		},
	} {
		r := valid()
		mutate(r)
		if err := r.Validate(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	r := valid()
	r.Command[0] = "~/bin/deploy"
	r.Dir = "~/work"
	if err := r.Validate(); err != nil {
		t.Fatalf("home-relative program refused: %v", err)
	}
}

func TestDecodeRefusesUnknownFieldsAndNewerVersions(t *testing.T) {
	raw, _ := json.Marshal(valid())
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	withExtra := strings.Replace(string(raw), `"version":1`, `"version":1,"shell":true`, 1)
	if _, err := Decode([]byte(withExtra)); err == nil {
		t.Fatal("unknown execution field accepted")
	}
	newer := strings.Replace(string(raw), `"version":1`, `"version":2`, 1)
	if _, err := Decode([]byte(newer)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("newer version: %v", err)
	}
}

func TestDigestPinsExecutionButNotDescription(t *testing.T) {
	base := Digest("s_scope", "shop-db/apps", valid(), "/home/u")
	same := valid()
	same.Description = "documentation only"
	if Digest("s_scope", "shop-db/apps", same, "/home/u") != base {
		t.Fatal("description changed the digest")
	}
	for name, mutate := range map[string]func(*Recipe){
		"command": func(r *Recipe) { r.Command[2] = "cat > /tmp/x" },
		"fields":  func(r *Recipe) { r.Fields[0].As = "PGPASSWORD" },
		"input":   func(r *Recipe) { r.Input = InputEnv },
		"targets": func(r *Recipe) { r.Targets = []string{"app-1"} },
		"dir":     func(r *Recipe) { r.Dir = "/srv" },
	} {
		r := valid()
		mutate(r)
		if Digest("s_scope", "shop-db/apps", r, "/home/u") == base {
			t.Fatalf("%s change kept the digest", name)
		}
	}
	if Digest("s_scope", "shop-db/apps", valid(), "/home/other") == base {
		t.Fatal("home not pinned")
	}
	if Digest("s_other", "shop-db/apps", valid(), "/home/u") == base || Digest("s_scope", "shop-db/other", valid(), "/home/u") == base {
		t.Fatal("scope or name not pinned")
	}
}

func TestPrepareRendersEachInput(t *testing.T) {
	svc := testService(t)
	r := valid()
	r.Fields = []Mapping{{Field: "db-password", As: "PGPASSWORD"}, {Field: "region", As: "REGION"}}
	p, err := r.Prepare(svc)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(p.Data); got != "PGPASSWORD=\"s3cret pw\"\nREGION=\"eu\"\n" || p.Env != nil {
		t.Fatalf("systemd-env: %q %v", got, p.Env)
	}
	r.Input = InputEnv
	if p, err = r.Prepare(svc); err != nil || p.Data != nil || p.Channel != ChannelEnv || strings.Join(p.Env, "|") != "PGPASSWORD=s3cret pw|REGION=eu" {
		t.Fatalf("env: %+v %v", p, err)
	}
	r.Input, r.Fields = InputFile, []Mapping{{Field: "ca.crt"}}
	if p, err = r.Prepare(svc); err != nil || string(p.Data) != "-----BEGIN-----\n" {
		t.Fatalf("file: %+v %v", p, err)
	}
	r.Input, r.Fields = "stdin:k8s-secret:app/pg", []Mapping{{Field: "db-password", As: "DATABASE_PASSWORD"}}
	if p, err = r.Prepare(svc); err != nil || !strings.Contains(string(p.Data), "DATABASE_PASSWORD:") || !strings.Contains(string(p.Data), "namespace: app") {
		t.Fatalf("k8s: %s %v", p.Data, err)
	}
	r.Input, r.Fields = InputEnv, []Mapping{{Field: "missing", As: "X"}}
	if _, err := r.Prepare(svc); err == nil {
		t.Fatal("missing field accepted")
	}
	r.Fields = []Mapping{{Field: "ca.crt", As: "CA"}}
	if _, err := r.Prepare(svc); err == nil {
		t.Fatal("file field passed through the environment")
	}
}

func TestSplitNameAndResultName(t *testing.T) {
	if s, n, err := SplitName("shop-db/apps"); err != nil || s != "shop-db" || n != "apps" {
		t.Fatalf("%q %q %v", s, n, err)
	}
	for _, bad := range []string{"shop-db", "/apps", "shop-db/", "a/b/c", "a b/c"} {
		if _, _, err := SplitName(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if ResultName("shop-db/apps", "", "dev1") != "shop-db/apps/-/dev1" {
		t.Fatal("result name without target")
	}
}

func TestResolveNamesStoresEnvNames(t *testing.T) {
	svc := testService(t)
	r := valid()
	r.Fields = []Mapping{{Field: "db-password"}, {Field: "region", As: "AWS_REGION"}}
	if err := r.ResolveNames(svc); err != nil {
		t.Fatal(err)
	}
	if r.Fields[0].As != "DB_PASSWORD" || r.Fields[1].As != "AWS_REGION" {
		t.Fatalf("names: %+v", r.Fields)
	}
	r.Fields = []Mapping{{Field: "ca.crt"}}
	if err := r.ResolveNames(svc); err == nil {
		t.Fatal("field without env name resolved")
	}
}

func TestResultConsistency(t *testing.T) {
	res := Result{Recipe: "shop-db/apps", Target: "app-1", Device: "dev1", Status: "ok", At: "2026-10-04T12:00:00Z"}
	if !res.Consistent("shop-db/apps/app-1/dev1") {
		t.Fatal("consistent result rejected")
	}
	if res.Consistent("shop-db/apps/app-1/dev2") || res.Consistent("shop-db/other/app-1/dev1") {
		t.Fatal("mismatched result accepted")
	}
}

func TestResultConsistencyChecksStatusAndTime(t *testing.T) {
	base := Result{Recipe: "a/b", Device: "d", Status: "ok", At: "2026-10-04T12:00:00Z"}
	if !base.Consistent("a/b/-/d") {
		t.Fatal("valid result rejected")
	}
	for name, mutate := range map[string]func(*Result){
		"ok with exit code": func(r *Result) { r.ExitCode = 7 },
		"failed with zero":  func(r *Result) { r.Status = "failed" },
		"control sequence":  func(r *Result) { r.At = "\x1b[2J2026-10-04T12:00:00Z" },
		"unknown status":    func(r *Result) { r.Status = "maybe" },
	} {
		r := base
		mutate(&r)
		if r.Consistent("a/b/-/d") {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestFD3InputUsesSameFormats(t *testing.T) {
	svc := testService(t)
	r := valid()
	r.Input = "fd3:systemd-env"
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	p, err := r.Prepare(svc)
	if err != nil || p.Channel != ChannelFD3 || string(p.Data) != "DB_PASSWORD=\"s3cret pw\"\n" {
		t.Fatalf("fd3: %+v %v", p, err)
	}
	for _, bad := range []string{"fd3:", "fd3:env", "stdin:env", "fd4:sh", "pipe:file", "env:garbage", "env:\x1b]52;c;x\x07"} {
		r.Input = bad
		if err := r.Validate(); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	r.Input, r.Fields = "fd3:k8s-secret:app/pg", []Mapping{{Field: "db-password"}}
	if err := r.Validate(); err != nil {
		t.Fatalf("fd3 k8s: %v", err)
	}
}
