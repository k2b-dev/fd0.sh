package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateVersionHelpers(t *testing.T) {
	cases := []struct {
		in      string
		tag     string
		dl      string
		version string
	}{
		{"0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"v0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"client-v0.8.0", "client-v0.8.0", "v0.8.0", "0.8.0"},
		{"fd0-v1.2.3", "fd0-v1.2.3", "v1.2.3", "1.2.3"},
	}
	for _, c := range cases {
		if got := canonicalClientReleaseTag(c.in); got != c.tag {
			t.Fatalf("canonicalClientReleaseTag(%q)=%q want %q", c.in, got, c.tag)
		}
		if got := explicitDownloadTag(c.in); got != c.dl {
			t.Fatalf("explicitDownloadTag(%q)=%q want %q", c.in, got, c.dl)
		}
		if got := releaseVersionNumber(c.tag); got != c.version {
			t.Fatalf("releaseVersionNumber(%q)=%q want %q", c.tag, got, c.version)
		}
	}
	if cmp, ok := compareVersionStrings("0.8.0", "0.9.0"); !ok || cmp >= 0 {
		t.Fatalf("compare 0.8.0 vs 0.9.0 = %d %v, want less", cmp, ok)
	}
	if got := updateArchiveName("standard", "linux_amd64"); got != "fd0_linux_amd64.tar.gz" {
		t.Fatalf("standard archive=%q", got)
	}
	if got := updateArchiveName("yubikey", "linux_amd64"); got != "fd0_yubikey_linux_amd64.tar.gz" {
		t.Fatalf("yubikey archive=%q", got)
	}
}

func TestRunUpdateHandsDesktopManagedInstallToDesktop(t *testing.T) {
	var out bytes.Buffer
	app := filepath.Join(t.TempDir(), "fd0.app")
	t.Setenv("FD0_DESKTOP_APP", app)
	var launchedPath string
	var launchedArgs []string
	err := RunUpdate(context.Background(), UpdateOptions{
		ManagedByDesktop: true,
		Stdout:           &out,
		Stderr:           ioDiscard{},
		desktopLauncher: func(appPath string, args ...string) error {
			launchedPath = appPath
			launchedArgs = append([]string(nil), args...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v", err)
	}
	if launchedPath != app || len(launchedArgs) != 1 || launchedArgs[0] != "--fd0-desktop-update" {
		t.Fatalf("desktop launch=%q %q", launchedPath, launchedArgs)
	}
	if !strings.Contains(out.String(), "opened fd0 Desktop") || !strings.Contains(out.String(), "app, CLI, and agent") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateRejectsStandaloneOptionsForDesktop(t *testing.T) {
	t.Setenv("FD0_DESKTOP_APP", filepath.Join(t.TempDir(), "fd0.app"))
	for _, test := range []struct {
		name string
		opts UpdateOptions
		flag string
	}{
		{name: "check", opts: UpdateOptions{CheckOnly: true}, flag: "--check"},
		{name: "yes", opts: UpdateOptions{Yes: true}, flag: "--yes"},
		{name: "version", opts: UpdateOptions{Version: "0.12.0"}, flag: "--version"},
		{name: "flavor", opts: UpdateOptions{Flavor: "yubikey"}, flag: "--flavor"},
		{name: "prefix", opts: UpdateOptions{Prefix: "/tmp/fd0"}, flag: "--prefix"},
		{name: "system", opts: UpdateOptions{System: true}, flag: "--system"},
		{name: "downgrade", opts: UpdateOptions{AllowDowngrade: true}, flag: "--allow-downgrade"},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.opts.ManagedByDesktop = true
			test.opts.Stdout = ioDiscard{}
			test.opts.Stderr = ioDiscard{}
			test.opts.desktopLauncher = func(string, ...string) error {
				t.Fatal("unsupported options must not launch fd0 Desktop")
				return nil
			}
			err := RunUpdate(context.Background(), test.opts)
			if err == nil || !strings.Contains(err.Error(), test.flag) {
				t.Fatalf("RunUpdate error=%v, want %s", err, test.flag)
			}
		})
	}
}

func TestRunUpdateCheckUsesLatestClientRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `[
			{"name":"website-v0.0.99","tag_name":"website-v0.0.99","draft":false,"prerelease":false},
			{"name":"client-v0.9.0-rc.1","tag_name":"v0.9.0-rc.1","draft":false,"prerelease":true},
			{"name":"client-v0.8.5","tag_name":"v0.8.5","draft":false,"prerelease":false},
			{"name":"client-v0.9.0","tag_name":"v0.9.0","draft":false,"prerelease":false}
		]`)
	}))
	defer srv.Close()
	var out bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		CheckOnly:      true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		Executable:     filepath.Join(t.TempDir(), "fd0"),
	})
	if !errors.Is(err, ErrUpdateAvailable) {
		t.Fatalf("RunUpdate error=%v, want ErrUpdateAvailable", err)
	}
	if !strings.Contains(out.String(), "fd0 0.9.0 standard is available") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "client-v0.9.0") {
		t.Fatalf("output should show scoped release name:\n%s", out.String())
	}
}

func TestRunUpdateLatestInstallsReleasesWithFreeFormTitles(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	downloads := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	defer downloads.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		fmt.Fprint(w, `[
			{"name":"Desktop 1.2.0 — new window","tag_name":"desktop-v1.2.0","draft":false,"prerelease":false},
			{"name":"CLI 0.9.0 — consistent selection","tag_name":"v0.9.0","draft":false,"prerelease":false},
			{"name":"fd0 CLI 0.8.9","tag_name":"v0.8.9","draft":false,"prerelease":false},
			{"name":"client-v0.8.5","tag_name":"v0.8.5","draft":false,"prerelease":false}
		]`)
	}))
	defer api.Close()
	prefix := t.TempDir()
	var out, stderr bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.5",
		Version:        "latest",
		Prefix:         prefix,
		Yes:            true,
		APIBase:        api.URL,
		ReleaseBase:    downloads.URL,
		HTTPClient:     downloads.Client(),
		Stdout:         &out,
		Stderr:         &stderr,
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), stderr.String())
	}
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0 standard") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateInstallsVerifiedArchive(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	var out, stderr bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "0.9.0",
		Prefix:         prefix,
		Yes:            true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         &stderr,
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), stderr.String())
	}
	for _, name := range []string{"fd0", "fd0-agent"} {
		path := filepath.Join(prefix, name)
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if st.Mode()&0o111 == 0 {
			t.Fatalf("%s is not executable: %v", name, st.Mode())
		}
	}
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0 standard") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdatePreservesYubikeyFlavor(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0 yubikey\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0 yubikey\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	if err := os.WriteFile(filepath.Join(prefix, "fd0"), []byte("#!/bin/sh\necho fd0 0.8.0 yubikey\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_yubikey_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	var out, stderr bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		CurrentFlavor:  "yubikey",
		Version:        "0.9.0",
		Prefix:         prefix,
		Executable:     filepath.Join(prefix, "fd0"),
		Yes:            true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         &stderr,
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "fd0_yubikey_linux_amd64.tar.gz") {
		t.Fatalf("update did not fetch yubikey archive:\n%s", stderr.String())
	}
	if !strings.Contains(out.String(), "updated fd0 to 0.9.0 yubikey") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
}

func TestRunUpdateExplicitFlavorSwitchAtSameVersion(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0 yubikey\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0 yubikey\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	if err := os.WriteFile(filepath.Join(prefix, "fd0"), []byte("#!/bin/sh\necho fd0 0.9.0 standard\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_yubikey_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	var out bytes.Buffer
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.9.0",
		CurrentFlavor:  "standard",
		Version:        "0.9.0",
		Flavor:         "yubikey",
		Prefix:         prefix,
		Executable:     filepath.Join(prefix, "fd0"),
		Yes:            true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         &out,
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err != nil {
		t.Fatalf("RunUpdate: %v\nstdout:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "action:  switch flavor") {
		t.Fatalf("expected switch flavor action:\n%s", out.String())
	}
}

func TestDetectInstalledFD0DoesNotExecuteTarget(t *testing.T) {
	prefix := t.TempDir()
	marker := filepath.Join(t.TempDir(), "executed")
	target := filepath.Join(prefix, "fd0")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n: > \""+marker+"\"\necho fd0 9.9.9 yubikey\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := detectInstalledFD0(prefix, filepath.Join(t.TempDir(), "running-fd0"), "0.8.0", "standard")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Present || got.Version != "" {
		t.Fatalf("detected client = %+v, want present with unknown version", got)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target binary executed before verification: %v", err)
	}
}

func TestRunUpdateRejectsChecksumMismatch(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: strings.Repeat("0", sha256.Size*2)},
	})
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "client-v0.9.0",
		Prefix:         prefix,
		Yes:            true,
		APIBase:        srv.URL,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("RunUpdate error=%v, want sha256 mismatch", err)
	}
}

func TestRunUpdateRequiresPublisherAuthentication(t *testing.T) {
	prefix := t.TempDir()
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "0.9.0",
		Prefix:         prefix,
		Yes:            true,
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     filepath.Join(t.TempDir(), "missing-cosign"),
	})
	if err == nil || !strings.Contains(err.Error(), "cosign is required") {
		t.Fatalf("RunUpdate error=%v, want required cosign error", err)
	}
}

func TestRunUpdateRejectsInvalidPublisherSignature(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "0.8.0",
		Version:        "0.9.0",
		Prefix:         prefix,
		Yes:            true,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, false),
	})
	if err == nil || !strings.Contains(err.Error(), "cosign verification failed") {
		t.Fatalf("RunUpdate error=%v, want cosign verification failure", err)
	}
	if _, statErr := os.Stat(filepath.Join(prefix, "fd0")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unverified fd0 was installed: %v", statErr)
	}
}

func TestRunUpdateRejectsDowngradeWithoutExplicitOverride(t *testing.T) {
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "1.0.0",
		Version:        "0.9.0",
		Prefix:         t.TempDir(),
		Yes:            true,
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-downgrade") {
		t.Fatalf("RunUpdate error=%v, want downgrade refusal", err)
	}
}

func TestRunUpdateRejectsPrereleaseDowngradeWithoutExplicitOverride(t *testing.T) {
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "1.0.0",
		Version:        "0.9.0-rc.1",
		Prefix:         t.TempDir(),
		Yes:            true,
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
	})
	if err == nil || !strings.Contains(err.Error(), "--allow-downgrade") {
		t.Fatalf("RunUpdate error=%v, want prerelease downgrade refusal", err)
	}
}

func TestRunUpdateAllowsExplicitAuthenticatedDowngrade(t *testing.T) {
	archive := makeUpdateArchive(t, map[string]string{
		"fd0":       "#!/bin/sh\necho fd0 0.9.0\n",
		"fd0-agent": "#!/bin/sh\necho fd0-agent 0.9.0\n",
	})
	sum := sha256.Sum256(archive)
	prefix := t.TempDir()
	srv := updateFixtureServer(t, map[string]updateFixtureArchive{
		"fd0_linux_amd64.tar.gz": {Body: archive, Sum: hex.EncodeToString(sum[:])},
	})
	err := RunUpdate(context.Background(), UpdateOptions{
		CurrentVersion: "1.0.0",
		Version:        "0.9.0",
		Prefix:         prefix,
		Yes:            true,
		AllowDowngrade: true,
		ReleaseBase:    srv.URL,
		HTTPClient:     srv.Client(),
		Stdout:         ioDiscard{},
		Stderr:         ioDiscard{},
		GOOS:           "linux",
		GOARCH:         "amd64",
		cosignPath:     fakeCosign(t, true),
	})
	if err != nil {
		t.Fatalf("RunUpdate authenticated downgrade: %v", err)
	}
}

func makeUpdateArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		b := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type updateFixtureArchive struct {
	Body []byte
	Sum  string
}

func updateFixtureServer(t *testing.T, archives map[string]updateFixtureArchive) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/download/v0.9.0/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix)
		if name == "checksums.txt.sigstore.json" {
			_, _ = fmt.Fprint(w, "test fixture")
			return
		}
		if name == "checksums.txt" {
			for archiveName, archive := range archives {
				fmt.Fprintf(w, "%s  %s\n", archive.Sum, archiveName)
			}
			return
		}
		archive, ok := archives[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(archive.Body)
	}))
}

func fakeCosign(t *testing.T, accept bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cosign")
	exit := "1"
	if accept {
		exit = "0"
	}
	body := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" | grep -F -- '--bundle' >/dev/null || exit 8\n" +
		"printf '%s\\n' \"$*\" | grep -F '^https://github\\.com/k2b-dev/fd0\\.sh/\\.github/workflows/release\\.yml@refs/tags/client-v0\\.9\\.0$' >/dev/null || exit 9\n" +
		"exit " + exit + "\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
