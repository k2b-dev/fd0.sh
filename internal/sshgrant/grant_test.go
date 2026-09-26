package sshgrant

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestKnownHostKeysRequireExistingTrust(t *testing.T) {
	key, _ := sshkey.NewEd25519("server", "")
	pub, _ := key.PublicKey()
	path := filepath.Join(t.TempDir(), "known_hosts")
	host := &sshhost.Host{Alias: "test", Hostname: "example.test", Port: 2222}
	name := "[example.test]:2222"
	for _, tc := range []struct {
		name, line string
		allowed    bool
	}{
		{"known", knownhosts.Line([]string{name}, pub), true},
		{"hashed", knownhosts.Line([]string{knownhosts.HashHostname(name)}, pub), true},
		{"unknown", knownhosts.Line([]string{"other.test"}, pub), false},
		{"revoked", "@revoked " + knownhosts.Line([]string{name}, pub), false},
		{"CA", "@cert-authority " + knownhosts.Line([]string{name}, pub), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			os.WriteFile(path, []byte(tc.line+"\n"), 0600)
			keys, err := KnownHostKeys(host, path)
			if tc.allowed {
				if err != nil || len(keys) != 1 {
					t.Fatal(keys, err)
				}
			} else if err == nil {
				t.Fatal("untrusted host accepted")
			}
		})
	}
}
