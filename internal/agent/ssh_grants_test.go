package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
)

func TestSSHGrantSurvivesExpiryButLockAllWipesIt(t *testing.T) {
	for _, expiration := range []string{"idle", "maximum"} {
		t.Run(expiration, func(t *testing.T) {
			s := newLifecycleTestServer(t, time.Hour, time.Hour)
			key, _ := sshkey.NewEd25519("test", "")
			secret := crypto.NewSecretCopy(key.Private)
			h := sshhost.Host{Alias: "host", Hostname: "host.test", User: "admin", KeyName: "test"}
			raw, _ := json.Marshal(h.Marshal())
			s.sshGrants = []activeSSHGrant{{grant: proto.SSHGrant{HostJSON: raw, HostKeys: [][]byte{[]byte("host-key")}}, keyType: key.Type, public: key.Public, private: secret}}
			if expiration == "idle" {
				s.lastActivity = time.Now().Add(-2 * time.Hour)
			} else {
				s.unlockedAt = time.Now().Add(-2 * time.Hour)
			}
			p := &liveSSHProvider{ctx: context.Background(), server: s, fetcher: func(context.Context) ([]sshagent.KeyEntry, error) {
				t.Fatal("locked grant fetched vault keys")
				return nil, nil
			}}
			var borrowed []byte
			err := p.WithKeys(func(keys []sshagent.KeyEntry) error {
				if len(keys) != 1 || len(keys[0].Destinations) != 1 {
					t.Fatal("expiry dropped grant or its restriction")
				}
				borrowed = keys[0].Key.Private
				if !bytes.Equal(borrowed, key.Private) {
					t.Fatal("wrong retained key")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("borrowed signing copy was not wiped")
			}
			if s.superPriv != nil || s.payloadKey != nil || s.x25519Priv != nil {
				t.Fatal("grant kept vault secrets alive")
			}
			if resp := s.dispatch(context.Background(), &Request{Op: OpLockAll}); resp.Err != "" {
				t.Fatal(resp.Err)
			}
			if secret.Len() != 0 {
				t.Fatal("lock-all did not destroy retained secret")
			}
			if err := p.WithKeys(func(keys []sshagent.KeyEntry) error {
				if len(keys) != 0 {
					t.Fatal("grant survived lock-all")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
