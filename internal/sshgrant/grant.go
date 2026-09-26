// Package sshgrant resolves personal SSH approvals against verified vault data.
package sshgrant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func Digest(g proto.SSHGrant) string {
	g.ID = ""
	b, _ := proto.Marshal(g)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Host(g proto.SSHGrant) (*sshhost.Host, error) {
	var j sshhost.JSON
	if err := json.Unmarshal(g.HostJSON, &j); err != nil {
		return nil, err
	}
	h, err := sshhost.Unmarshal(j)
	if err != nil {
		return nil, err
	}
	h.Scope = g.ScopeID
	return h, h.Validate()
}

// Resolve reads the canonical scope chain. Grants never keep OEKs or a vault
// decryption key alive. A missing/archived/replaced record invalidates a grant.
func Resolve(paths fdhome.Paths, body *proto.VaultBody, pub, priv []byte, scope, alias string) (proto.SSHGrant, *sshkey.Key, error) {
	var zero proto.SSHGrant
	id, err := proto.ParseScopeID(scope)
	if err != nil {
		return zero, nil, err
	}
	sd, ok := body.Scopes[scope]
	if !ok || sd.Leaving {
		return zero, nil, errors.New("scope unavailable")
	}
	xPriv, err := crypto.EdPrivToX25519(priv)
	if err != nil {
		return zero, nil, err
	}
	defer crypto.Wipe(xPriv)
	xPub, err := crypto.EdPubToX25519(pub)
	if err != nil {
		return zero, nil, err
	}
	events, err := chain.ReadScopeEventsReadOnly(paths.ScopeChain(id))
	if err != nil {
		return zero, nil, err
	}
	st, err := chain.ReplayScopeEvents(events, pub, xPub, chain.LocalOpener{Pub: xPub, Priv: xPriv}, nil)
	if err != nil {
		return zero, nil, err
	}
	if st == nil {
		return zero, nil, errors.New("scope chain is missing")
	}
	defer func() {
		for _, key := range st.OEKs {
			crypto.Wipe(key)
		}
	}()
	if st.Left {
		return zero, nil, errors.New("scope membership removed")
	}
	if mm := chain.CompareScopeTip(scope, sd.ChainTip, st); mm != nil && mm.Direction != "ahead" {
		return zero, nil, errors.New("scope rollback detected")
	}
	var hostID string
	var h *sshhost.Host
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || cur.Record.Name != "host:"+alias || cur.Record.Type != sshhost.TypeHost {
			continue
		}
		if h != nil {
			return zero, nil, errors.New("ambiguous host")
		}
		var j sshhost.JSON
		if err := decode(cur.Record.Payload, &j); err != nil {
			return zero, nil, err
		}
		h, err = sshhost.Unmarshal(j)
		if err != nil {
			return zero, nil, err
		}
		hostID = id
	}
	if h == nil {
		return zero, nil, errors.New("host unavailable")
	}
	if err := h.Validate(); err != nil {
		return zero, nil, err
	}
	if h.Alias != alias || h.KeyName == "" || h.User == "" {
		return zero, nil, errors.New("SSH grants require an explicit host alias, user and fd0 key")
	}
	// Metadata edits do not change the approved destination.
	h.Tags = nil
	h.Description = ""
	hostJSON, err := json.Marshal(h.Marshal())
	if err != nil {
		return zero, nil, err
	}
	var key *sshkey.Key
	var keyID string
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || cur.Record.Name != "ssh:"+h.KeyName {
			continue
		}
		if key != nil {
			crypto.Wipe(key.Private)
			return zero, nil, errors.New("ambiguous key")
		}
		var j sshkey.JSON
		if err := decode(cur.Record.Payload, &j); err != nil {
			return zero, nil, err
		}
		key, err = sshkey.Unmarshal(j)
		if err != nil {
			return zero, nil, err
		}
		if cur.Record.Type != string(key.Type) {
			crypto.Wipe(key.Private)
			return zero, nil, errors.New("record is no longer an SSH key")
		}
		keyID = id
	}
	if key == nil {
		return zero, nil, errors.New("SSH key unavailable")
	}
	keyPub, err := key.PublicKey()
	if err != nil {
		crypto.Wipe(key.Private)
		return zero, nil, err
	}
	return proto.SSHGrant{ScopeID: scope, Name: alias, HostID: hostID, KeyID: keyID, HostJSON: hostJSON, KeyPublic: keyPub.Marshal()}, key, nil
}

func Matches(g, current proto.SSHGrant) bool {
	return g.ScopeID == current.ScopeID && g.Name == current.Name && g.HostID == current.HostID && g.KeyID == current.KeyID && bytes.Equal(g.HostJSON, current.HostJSON) && bytes.Equal(g.KeyPublic, current.KeyPublic)
}

func decode(v any, out any) error {
	var b []byte
	var err error
	switch p := v.(type) {
	case string:
		b = []byte(p)
	case []byte:
		b = p
	default:
		b, err = json.Marshal(v)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// KnownHostKeys uses already-trusted known_hosts entries, including hashed
// names. It never scans the network or accepts a new host key implicitly.
func KnownHostKeys(h *sshhost.Host, path string) ([][]byte, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}
	port := h.Port
	if port == 0 {
		port = 22
	}
	address := net.JoinHostPort(h.Hostname, strconv.Itoa(port))
	probe, err := sshkey.NewEd25519("probe", "")
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(probe.Private)
	probePub, _ := probe.PublicKey()
	err = cb(address, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, probePub)
	var mismatch *knownhosts.KeyError
	if !errors.As(err, &mismatch) || len(mismatch.Want) == 0 {
		return nil, errors.New("no trusted host key: connect to this host and verify its fingerprint first")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(contents), "\n")
	var keys [][]byte
	for _, want := range mismatch.Want {
		// knownhosts' raw-key fallback includes certificate authorities. They are
		// trust roots, not the server identities this grant promises to constrain.
		if want.Line < 1 || want.Line > len(lines) || strings.HasPrefix(strings.TrimSpace(lines[want.Line-1]), "@") {
			continue
		}
		if _, cert := want.Key.(*ssh.Certificate); cert {
			continue
		}
		// Check each key with the callback to reject revoked keys and CA-only entries.
		if cb(address, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}, want.Key) != nil {
			continue
		}
		duplicate := false
		for _, k := range keys {
			if bytes.Equal(k, want.Key.Marshal()) {
				duplicate = true
			}
		}
		if !duplicate {
			keys = append(keys, want.Key.Marshal())
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted raw host key available; host certificates are not supported for locked SSH grants")
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys, nil
}
