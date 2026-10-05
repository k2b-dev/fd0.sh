package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/sshagent"
	"github.com/valentinkolb/fd0.sh/internal/sshgrant"
	"github.com/valentinkolb/fd0.sh/internal/sshkey"
	"github.com/valentinkolb/fd0.sh/internal/vault"
	"golang.org/x/crypto/ssh"
)

// Authentication is used only by create, with no reusable authorization token.
type SSHGrantReq struct {
	Action         string     `cbor:"action"`
	ScopeID        string     `cbor:"scope_id,omitempty"`
	Name           string     `cbor:"name,omitempty"`
	KnownHosts     string     `cbor:"known_hosts,omitempty"`
	Digest         string     `cbor:"digest,omitempty"`
	ID             string     `cbor:"id,omitempty"`
	Authentication *UnlockReq `cbor:"authentication,omitempty"`
}

type SSHGrantView struct {
	ID               string   `cbor:"id" json:"id"`
	ScopeID          string   `cbor:"scope_id" json:"scopeId"`
	Name             string   `cbor:"name" json:"name"`
	Hostname         string   `cbor:"hostname" json:"hostname"`
	User             string   `cbor:"user" json:"user"`
	Port             int      `cbor:"port" json:"port"`
	Jump             string   `cbor:"jump,omitempty" json:"jump,omitempty"`
	Fingerprint      string   `cbor:"fingerprint" json:"fingerprint"`
	HostFingerprints []string `cbor:"host_fingerprints" json:"hostFingerprints"`
	Active           bool     `cbor:"active" json:"active"`
}

type SSHGrantResp struct {
	Grants   []SSHGrantView `cbor:"grants" json:"grants"`
	Digest   string         `cbor:"digest,omitempty" json:"digest,omitempty"`
	DeviceID string         `cbor:"device_id" json:"deviceId"`
}

type activeSSHGrant struct {
	grant   proto.SSHGrant
	keyType sshkey.Type
	public  []byte
	private *crypto.Secret
}

func (s *Server) clearSSHGrantsHeld() {
	for _, g := range s.sshGrants {
		g.private.Destroy()
	}
	s.sshGrants = nil
	// Secret grants share every lifecycle point with SSH grants.
	s.clearSecretGrantsHeld()
}

// Rebuild on unlock and every committed vault write: key rotation, deletion,
// changed connection settings or lost membership disable an old approval.
func (s *Server) refreshSSHGrantsHeld(body *proto.VaultBody) {
	s.clearSSHGrantsHeld()
	defer s.refreshSecretGrantsHeld(body)
	if s.superPriv == nil || s.deviceID == "" {
		return
	}
	for _, g := range body.SSHGrants {
		if g.DeviceID != s.deviceID {
			continue
		}
		current, key, err := sshgrant.Resolve(s.paths, body, s.userSuperPub, s.superPriv.Bytes(), g.ScopeID, g.Name)
		if err != nil {
			continue
		}
		if sshgrant.Matches(g, current) && len(g.HostKeys) > 0 {
			s.sshGrants = append(s.sshGrants, activeSSHGrant{grant: g, keyType: key.Type, public: append([]byte(nil), key.Public...), private: crypto.NewSecretCopy(key.Private)})
		}
		crypto.Wipe(key.Private)
	}
}

// Only called while holding s.mu, including throughout the signing callback.
func (s *Server) withGrantedSSHKeysHeld(use func([]sshagent.KeyEntry) error) error {
	entries := make([]sshagent.KeyEntry, 0, len(s.sshGrants))
	defer func() {
		for _, e := range entries {
			crypto.Wipe(e.Key.Private)
		}
	}()
	for _, g := range s.sshGrants {
		h, err := sshgrant.Host(g.grant)
		if err != nil {
			continue
		}
		entries = append(entries, sshagent.KeyEntry{
			Key:          &sshkey.Key{Type: g.keyType, Public: g.public, Private: append([]byte(nil), g.private.Bytes()...)},
			Comment:      "fd0 grant: " + g.grant.Name,
			Destinations: []sshagent.Destination{{User: h.User, HostKeys: g.grant.HostKeys}},
		})
	}
	return use(entries)
}

func grantView(g proto.SSHGrant, active bool) SSHGrantView {
	v := SSHGrantView{ID: g.ID, ScopeID: g.ScopeID, Name: g.Name, Active: active, HostFingerprints: []string{}}
	if h, err := sshgrant.Host(g); err == nil {
		v.Hostname = h.Hostname
		v.User = h.User
		v.Port = h.Port
		v.Jump = h.ProxyJump
	}
	if pub, err := ssh.ParsePublicKey(g.KeyPublic); err == nil {
		v.Fingerprint = ssh.FingerprintSHA256(pub)
	}
	for _, b := range g.HostKeys {
		if pub, err := ssh.ParsePublicKey(b); err == nil {
			v.HostFingerprints = append(v.HostFingerprints, ssh.FingerprintSHA256(pub))
		}
	}
	return v
}

func (s *Server) prepareSSHGrantHeld(r *SSHGrantReq) (proto.SSHGrant, error) {
	var body proto.VaultBody
	s.expireUnlockedHeld(time.Now())
	if s.superPriv == nil {
		return proto.SSHGrant{}, errors.New("unlock the vault before managing SSH grants")
	}
	if err := proto.Unmarshal(s.redactedBody, &body); err != nil {
		return proto.SSHGrant{}, err
	}
	g, key, err := sshgrant.Resolve(s.paths, &body, s.userSuperPub, s.superPriv.Bytes(), r.ScopeID, r.Name)
	if err != nil {
		return g, err
	}
	defer crypto.Wipe(key.Private)
	g.DeviceID = s.deviceID
	h, err := sshgrant.Host(g)
	if err != nil {
		return g, err
	}
	g.HostKeys, err = sshgrant.KnownHostKeys(h, r.KnownHosts)
	return g, err
}

func (s *Server) handleSSHGrant(ctx context.Context, r *SSHGrantReq) *Response {
	if r == nil {
		return errResp("missing SSH grant request")
	}
	if r.Authentication != nil {
		defer crypto.Wipe(r.Authentication.Passphrase)
		defer crypto.Wipe(r.Authentication.YubikeyPIN)
	}
	if r.Action == "create" {
		if r.Authentication == nil {
			return errResp("SSH grants require fresh authentication for this command")
		}
		if r.Digest == "" {
			return errResp("review the SSH grant before authorizing it")
		}
		s.mu.Lock()
		session := s.unlockSession
		s.mu.Unlock()
		// Authenticate independently; never reuse unlockKey or create a general
		// unlock session as a side effect of approving a grant.
		return s.authenticate(ctx, r.Authentication, func(v *proto.VaultFile, res *vault.OpenResult) *Response {
			s.mu.Lock()
			defer s.mu.Unlock()
			if ctx.Err() != nil {
				return errResp("SSH grant authentication timed out")
			}
			if s.superPriv == nil || session != s.unlockSession || !bytes.Equal(v.UserSuperPub, s.userSuperPub) {
				return errResp("vault session changed; review the grant again")
			}
			st, err := chain.ReplayUser(s.paths.UserChain)
			if err != nil || verifyLiveAuthMethod(st, v.UserSuperPub, res.Body.SuperPriv, res.UsedWrap, res.UnlockKey) != nil {
				return errResp("authentication method changed; authenticate again")
			}
			g, err := s.prepareSSHGrantHeld(r)
			if err != nil {
				return errResp(err.Error())
			}
			if sshgrant.Digest(g) != r.Digest {
				return errResp("host, key or device changed; review the grant again")
			}
			var body proto.VaultBody
			if err := proto.Unmarshal(s.redactedBody, &body); err != nil {
				return errResp("invalid cached vault")
			}
			for _, old := range body.SSHGrants {
				if old.DeviceID == s.deviceID && old.ScopeID == g.ScopeID && old.Name == g.Name {
					return errResp("revoke the existing SSH grant before replacing it")
				}
			}
			if len(body.SSHGrants) >= 256 {
				return errResp("too many SSH grants")
			}
			g.ID = rand.Text()
			body.SSHGrants = append(body.SSHGrants, g)
			if err := s.saveSSHGrantsHeld(&body); err != nil {
				return errResp(err.Error())
			}
			active := false
			for _, a := range s.sshGrants {
				if a.grant.ID == g.ID {
					active = true
				}
			}
			return &Response{SSHGrant: &SSHGrantResp{DeviceID: s.deviceID, Grants: []SSHGrantView{grantView(g, active)}}}
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &SSHGrantResp{DeviceID: s.deviceID, Grants: []SSHGrantView{}}
	switch r.Action {
	case "prepare":
		g, err := s.prepareSSHGrantHeld(r)
		if err != nil {
			return errResp(err.Error())
		}
		out.Digest = sshgrant.Digest(g)
		out.Grants = append(out.Grants, grantView(g, false))
	case "list":
		if s.superPriv != nil {
			var body proto.VaultBody
			if err := proto.Unmarshal(s.redactedBody, &body); err != nil {
				return errResp("invalid cached vault")
			}
			for _, g := range body.SSHGrants {
				if g.DeviceID == s.deviceID {
					active := false
					for _, a := range s.sshGrants {
						if a.grant.ID == g.ID {
							active = true
						}
					}
					out.Grants = append(out.Grants, grantView(g, active))
				}
			}
		} else {
			for _, g := range s.sshGrants {
				out.Grants = append(out.Grants, grantView(g.grant, true))
			}
		}
	case "revoke":
		if s.superPriv == nil {
			return errResp("unlock to remove a saved grant; use fd0 lock --all to stop all active grants immediately")
		}
		var body proto.VaultBody
		if err := proto.Unmarshal(s.redactedBody, &body); err != nil {
			return errResp("invalid cached vault")
		}
		found := false
		keep := body.SSHGrants[:0]
		for _, g := range body.SSHGrants {
			if g.ID == r.ID && g.DeviceID == s.deviceID {
				found = true
				continue
			}
			keep = append(keep, g)
		}
		if !found {
			return errResp("SSH grant not found on this device")
		}
		body.SSHGrants = keep
		if err := s.saveSSHGrantsHeld(&body); err != nil {
			return errResp(err.Error())
		}
	default:
		return errResp("unknown SSH grant action")
	}
	return &Response{SSHGrant: out}
}

func (s *Server) saveSSHGrantsHeld(body *proto.VaultBody) error {
	body.SuperPriv = append([]byte(nil), s.superPriv.Bytes()...)
	defer crypto.Wipe(body.SuperPriv)
	redacted := *body
	redacted.SuperPriv = make([]byte, len(body.SuperPriv))
	rb, err := proto.Marshal(redacted)
	if err != nil {
		return err
	}
	if err := vault.SaveBody(s.paths.Vault, s.userSuperPub, body, s.payloadKey.Bytes()); err != nil {
		crypto.Wipe(rb)
		return fmt.Errorf("save SSH grants: %w", err)
	}
	crypto.Wipe(s.redactedBody)
	s.redactedBody = rb
	s.sshRevision++
	s.refreshSSHGrantsHeld(body)
	return nil
}

func (c *Client) SSHGrant(r SSHGrantReq) (*SSHGrantResp, error) {
	status, err := c.Status()
	if err != nil {
		return nil, err
	}
	if !status.SSHGrantsSupported {
		return nil, errors.New("the running fd0 service does not support SSH grants; update and restart it when ready")
	}
	resp, err := c.doWithTimeout(&Request{Op: OpSSHGrant, SSHGrant: &r}, agentUnlockClientTimeout)
	if err != nil {
		return nil, err
	}
	if resp.SSHGrant == nil {
		return nil, errors.New("agent does not support SSH grants; update the local service")
	}
	return resp.SSHGrant, nil
}
func (c *Client) LockAll() error { _, err := c.do(&Request{Op: OpLockAll}); return err }
