package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/secretgrant"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// SecretGrantReq manages grants that keep single values readable while the
// vault is locked (docs/SECRET_GRANTS_PLAN.md). Create needs fresh
// authentication and the digest from prepare; read is the only operation
// that works while locked and returns exactly one granted value.
type SecretGrantReq struct {
	Action         string     `cbor:"action"` // list, prepare, create, revoke, read
	ScopeID        string     `cbor:"scope_id,omitempty"` // scope ID, or a label for read
	Kind           string     `cbor:"kind,omitempty"`
	Name           string     `cbor:"name,omitempty"`
	Field          string     `cbor:"field,omitempty"`
	ExpiresAt      int64      `cbor:"expires_at,omitempty"`
	Digest         string     `cbor:"digest,omitempty"`
	ID             string     `cbor:"id,omitempty"`
	Authentication *UnlockReq `cbor:"authentication,omitempty"`
}

type SecretGrantView struct {
	proto.SecretGrant
	ScopeLabel string `cbor:"scope_label" json:"scopeLabel"`
	Active     bool   `cbor:"active" json:"active"`
}

type SecretGrantResp struct {
	DeviceID string            `cbor:"device_id" json:"deviceId"`
	Digest   string            `cbor:"digest,omitempty" json:"digest,omitempty"`
	Grants   []SecretGrantView `cbor:"grants" json:"grants"`
	Value    []byte            `cbor:"value,omitempty" json:"-"`
}

type activeSecretGrant struct {
	grant      proto.SecretGrant
	scopeLabel string
	value      *crypto.Secret
}

func (s *Server) clearSecretGrantsHeld() {
	for _, g := range s.secretGrants {
		g.value.Destroy()
	}
	s.secretGrants = nil
}

// refreshSecretGrantsHeld rebuilds the released values from the unlocked
// vault, on unlock and after every committed vault write, so a rotation is
// served after the next lock. A deleted, renamed or retyped record, lost
// membership or expiry leaves a grant inactive.
func (s *Server) refreshSecretGrantsHeld(body *proto.VaultBody) {
	s.clearSecretGrantsHeld()
	if s.superPriv == nil || s.deviceID == "" {
		return
	}
	now := time.Now().Unix()
	states := map[string]*chain.ScopeState{}
	defer func() {
		for _, st := range states {
			if st != nil {
				secretgrant.WipeScope(st)
			}
		}
	}()
	for _, g := range body.SecretGrants {
		if g.DeviceID != s.deviceID || g.ExpiresAt <= now {
			continue
		}
		st, seen := states[g.ScopeID]
		if !seen {
			st, _ = secretgrant.ReplayScope(s.paths, body, s.userSuperPub, s.superPriv.Bytes(), g.ScopeID)
			states[g.ScopeID] = st
		}
		if st == nil {
			continue
		}
		value, err := secretgrant.Value(st, g)
		if err != nil {
			continue
		}
		s.secretGrants = append(s.secretGrants, activeSecretGrant{grant: g, scopeLabel: body.Scopes[g.ScopeID].Label, value: crypto.NewSecretCopy(value)})
		crypto.Wipe(value)
	}
}

func (s *Server) handleSecretGrant(ctx context.Context, r *SecretGrantReq) *Response {
	if r == nil {
		return errResp("missing secret grant request")
	}
	if r.Authentication != nil {
		defer crypto.Wipe(r.Authentication.Passphrase)
		defer crypto.Wipe(r.Authentication.YubikeyPIN)
	}
	if r.Action == "create" {
		if r.Authentication == nil {
			return errResp("secret grants require fresh authentication")
		}
		if r.Digest == "" {
			return errResp("review the secret grant before authorizing it")
		}
		s.mu.Lock()
		session := s.unlockSession
		s.mu.Unlock()
		return s.authenticate(ctx, r.Authentication, func(v *proto.VaultFile, res *vault.OpenResult) *Response {
			s.mu.Lock()
			defer s.mu.Unlock()
			if ctx.Err() != nil {
				return errResp("secret grant authentication timed out")
			}
			if s.superPriv == nil || session != s.unlockSession || !bytes.Equal(v.UserSuperPub, s.userSuperPub) {
				return errResp("vault session changed; review the grant again")
			}
			st, err := chain.ReplayUser(s.paths.UserChain)
			if err != nil || verifyLiveAuthMethod(st, v.UserSuperPub, res.Body.SuperPriv, res.UsedWrap, res.UnlockKey) != nil {
				return errResp("authentication method changed; authenticate again")
			}
			body, err := s.cachedBodyHeld()
			if err != nil {
				return errResp(err.Error())
			}
			g, err := s.prepareSecretGrantHeld(body, r)
			if err != nil {
				return errResp(err.Error())
			}
			if secretgrant.Digest(g) != r.Digest {
				return errResp("the value, record or expiry changed; review the grant again")
			}
			keep := body.SecretGrants[:0]
			for _, old := range body.SecretGrants {
				// Granting the same value again replaces the old grant (renewal).
				if old.DeviceID == s.deviceID && old.ScopeID == g.ScopeID && old.RecordID == g.RecordID && old.Field == g.Field {
					continue
				}
				keep = append(keep, old)
			}
			if len(keep) >= secretgrant.MaxGrants {
				return errResp("too many secret grants on this device; revoke unused ones")
			}
			g.ID = "sg_" + rand.Text()
			g.CreatedAt = time.Now().Unix()
			body.SecretGrants = append(keep, g)
			if err := s.saveSSHGrantsHeld(body); err != nil {
				return errResp(err.Error())
			}
			return &Response{SecretGrant: &SecretGrantResp{DeviceID: s.deviceID, Grants: []SecretGrantView{s.viewHeld(g)}}}
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &SecretGrantResp{DeviceID: s.deviceID, Grants: []SecretGrantView{}}
	switch r.Action {
	case "read":
		value, err := s.readGrantHeld(r)
		if err != nil {
			return errResp(err.Error())
		}
		out.Value = value
	case "list":
		if s.superPriv != nil {
			body, err := s.cachedBodyHeld()
			if err != nil {
				return errResp(err.Error())
			}
			for _, g := range body.SecretGrants {
				if g.DeviceID == s.deviceID {
					out.Grants = append(out.Grants, s.viewHeld(g))
				}
			}
		} else {
			// Locked: only what is active is known, as for SSH grants.
			for _, a := range s.secretGrants {
				if a.grant.ExpiresAt > time.Now().Unix() {
					out.Grants = append(out.Grants, SecretGrantView{SecretGrant: a.grant, ScopeLabel: a.scopeLabel, Active: true})
				}
			}
		}
	case "prepare":
		if s.superPriv == nil {
			return errResp("locked")
		}
		body, err := s.cachedBodyHeld()
		if err != nil {
			return errResp(err.Error())
		}
		g, err := s.prepareSecretGrantHeld(body, r)
		if err != nil {
			return errResp(err.Error())
		}
		out.Digest = secretgrant.Digest(g)
		out.Grants = append(out.Grants, s.viewHeld(g))
	case "revoke":
		if s.superPriv == nil {
			return errResp("unlock to remove a saved grant; use fd0 lock --all to stop all active grants immediately")
		}
		body, err := s.cachedBodyHeld()
		if err != nil {
			return errResp(err.Error())
		}
		found := false
		keep := body.SecretGrants[:0]
		for _, g := range body.SecretGrants {
			if g.ID == r.ID && g.DeviceID == s.deviceID {
				found = true
				continue
			}
			keep = append(keep, g)
		}
		if !found {
			return errResp("secret grant not found on this device")
		}
		body.SecretGrants = keep
		if err := s.saveSSHGrantsHeld(body); err != nil {
			return errResp(err.Error())
		}
	default:
		return errResp("unknown secret grant action")
	}
	return &Response{SecretGrant: out}
}

func (s *Server) prepareSecretGrantHeld(body *proto.VaultBody, r *SecretGrantReq) (proto.SecretGrant, error) {
	var zero proto.SecretGrant
	now := time.Now()
	if r.ExpiresAt <= now.Unix() || r.ExpiresAt > now.Add(secretgrant.MaxTTL+time.Hour).Unix() {
		return zero, errors.New("grant expiry must be in the future and at most 365 days away")
	}
	st, err := secretgrant.ReplayScope(s.paths, body, s.userSuperPub, s.superPriv.Bytes(), r.ScopeID)
	if err != nil {
		return zero, err
	}
	defer secretgrant.WipeScope(st)
	recordID, fieldType, err := secretgrant.Find(st, r.Kind, r.Name, r.Field)
	if err != nil {
		return zero, err
	}
	return proto.SecretGrant{DeviceID: s.deviceID, ScopeID: r.ScopeID, RecordID: recordID, Kind: r.Kind,
		Name: r.Name, Field: r.Field, FieldType: fieldType, ExpiresAt: r.ExpiresAt}, nil
}

func (s *Server) viewHeld(g proto.SecretGrant) SecretGrantView {
	v := SecretGrantView{SecretGrant: g}
	for _, a := range s.secretGrants {
		if a.grant.ID == g.ID && g.ID != "" && g.ExpiresAt > time.Now().Unix() {
			v.Active, v.ScopeLabel = true, a.scopeLabel
		}
	}
	if body, err := s.cachedBodyHeld(); err == nil && v.ScopeLabel == "" {
		v.ScopeLabel = body.Scopes[g.ScopeID].Label
	}
	return v
}

// readGrantHeld returns one active, unexpired granted value. The scope must
// match the grant's scope ID or its label exactly; names never prefix-match.
func (s *Server) readGrantHeld(r *SecretGrantReq) ([]byte, error) {
	now := time.Now().Unix()
	var hit *activeSecretGrant
	for i := range s.secretGrants {
		a := &s.secretGrants[i]
		if a.grant.Kind != r.Kind || a.grant.Name != r.Name || a.grant.Field != r.Field || a.grant.ExpiresAt <= now {
			continue
		}
		if r.ScopeID != "" && r.ScopeID != a.grant.ScopeID && r.ScopeID != a.scopeLabel {
			continue
		}
		if hit != nil {
			return nil, errors.New("several grants match; pass the scope ID")
		}
		hit = a
	}
	if hit == nil {
		return nil, errors.New("locked")
	}
	return append([]byte(nil), hit.value.Bytes()...), nil
}

// SecretGrant sends a secret grant request to the agent.
func (c *Client) SecretGrant(r SecretGrantReq) (*SecretGrantResp, error) {
	status, err := c.Status()
	if err != nil {
		return nil, err
	}
	if !status.SecretGrantsSupported {
		return nil, errors.New("the running fd0 service does not support secret grants; restart it after updating fd0")
	}
	resp, err := c.doWithTimeout(&Request{Op: OpSecretGrant, SecretGrant: &r}, agentUnlockClientTimeout)
	if err != nil {
		return nil, err
	}
	if resp.SecretGrant == nil {
		return nil, errors.New("agent returned no secret grant result")
	}
	return resp.SecretGrant, nil
}

func (s *Server) activeSecretGrantCountHeld() int {
	n, now := 0, time.Now().Unix()
	for _, a := range s.secretGrants {
		if a.grant.ExpiresAt > now {
			n++
		}
	}
	return n
}
