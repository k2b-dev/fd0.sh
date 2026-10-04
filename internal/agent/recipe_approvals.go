package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"regexp"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// RecipeApprovalReq lists, creates or revokes this device's approvals to run
// deploy recipes (docs/SERVICES_PLAN.md, phase 3). Create needs fresh
// authentication; the approval pins the reviewed recipe digest. Approving
// grants no locked access: recipes still run only with an unlocked vault.
type RecipeApprovalReq struct {
	Action         string     `cbor:"action"` // list, create, revoke
	ScopeID        string     `cbor:"scope_id,omitempty"`
	Name           string     `cbor:"name,omitempty"` // SERVICE/NAME
	Digest         string     `cbor:"digest,omitempty"`
	Authentication *UnlockReq `cbor:"authentication,omitempty"`
}

type RecipeApprovalResp struct {
	DeviceID  string                 `cbor:"device_id" json:"deviceId"`
	Approvals []proto.RecipeApproval `cbor:"approvals" json:"approvals"`
}

const maxRecipeApprovals = 512

var recipeDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Server) handleRecipeApproval(ctx context.Context, r *RecipeApprovalReq) *Response {
	if r == nil {
		return errResp("missing recipe approval request")
	}
	if r.Authentication != nil {
		defer crypto.Wipe(r.Authentication.Passphrase)
		defer crypto.Wipe(r.Authentication.YubikeyPIN)
	}
	if r.Action == "create" {
		if r.Authentication == nil {
			return errResp("approving a recipe requires fresh authentication")
		}
		if r.ScopeID == "" || r.Name == "" || !recipeDigestRE.MatchString(r.Digest) {
			return errResp("review the recipe before approving it")
		}
		s.mu.Lock()
		session := s.unlockSession
		s.mu.Unlock()
		// Authenticate independently; approving never creates or reuses a
		// general unlock session.
		return s.authenticate(ctx, r.Authentication, func(v *proto.VaultFile, res *vault.OpenResult) *Response {
			s.mu.Lock()
			defer s.mu.Unlock()
			if ctx.Err() != nil {
				return errResp("recipe approval authentication timed out")
			}
			if s.superPriv == nil || session != s.unlockSession || !bytes.Equal(v.UserSuperPub, s.userSuperPub) {
				return errResp("vault session changed; review the recipe again")
			}
			st, err := chain.ReplayUser(s.paths.UserChain)
			if err != nil || verifyLiveAuthMethod(st, v.UserSuperPub, res.Body.SuperPriv, res.UsedWrap, res.UnlockKey) != nil {
				return errResp("authentication method changed; authenticate again")
			}
			body, err := s.cachedBodyHeld()
			if err != nil {
				return errResp(err.Error())
			}
			keep := body.RecipeApprovals[:0]
			for _, a := range body.RecipeApprovals {
				// Approving a changed recipe replaces the old approval.
				if a.DeviceID == s.deviceID && a.ScopeID == r.ScopeID && a.Name == r.Name {
					continue
				}
				keep = append(keep, a)
			}
			if len(keep) >= maxRecipeApprovals {
				return errResp("too many recipe approvals on this device; revoke unused ones")
			}
			a := proto.RecipeApproval{ID: "ra_" + rand.Text(), DeviceID: s.deviceID, ScopeID: r.ScopeID,
				Name: r.Name, Digest: r.Digest, ApprovedAt: time.Now().Unix()}
			body.RecipeApprovals = append(keep, a)
			if err := s.saveSSHGrantsHeld(body); err != nil {
				return errResp(err.Error())
			}
			return &Response{RecipeApproval: &RecipeApprovalResp{DeviceID: s.deviceID, Approvals: []proto.RecipeApproval{a}}}
		})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	body, err := s.cachedBodyHeld()
	if err != nil {
		return errResp(err.Error())
	}
	out := &RecipeApprovalResp{DeviceID: s.deviceID, Approvals: []proto.RecipeApproval{}}
	switch r.Action {
	case "list":
		for _, a := range body.RecipeApprovals {
			if a.DeviceID == s.deviceID {
				out.Approvals = append(out.Approvals, a)
			}
		}
	case "revoke":
		found := false
		keep := body.RecipeApprovals[:0]
		for _, a := range body.RecipeApprovals {
			if a.DeviceID == s.deviceID && a.ScopeID == r.ScopeID && a.Name == r.Name {
				found = true
				continue
			}
			keep = append(keep, a)
		}
		if !found {
			return errResp("recipe is not approved on this device")
		}
		body.RecipeApprovals = keep
		if err := s.saveSSHGrantsHeld(body); err != nil {
			return errResp(err.Error())
		}
	default:
		return errResp("unknown recipe approval action")
	}
	return &Response{RecipeApproval: out}
}

func (s *Server) cachedBodyHeld() (*proto.VaultBody, error) {
	var body proto.VaultBody
	if err := proto.Unmarshal(s.redactedBody, &body); err != nil {
		return nil, errors.New("invalid cached vault")
	}
	return &body, nil
}

// RecipeApproval sends a recipe approval request to the agent.
func (c *Client) RecipeApproval(r RecipeApprovalReq) (*RecipeApprovalResp, error) {
	status, err := c.Status()
	if err != nil {
		return nil, err
	}
	if !status.RecipesSupported {
		return nil, errors.New("the running fd0 service does not support deploy recipes; restart it after updating fd0")
	}
	resp, err := c.doWithTimeout(&Request{Op: OpRecipeApproval, RecipeApproval: &r}, agentUnlockClientTimeout)
	if err != nil {
		return nil, err
	}
	if resp.RecipeApproval == nil {
		return nil, errors.New("agent returned no recipe approval result")
	}
	return resp.RecipeApproval, nil
}
