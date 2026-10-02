package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// requireValueWrite refuses to sign a secret.set the scope's role rules
// would reject, so a reader never appends an event every other client drops.
func (s *Session) requireValueWrite(scopeID string, st *chain.ScopeState) error {
	switch role := st.Roles.RoleOf(s.UserSuperPub); role {
	case proto.RoleAdmin, proto.RoleWriter:
		return nil
	default:
		return fmt.Errorf("your role in %s is %s: you can read values but not change them", scopeName(s, scopeID), role)
	}
}

// requireAdmin refuses membership and role changes for non-admins.
func (s *Session) requireAdmin(scopeID string, st *chain.ScopeState) error {
	if role := st.Roles.RoleOf(s.UserSuperPub); role != proto.RoleAdmin {
		return fmt.Errorf("your role in %s is %s: only admins can change membership", scopeName(s, scopeID), role)
	}
	return nil
}

// requireScopeRolesSupport refuses to author role events unless the primary
// server advertises scope roles, so a user cannot lock a scope on a server
// that would reject its events. It is a usability guard, not authorization.
func (s *Session) requireScopeRolesSupport(ctx context.Context) error {
	server, err := ResolvePrimary("")
	if err != nil {
		return err
	}
	u, err := canon.ParseURL(server)
	if err != nil {
		return fmt.Errorf("server URL: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String()+"/v1/capabilities", nil)
	if err != nil {
		return err
	}
	resp, err := syncHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("check server support for scope roles: %w", err)
	}
	defer resp.Body.Close()
	var caps struct {
		ScopeRoles bool `json:"scopeRoles"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&caps) != nil || !caps.ScopeRoles {
		return fmt.Errorf("server %s does not support scope roles yet; update fd0-server before assigning writer or reader roles", u.String())
	}
	return nil
}
