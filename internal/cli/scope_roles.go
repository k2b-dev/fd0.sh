package cli

import (
	"fmt"

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
