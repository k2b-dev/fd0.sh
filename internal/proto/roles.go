package proto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// ScopeRoles maps hex(member super_pub) to a role. A member without an entry
// is an admin, which is how every scope behaved before roles existed.
type ScopeRoles map[string]string

// ValidRole reports whether role is one of the three member roles.
func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleWriter || role == RoleReader
}

// RoleOf returns member's role. Callers check membership separately.
func (r ScopeRoles) RoleOf(member []byte) string {
	if role, ok := r[hex.EncodeToString(member)]; ok {
		return role
	}
	return RoleAdmin
}

// AuthorizeScopeEvent applies the role rules of docs/SCOPE_ROLES_PLAN.md to
// a non-genesis scope event, given the membership and roles before it. It is
// the single implementation shared by the server validator and client replay.
// It checks authorization and payload role shape only; envelope rules (seq,
// prev_hash, OEK versions, key deliveries) stay with the callers.
func AuthorizeScopeEvent(sp *SignedPrefix, members [][]byte, roles ScopeRoles) error {
	if !containsKey(members, sp.Author) {
		return errors.New("scope: author not in auth_list")
	}
	author := roles.RoleOf(sp.Author)
	switch sp.Kind {
	case KindSecretSet:
		if sp.Payload.Role != "" {
			return errors.New("secret.set: role must be empty")
		}
		if author != RoleAdmin && author != RoleWriter {
			return fmt.Errorf("secret.set: author role %q may not write values", author)
		}
		return nil
	case KindMemberChange:
		if author != RoleAdmin {
			return fmt.Errorf("member.change: author role %q may not change membership", author)
		}
		switch sp.Payload.Op {
		case OpAdd:
			if sp.Payload.Role != "" && !ValidRole(sp.Payload.Role) {
				return fmt.Errorf("member.change add: invalid role %q", sp.Payload.Role)
			}
		case OpRemove:
			if sp.Payload.Role != "" {
				return errors.New("member.change remove: role must be empty")
			}
		case OpRole:
			if !ValidRole(sp.Payload.Role) {
				return fmt.Errorf("member.change role: invalid role %q", sp.Payload.Role)
			}
			if !containsKey(members, sp.Payload.Member) {
				return errors.New("member.change role: target is not a member")
			}
			if roles.RoleOf(sp.Payload.Member) == sp.Payload.Role {
				return errors.New("member.change role: role is unchanged")
			}
		default:
			return fmt.Errorf("member.change: bad op %q", sp.Payload.Op)
		}
		return nil
	default:
		return fmt.Errorf("scope: bad kind %q", sp.Kind)
	}
}

// GenesisRole checks the role carried by a scope's genesis event.
func GenesisRole(sp *SignedPrefix) error {
	if sp.Payload.Role != "" && sp.Payload.Role != RoleAdmin {
		return fmt.Errorf("genesis: author must be admin, got role %q", sp.Payload.Role)
	}
	return nil
}

// NextScopeRoles returns the roles after an authorized member.change and
// enforces that a non-empty scope keeps at least one admin. post is the
// member set after the event. Legacy admin entries stay implicit, so scopes
// that never use roles keep an empty map.
func NextScopeRoles(roles ScopeRoles, post [][]byte, sp *SignedPrefix) (ScopeRoles, error) {
	next := ScopeRoles{}
	for k, v := range roles {
		next[k] = v
	}
	key := hex.EncodeToString(sp.Payload.Member)
	switch sp.Payload.Op {
	case OpAdd, OpRole:
		if sp.Payload.Role == "" || sp.Payload.Role == RoleAdmin {
			delete(next, key)
		} else {
			next[key] = sp.Payload.Role
		}
	case OpRemove:
		delete(next, key)
	}
	if len(post) > 0 {
		hasAdmin := false
		for _, m := range post {
			if next.RoleOf(m) == RoleAdmin {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			return nil, errors.New("member.change: the scope would have no admin left")
		}
	}
	return next, nil
}

func containsKey(set [][]byte, key []byte) bool {
	for _, m := range set {
		if bytes.Equal(m, key) {
			return true
		}
	}
	return false
}
