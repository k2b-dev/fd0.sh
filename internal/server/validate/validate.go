// Package validate runs server-side checks on incoming events.
//
// All cryptographic / structural invariants from PROTOCOL.md §3 (user chain)
// and §4 (scope chain) are enforced here before the store accepts an event.
package validate

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// ScopeMeta is the CBOR shape stored in chains.metadata for scope chains.
type ScopeMeta struct {
	OEKVersionMax uint64   `cbor:"oek_version_max"`
	Members       [][]byte `cbor:"members"` // sorted Ed25519 super_pubs
	// Roles holds non-admin roles (docs/SCOPE_ROLES_PLAN.md); members
	// without an entry are admins.
	Roles proto.ScopeRoles `cbor:"roles,omitempty"`
}

// UserMeta is the CBOR shape stored in chains.metadata for user chains.
type UserMeta struct {
	SuperPub []byte `cbor:"super_pub"`
	ShortID  string `cbor:"short_id"`
}

// UserEvent validates a single auth.set event against the prior chain state.
//
//	prior == nil iff this is genesis (seq=0).
//
// THREAT: T01 (server fabricates auth.set events).
func UserEvent(ev *proto.UserEvent, prior *UserMeta, priorTipHash []byte, priorTipSeq uint64) error {
	if ev.Kind != proto.KindAuthSet {
		return fmt.Errorf("bad kind %q", ev.Kind)
	}
	if len(ev.Payload.Active) == 0 {
		return errors.New("auth.set: empty active")
	}
	seen := map[string]struct{}{}
	for _, m := range ev.Payload.Active {
		if _, dup := seen[m.MethodID]; dup {
			return fmt.Errorf("auth.set: duplicate method_id %s", m.MethodID)
		}
		seen[m.MethodID] = struct{}{}
		if m.MethodType != proto.AuthPassphrase && m.MethodType != proto.AuthYubikey {
			return fmt.Errorf("auth.set: bad method_type %s", m.MethodType)
		}
	}
	if prior == nil {
		// SECURITY (codex audit 🔴 validate.go:49): protocol
		// requires CBOR nil (0xf6) for genesis prev_hash, NOT an
		// empty byte string (0x40). The previous `len(...) != 0`
		// check accepted both, letting non-canonical clients
		// store events that fail signature verification under
		// strict canonicalisation. PrevHash == nil is the only
		// valid genesis encoding.
		if ev.Seq != 0 || ev.PrevHash != nil {
			return errors.New("auth.set genesis: bad seq/prev_hash (must be CBOR nil)")
		}
	} else {
		if ev.Seq != priorTipSeq+1 {
			return fmt.Errorf("auth.set: seq=%d, expected %d", ev.Seq, priorTipSeq+1)
		}
		if !bytes.Equal(ev.PrevHash, priorTipHash) {
			return errors.New("auth.set: prev_hash mismatch")
		}
		if !bytes.Equal(ev.UserSuperPub, prior.SuperPub) {
			return errors.New("auth.set: user_super_pub changed")
		}
	}
	si, err := ev.SignedInput()
	if err != nil {
		return err
	}
	if !crypto.VerifyBytes(ev.UserSuperPub, si, ev.Signature) {
		return errors.New("auth.set: bad signature")
	}
	return nil
}

// ScopeEvent validates one scope event. prior is nil iff genesis. priorTip*
// describe the chain state before this event.
//
// Returns the post-mutation ScopeMeta the caller should write back.
//
// THREAT: T26 (forged member.change unsigned author),
//
//	T30 (no-op membership change as poison vehicle).
func ScopeEvent(ev *proto.ScopeEvent, prior *ScopeMeta, priorTipHash []byte, priorTipSeq uint64) (*ScopeMeta, error) {
	sp := &ev.SignedPrefix
	// Author == signer.
	if !bytes.Equal(sp.Author, ev.Signature.SignerPubkey) {
		return nil, errors.New("scope: author != signer")
	}
	// Signature.
	si, err := ev.SignedInput()
	if err != nil {
		return nil, err
	}
	if !crypto.VerifyBytes(sp.Author, si, ev.Signature.Signature) {
		return nil, errors.New("scope: bad signature")
	}
	// Genesis vs. successor envelope.
	if prior == nil {
		// Genesis.
		if sp.Kind != proto.KindMemberChange || sp.Payload.Op != proto.OpAdd {
			return nil, errors.New("scope: genesis must be member.change op=add")
		}
		// SECURITY (codex audit 🔴 validate.go:91): scope genesis
		// MUST have signed_prefix.scope == nil per PROTOCOL.md;
		// the previous code didn't enforce that, allowing the
		// server to store a protocol-invalid genesis where the
		// scope field was a non-nil placeholder. Reject.
		if sp.Scope != nil {
			return nil, errors.New("scope: genesis signed_prefix.scope must be nil")
		}
		// SECURITY (codex audit 🔴 validate.go:97): same nil-vs-
		// empty-bytes hazard as auth.set genesis.
		if sp.Seq != 0 || sp.PrevHash != nil {
			return nil, errors.New("scope: genesis bad seq/prev_hash (must be CBOR nil)")
		}
		if !bytes.Equal(sp.Payload.Member, sp.Author) {
			return nil, errors.New("scope: genesis member must equal author")
		}
		if err := proto.GenesisRole(sp); err != nil {
			return nil, err
		}
		if sp.OEKVersion != 1 {
			return nil, errors.New("scope: genesis oek_version must be 1")
		}
		// key_deliveries: exactly one, recipient is author's X25519.
		if len(sp.KeyDeliveries) != 1 {
			return nil, errors.New("scope: genesis must have one key_delivery")
		}
		x, err := crypto.EdPubToX25519(sp.Author)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(sp.KeyDeliveries[0].RecipientPubkey, x) {
			return nil, errors.New("scope: genesis key_delivery recipient != author")
		}
		return &ScopeMeta{
			OEKVersionMax: 1,
			Members:       [][]byte{append([]byte(nil), sp.Author...)},
		}, nil
	}
	// Non-genesis common envelope.
	if sp.Seq != priorTipSeq+1 {
		return nil, fmt.Errorf("scope: seq=%d, expected %d", sp.Seq, priorTipSeq+1)
	}
	if !bytes.Equal(sp.PrevHash, priorTipHash) {
		return nil, errors.New("scope: prev_hash mismatch")
	}
	if err := proto.AuthorizeScopeEvent(sp, prior.Members, prior.Roles); err != nil {
		return nil, err
	}
	switch sp.Kind {
	case proto.KindMemberChange:
		return validateMemberChange(sp, prior)
	case proto.KindSecretSet:
		return validateSecretSet(sp, prior)
	default:
		return nil, fmt.Errorf("scope: bad kind %q", sp.Kind)
	}
}

func validateMemberChange(sp *proto.SignedPrefix, prior *ScopeMeta) (*ScopeMeta, error) {
	if len(prior.Members) > proto.MaxLegacyScopeMembers {
		return nil, errors.New("member.change: prior member set exceeds protocol limit")
	}
	if len(sp.KeyDeliveries) > proto.MaxKeyDeliveries {
		return nil, errors.New("member.change: too many key_deliveries")
	}
	// Payload shape: member.change must have op/member, must NOT have enc_body.
	if len(sp.Payload.EncBody) != 0 {
		return nil, errors.New("member.change: enc_body must be empty")
	}
	if sp.Payload.Op == "" || len(sp.Payload.Member) != 32 {
		return nil, errors.New("member.change: op/member missing")
	}
	if sp.Payload.Op == proto.OpRole {
		// A role change keeps membership and read access, so the OEK is
		// not rotated: no new version, no key deliveries, no projection.
		if sp.OEKVersion != prior.OEKVersionMax {
			return nil, fmt.Errorf("member.change role: oek_version=%d, want %d", sp.OEKVersion, prior.OEKVersionMax)
		}
		if len(sp.KeyDeliveries) != 0 || len(sp.Payload.EncProjection) != 0 {
			return nil, errors.New("member.change role: key_deliveries and enc_projection must be empty")
		}
		roles, err := proto.NextScopeRoles(prior.Roles, prior.Members, sp)
		if err != nil {
			return nil, err
		}
		return &ScopeMeta{OEKVersionMax: prior.OEKVersionMax, Members: prior.Members, Roles: roles}, nil
	}
	if sp.OEKVersion != prior.OEKVersionMax+1 {
		return nil, fmt.Errorf("member.change: oek_version=%d, want %d", sp.OEKVersion, prior.OEKVersionMax+1)
	}
	switch sp.Payload.Op {
	case proto.OpAdd:
		if memberContains(prior.Members, sp.Payload.Member) {
			return nil, errors.New("member.change add: target already a member")
		}
		if len(prior.Members) >= proto.MaxScopeMembers {
			return nil, errors.New("member.change add: scope member limit reached")
		}
	case proto.OpRemove:
		if !memberContains(prior.Members, sp.Payload.Member) {
			return nil, errors.New("member.change remove: target not a member")
		}
	default:
		return nil, fmt.Errorf("member.change: bad op %q", sp.Payload.Op)
	}
	post := mutateMembers(prior.Members, sp.Payload.Member, sp.Payload.Op)
	if len(sp.KeyDeliveries) != len(post) {
		return nil, errors.New("member.change: key_deliveries don't match post-mutation set")
	}
	// key_deliveries set must equal X25519(post).
	wantX := make([][]byte, 0, len(post))
	for _, m := range post {
		x, err := crypto.EdPubToX25519(m)
		if err != nil {
			return nil, err
		}
		wantX = append(wantX, x)
	}
	got := make([][]byte, 0, len(sp.KeyDeliveries))
	for _, kd := range sp.KeyDeliveries {
		got = append(got, append([]byte(nil), kd.RecipientPubkey...))
	}
	wantX = sortBytes(wantX)
	got = sortBytes(got)
	if !equalSet(wantX, got) {
		return nil, errors.New("member.change: key_deliveries don't match post-mutation set")
	}
	// Body size.
	if len(sp.Payload.EncProjection) > 1<<20 {
		return nil, errors.New("member.change: body too large")
	}
	roles, err := proto.NextScopeRoles(prior.Roles, post, sp)
	if err != nil {
		return nil, err
	}
	return &ScopeMeta{
		OEKVersionMax: sp.OEKVersion,
		Members:       post,
		Roles:         roles,
	}, nil
}

func validateSecretSet(sp *proto.SignedPrefix, prior *ScopeMeta) (*ScopeMeta, error) {
	if sp.OEKVersion != prior.OEKVersionMax {
		return nil, fmt.Errorf("secret.set: oek_version=%d, want %d", sp.OEKVersion, prior.OEKVersionMax)
	}
	if len(sp.KeyDeliveries) != 0 {
		return nil, errors.New("secret.set: key_deliveries must be empty")
	}
	// Payload shape: secret.set must have enc_body, no member.change fields.
	if len(sp.Payload.EncBody) == 0 {
		return nil, errors.New("secret.set: enc_body required")
	}
	if sp.Payload.Op != "" || len(sp.Payload.Member) != 0 || len(sp.Payload.EncProjection) != 0 {
		return nil, errors.New("secret.set: stray member.change fields")
	}
	if len(sp.Payload.EncBody) > 64*1024 {
		return nil, errors.New("secret.set: body too large")
	}
	out := *prior
	return &out, nil
}

// ---- helpers ----

func memberContains(ms [][]byte, k []byte) bool {
	for _, m := range ms {
		if bytes.Equal(m, k) {
			return true
		}
	}
	return false
}

func mutateMembers(prior [][]byte, target []byte, op string) [][]byte {
	switch op {
	case proto.OpAdd:
		out := make([][]byte, 0, len(prior)+1)
		out = append(out, prior...)
		out = append(out, append([]byte(nil), target...))
		return sortBytes(out)
	case proto.OpRemove:
		out := make([][]byte, 0, len(prior))
		for _, m := range prior {
			if !bytes.Equal(m, target) {
				out = append(out, m)
			}
		}
		return sortBytes(out)
	}
	return prior
}

func equalSet(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sortBytes(s [][]byte) [][]byte {
	sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i], s[j]) < 0 })
	return s
}
