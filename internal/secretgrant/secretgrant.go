// Package secretgrant resolves grants that let a device read one value while
// the vault is locked (docs/SECRET_GRANTS_PLAN.md): a plain secret, one
// text or secret field of a pass item, or one service field.
package secretgrant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/service"
)

const (
	KindSecret  = "secret"
	KindPass    = "pass"
	KindService = "service"

	DefaultTTL = 30 * 24 * time.Hour
	MaxTTL     = 365 * 24 * time.Hour
	MaxGrants  = 256
)

// RecordName is the stored record name for a kind and bare name.
func RecordName(kind, name string) (string, error) {
	switch kind {
	case KindSecret:
		return name, nil
	case KindPass:
		return "pass:" + name, nil
	case KindService:
		return "service:" + name, nil
	}
	return "", fmt.Errorf("unknown grant kind %q", kind)
}

// ReplayScope replays one scope with the identity key, refusing scopes the
// device is leaving or has left and local rollbacks against the vault tip.
// The caller wipes the returned state's OEKs.
func ReplayScope(paths fdhome.Paths, body *proto.VaultBody, pub, priv []byte, scope string) (*chain.ScopeState, error) {
	id, err := proto.ParseScopeID(scope)
	if err != nil {
		return nil, err
	}
	sd, ok := body.Scopes[scope]
	if !ok || sd.Leaving {
		return nil, errors.New("scope unavailable")
	}
	xPriv, err := crypto.EdPrivToX25519(priv)
	if err != nil {
		return nil, err
	}
	defer crypto.Wipe(xPriv)
	xPub, err := crypto.EdPubToX25519(pub)
	if err != nil {
		return nil, err
	}
	events, err := chain.ReadScopeEventsReadOnly(paths.ScopeChain(id))
	if err != nil {
		return nil, err
	}
	st, err := chain.ReplayScopeEvents(events, pub, xPub, chain.LocalOpener{Pub: xPub, Priv: xPriv}, nil)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("scope chain is missing")
	}
	if st.Left {
		WipeScope(st)
		return nil, errors.New("scope membership removed")
	}
	if mm := chain.CompareScopeTip(scope, sd.ChainTip, st); mm != nil && mm.Direction != "ahead" {
		WipeScope(st)
		return nil, errors.New("scope rollback detected")
	}
	return st, nil
}

// WipeScope wipes a replayed scope's keys.
func WipeScope(st *chain.ScopeState) {
	for _, key := range st.OEKs {
		crypto.Wipe(key)
	}
}

// Find locates the record a new grant would pin: by kind and bare name, with
// exactly one match, and the value's field type. It returns the record ID.
func Find(st *chain.ScopeState, kind, name, field string) (recordID, fieldType string, err error) {
	recordName, err := RecordName(kind, name)
	if err != nil {
		return "", "", err
	}
	for id, cur := range st.SecretIndex {
		if cur.Record == nil || cur.Record.Name != recordName {
			continue
		}
		if recordID != "" {
			return "", "", fmt.Errorf("%s %q is ambiguous in this scope", kind, name)
		}
		_, fieldType, err = extract(cur.Record, kind, field)
		if err != nil {
			return "", "", err
		}
		recordID = id
	}
	if recordID == "" {
		return "", "", fmt.Errorf("%s %q not found in this scope", kind, name)
	}
	return recordID, fieldType, nil
}

// Value returns the granted value if the pinned record still exists under
// the same name, kind and field type. Any change disables the grant until it
// is approved again. The caller wipes the value.
func Value(st *chain.ScopeState, g proto.SecretGrant) ([]byte, error) {
	cur, ok := st.SecretIndex[g.RecordID]
	if !ok || cur.Record == nil {
		return nil, errors.New("granted record was deleted or moved")
	}
	recordName, err := RecordName(g.Kind, g.Name)
	if err != nil {
		return nil, err
	}
	if cur.Record.Name != recordName {
		return nil, errors.New("granted record was renamed")
	}
	value, fieldType, err := extract(cur.Record, g.Kind, g.Field)
	if err != nil {
		return nil, err
	}
	if fieldType != g.FieldType {
		crypto.Wipe(value)
		return nil, errors.New("granted field changed type")
	}
	return value, nil
}

func extract(rec *proto.SecretRecord, kind, field string) ([]byte, string, error) {
	switch kind {
	case KindSecret:
		if rec.Type != "kv.string" || field != "" {
			return nil, "", errors.New("only plain string secrets can be granted without a field")
		}
		v, ok := rec.Payload.(string)
		if !ok {
			return nil, "", errors.New("secret has no string value")
		}
		return []byte(v), "secret", nil
	case KindPass:
		if rec.Type != passitem.TypePassItem || field == "" {
			return nil, "", errors.New("a pass grant needs one field")
		}
		raw, err := payloadBytes(rec.Payload)
		if err != nil {
			return nil, "", err
		}
		item, err := passitem.Decode(raw)
		if err != nil {
			return nil, "", err
		}
		f, err := item.Field(field)
		if err != nil {
			return nil, "", err
		}
		if f.Type != passitem.FieldText && f.Type != passitem.FieldSecret {
			return nil, "", fmt.Errorf("field %q is %s; only text and secret fields can be granted", field, f.Type)
		}
		v, err := passitem.StringValue(*f)
		if err != nil {
			return nil, "", err
		}
		return []byte(v), f.Type, nil
	case KindService:
		if rec.Type != service.TypeService || field == "" {
			return nil, "", errors.New("a service grant needs one field")
		}
		raw, err := payloadBytes(rec.Payload)
		if err != nil {
			return nil, "", err
		}
		svc, err := service.Decode(raw)
		if err != nil {
			return nil, "", err
		}
		f, err := svc.Field(field)
		if err != nil {
			return nil, "", err
		}
		if f.Type != service.FieldText && f.Type != service.FieldSecret {
			return nil, "", fmt.Errorf("field %q is %s; only text and secret fields can be granted", field, f.Type)
		}
		return []byte(f.Value), f.Type, nil
	}
	return nil, "", fmt.Errorf("unknown grant kind %q", kind)
}

func payloadBytes(p any) ([]byte, error) {
	switch v := p.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		return json.Marshal(v)
	}
}

// Digest is what the reviewer approves: everything the grant pins.
func Digest(g proto.SecretGrant) string {
	canonical := struct {
		Domain    string `json:"domain"`
		Device    string `json:"device"`
		Scope     string `json:"scope"`
		Record    string `json:"record"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Field     string `json:"field"`
		FieldType string `json:"fieldType"`
		Expires   int64  `json:"expires"`
	}{"fd0-secret-grant-v1", g.DeviceID, g.ScopeID, g.RecordID, g.Kind, g.Name, g.Field, g.FieldType, g.ExpiresAt}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
