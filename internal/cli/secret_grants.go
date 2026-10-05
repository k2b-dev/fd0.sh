package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/secretgrant"
)

// Secret grants (docs/SECRET_GRANTS_PLAN.md) keep one value readable on this
// device while the vault is locked, for unattended consumers such as a cld
// agent profile reading its client secret. Every process of the OS user can
// read a granted value while the grant is active.

// ParseGrantTTL accepts Go durations and whole days ("30d").
func ParseGrantTTL(s string) (time.Duration, error) {
	if s == "" {
		return secretgrant.DefaultTTL, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil {
			return 0, fmt.Errorf("invalid --ttl %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid --ttl %q (use for example 30d or 72h)", s)
		}
	}
	if d <= 0 || d > secretgrant.MaxTTL {
		return 0, errors.New("--ttl must be between 1 hour and 365 days")
	}
	return d, nil
}

// ManageSecretGrant serializes persistent changes with ordinary CLI writers;
// list and read go straight to the agent and work while locked.
func ManageSecretGrant(ctx context.Context, r agent.SecretGrantReq) (*agent.SecretGrantResp, error) {
	if r.Action == "list" || r.Action == "read" {
		paths, err := fdhome.Resolve()
		if err != nil {
			return nil, err
		}
		return agent.NewClient(paths.AgentSock).SecretGrant(r)
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if r.Action == "prepare" || r.Action == "create" {
		scopeID, err := s.resolveScopeID(r.ScopeID)
		if err != nil {
			return nil, err
		}
		r.ScopeID = scopeID
	}
	return s.Agent.SecretGrant(r)
}

// RunValueGrant reviews and saves a grant for one value after fresh
// authentication in a terminal.
func RunValueGrant(ctx context.Context, kind, scope, name, field, ttl, method string) error {
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("create secret grants yourself in an interactive terminal; fresh authentication is required")
	}
	d, err := ParseGrantTTL(ttl)
	if err != nil {
		return err
	}
	if scope == "" {
		return errors.New("--scope is required, so the grant names exactly one value")
	}
	r := agent.SecretGrantReq{Action: "prepare", ScopeID: scope, Kind: kind, Name: name, Field: field, ExpiresAt: time.Now().Add(d).Unix()}
	preview, err := ManageSecretGrant(ctx, r)
	if err != nil {
		return err
	}
	if len(preview.Grants) != 1 {
		return errors.New("invalid secret grant preview")
	}
	g := preview.Grants[0]
	r.ScopeID = g.ScopeID
	target := g.Name
	if g.Field != "" {
		target += " → " + g.Field
	}
	fmt.Fprintf(os.Stderr, "Keep this value readable on this device while fd0 is locked:\n  %s %s (%s field) in %s\n  Expires: %s\n",
		g.Kind, terminalSafe(target), g.FieldType, terminalSafe(g.ScopeLabel), time.Unix(g.ExpiresAt, 0).Format("2006-01-02 15:04"))
	fmt.Fprintln(os.Stderr, "While the grant is active, every process of your OS user can read this value; locking does not stop that.\nfd0 lock --all stops all grants until the next unlock. Authenticate again to authorize exactly this grant. Ctrl+C cancels.")
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	methods, err := LoadGrantAuthMethods(paths)
	if err != nil {
		return err
	}
	chosen, credential, err := promptAuthentication(paths, methods, method)
	defer crypto.Wipe(credential.Passphrase)
	defer crypto.Wipe(credential.YubikeyPIN)
	if err != nil {
		return err
	}
	r.Action, r.Digest = "create", preview.Digest
	r.Authentication = &agent.UnlockReq{MethodType: chosen.MethodType, Passphrase: credential.Passphrase, YubikeyPIN: credential.YubikeyPIN}
	result, err := ManageSecretGrant(ctx, r)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ secret grant saved: %s (active after the next lock; use exact names and --scope while locked)\n", result.Grants[0].ID)
	return nil
}

// RunValueGrants lists this device's secret grants without values.
func RunValueGrants(ctx context.Context, asJSON bool) error {
	result, err := ManageSecretGrant(ctx, agent.SecretGrantReq{Action: "list"})
	if err != nil {
		return err
	}
	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if len(result.Grants) == 0 {
		fmt.Println("No visible secret grants. Unlock to see saved grants after an agent restart.")
	}
	for _, g := range result.Grants {
		state := "inactive (unlock, or grant again if the value changed)"
		if g.Active {
			state = "active"
		}
		if g.ExpiresAt <= time.Now().Unix() {
			state = "expired"
		}
		target := g.Name
		if g.Field != "" {
			target += "/" + g.Field
		}
		fmt.Printf("%s  %-7s %s  %s  expires %s  %s\n", g.ID, g.Kind, terminalSafe(target), terminalSafe(g.ScopeLabel),
			time.Unix(g.ExpiresAt, 0).Format("2006-01-02"), state)
	}
	return nil
}

// RunValueRevoke removes one grant (vault unlocked).
func RunValueRevoke(ctx context.Context, id string) error {
	if _, err := ManageSecretGrant(ctx, agent.SecretGrantReq{Action: "revoke", ID: id}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "✓ secret grant removed")
	return nil
}

// grantedValue reads a granted value while the vault is locked. It returns
// ErrAgentLocked unless exactly one active grant matches.
func grantedValue(kind, scope, name, field string) ([]byte, error) {
	resp, err := ManageSecretGrant(context.Background(), agent.SecretGrantReq{Action: "read", ScopeID: scope, Kind: kind, Name: name, Field: field})
	if err != nil {
		if strings.Contains(err.Error(), "several grants match") {
			return nil, err
		}
		return nil, ErrAgentLocked
	}
	return resp.Value, nil
}

// HasGrantedValue reports whether a locked read would succeed, so the CLI can
// skip the interactive unlock prompt.
func HasGrantedValue(kind, scope, name, field string) bool {
	v, err := grantedValue(kind, scope, name, field)
	crypto.Wipe(v)
	return err == nil
}

func printValue(v []byte, raw bool) {
	_, _ = os.Stdout.Write(v)
	if !raw {
		fmt.Println()
	}
}
