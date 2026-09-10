package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

var organizationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var errOrganizationDenied = errors.New("organization session is expired, revoked, or locked; ask the user to create a new session")

type OrganizationAccessOptions struct {
	Scopes       []string
	Destinations []string
	Operations   []string
	TTL          time.Duration
}
type organizationGrant struct {
	ID            string    `json:"id"`
	Expires       time.Time `json:"expires"`
	UnlockSession string    `json:"unlockSession"`
	Scopes        []string  `json:"scopes"`
	Destinations  []string  `json:"destinations"`
	Operations    []string  `json:"operations"`
	Revoked       bool      `json:"revoked"`
}
type OrganizationAccess struct {
	paths fdhome.Paths
	grant organizationGrant
}

func organizationID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func organizationDir(paths fdhome.Paths, id string) (string, error) {
	if !organizationIDPattern.MatchString(id) {
		return "", errors.New("invalid organization session ID")
	}
	return filepath.Join(paths.Home, "organization", "sessions", id), nil
}
func (a *OrganizationAccess) dir() string {
	path, _ := organizationDir(a.paths, a.grant.ID)
	return path
}
func readOrganizationJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() > 1<<20 {
		return errors.New("organization document exceeds limit")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid organization document")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid organization document")
	}
	return nil
}
func writeOrganizationJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("organization document exceeds limit")
	}
	return writeFileAtomic(path, data, 0600)
}
func NewOrganizationAccess(ctx context.Context, opts OrganizationAccessOptions) (*OrganizationAccess, error) {
	if len(opts.Scopes) == 0 || opts.TTL <= 0 || opts.TTL > 4*time.Hour {
		return nil, errors.New("explicit source scopes and a lifetime of at most four hours are required")
	}
	if len(opts.Operations) == 0 {
		return nil, errors.New("explicit organization operations are required")
	}
	for _, op := range opts.Operations {
		if !slices.Contains([]string{"tags", "rename", "move"}, op) {
			return nil, errors.New("unsupported organization permission")
		}
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, errors.New("unlock fd0 before starting an organization session")
	}
	defer s.Close()
	status, err := s.Agent.Status()
	if err != nil || !status.Unlocked || status.UnlockSession == "" {
		return nil, errors.New("organization sessions require an unlocked agent with unlock-session support")
	}
	grant := organizationGrant{ID: organizationID(), Expires: time.Now().Add(opts.TTL), UnlockSession: status.UnlockSession, Operations: slices.Clone(opts.Operations)}
	for _, value := range opts.Scopes {
		id, err := s.resolveScopeID(value)
		if err != nil {
			return nil, errors.New("unknown source scope")
		}
		if !slices.Contains(grant.Scopes, id) {
			grant.Scopes = append(grant.Scopes, id)
		}
	}
	for _, value := range opts.Destinations {
		id, err := s.resolveScopeID(value)
		if err != nil {
			return nil, errors.New("unknown destination scope")
		}
		if !slices.Contains(grant.Destinations, id) {
			grant.Destinations = append(grant.Destinations, id)
		}
	}
	if slices.Contains(grant.Operations, "move") && len(grant.Destinations) == 0 {
		return nil, errors.New("move permission requires explicit destination scopes")
	}
	access := &OrganizationAccess{paths: s.Paths, grant: grant}
	if err := os.MkdirAll(access.dir(), 0700); err != nil {
		return nil, err
	}
	if err := writeOrganizationJSON(filepath.Join(access.dir(), "grant.json"), grant); err != nil {
		return nil, err
	}
	return access, nil
}
func (a *OrganizationAccess) check() error {
	var grant organizationGrant
	if err := readOrganizationJSON(filepath.Join(a.dir(), "grant.json"), &grant); err != nil {
		return errOrganizationDenied
	}
	if grant.Revoked || !time.Now().Before(a.grant.Expires) || grant.UnlockSession != a.grant.UnlockSession {
		return errOrganizationDenied
	}
	status, err := agent.NewClient(a.paths.AgentSock).Status()
	if err != nil || !status.Unlocked || status.UnlockSession != a.grant.UnlockSession {
		return errOrganizationDenied
	}
	return nil
}
func (a *OrganizationAccess) session(ctx context.Context) (*Session, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, errors.New("organization vault is unavailable")
	}
	s.organizationCheck = a.check
	if err := a.check(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (a *OrganizationAccess) Info() (map[string]any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	return map[string]any{"sessionId": a.grant.ID, "expiresAt": a.grant.Expires, "sourceScopes": a.grant.Scopes, "destinationScopes": a.grant.Destinations, "operations": a.grant.Operations}, nil
}
func (a *OrganizationAccess) Inventory(ctx context.Context) ([]OrganizationItem, error) {
	s, err := a.session(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	items := []OrganizationItem{}
	for _, scope := range a.grant.Scopes {
		next, err := s.OrganizationInventory(OrganizationFilter{Scope: scope})
		if err != nil {
			return nil, errors.New("organization inventory unavailable")
		}
		items = append(items, next...)
	}
	if err := a.check(); err != nil {
		return nil, err
	}
	return items, nil
}

type OrganizationChange struct {
	Title         *string   `json:"title,omitempty"`
	ScopeID       string    `json:"scopeId"`
	ID            string    `json:"id"`
	Revision      string    `json:"revision"`
	Tags          *[]string `json:"tags,omitempty"`
	Name          *string   `json:"name,omitempty"`
	TargetScopeID string    `json:"targetScopeId,omitempty"`
}
type OrganizationPlanItem struct {
	Before OrganizationItem   `json:"before"`
	Change OrganizationChange `json:"change"`
}
type OrganizationScopePolicy struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Members  int    `json:"members"`
	Revision string `json:"revision"`
}

type OrganizationPlan struct {
	Scopes    []OrganizationScopePolicy `json:"scopes"`
	ID        string                    `json:"id"`
	SessionID string                    `json:"sessionId"`
	Items     []OrganizationPlanItem    `json:"items"`
}

func (p OrganizationPlan) Digest() string {
	raw, _ := json.Marshal(p)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func (a *OrganizationAccess) planPath(id string) (string, error) {
	if !organizationIDPattern.MatchString(id) {
		return "", errors.New("invalid plan ID")
	}
	return filepath.Join(a.dir(), id+".plan.json"), nil
}
func (a *OrganizationAccess) Propose(ctx context.Context, changes []OrganizationChange) (map[string]any, error) {
	if len(changes) == 0 || len(changes) > 100 {
		return nil, errors.New("a plan needs 1–100 items")
	}
	s, err := a.session(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	files, err := filepath.Glob(filepath.Join(a.dir(), "*.plan.json"))
	if err != nil || len(files) >= 32 {
		return nil, errors.New("session proposal limit reached; ask the user to start a new session")
	}
	plan := OrganizationPlan{ID: organizationID(), SessionID: a.grant.ID}
	seen := map[string]bool{}
	for _, change := range changes {
		if !slices.Contains(a.grant.Scopes, change.ScopeID) {
			return nil, errors.New("source scope is outside this session")
		}
		key := change.ScopeID + "/" + change.ID
		if seen[key] {
			return nil, errors.New("combine changes for an item into one plan entry")
		}
		seen[key] = true
		items, err := s.OrganizationInventory(OrganizationFilter{Scope: change.ScopeID})
		if err != nil {
			return nil, errors.New("item metadata unavailable")
		}
		index := slices.IndexFunc(items, func(item OrganizationItem) bool { return item.ID == change.ID })
		if index < 0 {
			return nil, errors.New("item is not in the permitted inventory")
		}
		item := items[index]
		if item.Revision != change.Revision {
			return nil, errors.New("item changed; refresh its metadata before proposing")
		}
		if change.Title != nil {
			if !slices.Contains(a.grant.Operations, "rename") || item.Kind != "pass" || strings.TrimSpace(*change.Title) == "" || len(*change.Title) > 4096 {
				return nil, errors.New("a nonempty password title and rename permission are required")
			}
		}

		if change.Tags != nil {
			if !slices.Contains(a.grant.Operations, "tags") {
				return nil, errors.New("tag changes are not permitted")
			}
			tags, err := changedItemTags(item.Kind, item.Tags, "set", *change.Tags)
			if err != nil {
				return nil, errors.New("invalid tags for this item type")
			}
			change.Tags = &tags
		}
		if change.Name != nil {
			if !slices.Contains(a.grant.Operations, "rename") {
				return nil, errors.New("renaming is not permitted")
			}
			if err := validItemName(*change.Name); err != nil {
				return nil, errors.New("invalid item name")
			}
			for _, other := range items {
				if slices.Contains(other.References, item.Name) {
					return nil, errors.New("item is referenced by a host; update its references in the trusted client before renaming")
				}
			}
		}
		if change.TargetScopeID != "" {
			if !slices.Contains(a.grant.Operations, "move") || !slices.Contains(a.grant.Destinations, change.TargetScopeID) {
				return nil, errors.New("destination scope is outside this session")
			}
			if change.TargetScopeID == change.ScopeID {
				return nil, errors.New("source and destination scopes must differ")
			}
		}
		if change.Tags == nil && change.Name == nil && change.Title == nil && change.TargetScopeID == "" {
			return nil, errors.New("empty item change")
		}
		plan.Items = append(plan.Items, OrganizationPlanItem{Before: item, Change: change})
	}
	scopes := map[string]bool{}
	for _, entry := range plan.Items {
		scopes[entry.Before.ScopeID] = true
		if entry.Change.TargetScopeID != "" {
			scopes[entry.Change.TargetScopeID] = true
		}
	}
	for scope := range scopes {
		policy, err := s.organizationScopePolicy(scope)
		if err != nil {
			return nil, errors.New("scope access could not be verified")
		}
		plan.Scopes = append(plan.Scopes, policy)
	}
	slices.SortFunc(plan.Scopes, func(a, b OrganizationScopePolicy) int { return strings.Compare(a.ID, b.ID) })
	if err := a.checkPlanTargets(s, plan); err != nil {
		return nil, err
	}
	path, _ := a.planPath(plan.ID)
	if err := writeOrganizationJSON(path, plan); err != nil {
		return nil, errors.New("could not save organization proposal")
	}
	return map[string]any{"plan": plan, "digest": plan.Digest(), "approved": false}, nil
}
func (a *OrganizationAccess) checkPlanTargets(s *Session, p OrganizationPlan) error {
	seen := map[string]bool{}
	for _, entry := range p.Items {
		name := entry.Before.Name
		if entry.Change.Name != nil {
			record, err := s.GetTypedSecret(entry.Before.ScopeID, entry.Before.Name)
			if err != nil {
				return errors.New("item changed; create a fresh plan")
			}
			kind, err := OrganizationKind(record.Type)
			if err != nil {
				return errors.New("unsupported item type")
			}
			name = kind.Prefix + *entry.Change.Name
		}
		scope := entry.Before.ScopeID
		if entry.Change.TargetScopeID != "" {
			scope = entry.Change.TargetScopeID
		}
		target := scope + "/" + name
		if seen[target] {
			return errors.New("multiple changes have the same destination")
		}
		seen[target] = true
		if scope == entry.Before.ScopeID && name == entry.Before.Name {
			continue
		}
		if _, err := s.GetTypedSecret(scope, name); err == nil {
			return errors.New("destination item already exists; choose another name or scope")
		} else if !errors.Is(err, ErrTypedSecretNotFound) {
			return errors.New("destination could not be checked")
		}
	}
	return nil
}
func loadOrganizationAccess(id string) (*OrganizationAccess, error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	dir, err := organizationDir(paths, id)
	if err != nil {
		return nil, err
	}
	var grant organizationGrant
	if err := readOrganizationJSON(filepath.Join(dir, "grant.json"), &grant); err != nil {
		return nil, errors.New("organization session not found")
	}
	if grant.ID != id {
		return nil, errors.New("invalid organization session")
	}
	return &OrganizationAccess{paths: paths, grant: grant}, nil
}
func (a *OrganizationAccess) readPlan(id string) (OrganizationPlan, error) {
	var plan OrganizationPlan
	path, err := a.planPath(id)
	if err != nil {
		return plan, err
	}
	if err := readOrganizationJSON(path, &plan); err != nil {
		return plan, errors.New("organization plan not found")
	}
	if plan.ID != id || plan.SessionID != a.grant.ID {
		return plan, errors.New("plan belongs to another session")
	}
	return plan, nil
}
func ReviewOrganizationPlan(sessionID, planID string) (map[string]any, error) {
	a, err := loadOrganizationAccess(sessionID)
	if err != nil {
		return nil, err
	}
	plan, err := a.readPlan(planID)
	if err != nil {
		return nil, err
	}
	result := map[string]any{"plan": plan, "digest": plan.Digest()}
	var progress organizationProgress
	if err := readOrganizationJSON(filepath.Join(a.dir(), planID+".progress.json"), &progress); err == nil {
		result["progress"] = progress
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("could not read plan progress")
	}
	return result, nil
}
func ApproveOrganizationPlan(sessionID, planID, digest string) error {
	a, err := loadOrganizationAccess(sessionID)
	if err != nil {
		return err
	}
	if err := a.check(); err != nil {
		return err
	}
	plan, err := a.readPlan(planID)
	if err != nil {
		return err
	}
	if digest != plan.Digest() {
		return errors.New("review digest does not match the saved plan")
	}
	return writeOrganizationJSON(filepath.Join(a.dir(), planID+".approval.json"), map[string]string{"digest": digest})
}
func RevokeOrganizationAccess(sessionID string) error {
	a, err := loadOrganizationAccess(sessionID)
	if err != nil {
		return err
	}
	a.grant.Revoked = true
	return writeOrganizationJSON(filepath.Join(a.dir(), "grant.json"), a.grant)
}

type organizationProgressItem struct {
	ID       string `json:"id"`
	ScopeID  string `json:"scopeId"`
	Name     string `json:"name"`
	Revision string `json:"revision"`
	Stage    int    `json:"stage"`
}
type organizationProgress struct {
	Digest   string                     `json:"digest"`
	Items    []organizationProgressItem `json:"items"`
	Moving   bool                       `json:"moving"`
	Complete bool                       `json:"complete"`
}

func (a *OrganizationAccess) Execute(ctx context.Context, id string) (any, error) {
	s, err := a.session(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	plan, err := a.readPlan(id)
	if err != nil {
		return nil, err
	}
	approval := map[string]string{}
	if readOrganizationJSON(filepath.Join(a.dir(), id+".approval.json"), &approval) != nil || approval["digest"] != plan.Digest() {
		return nil, errors.New("the user must review and approve this exact plan in their trusted terminal")
	}
	s.organizationCheck = func() error {
		if err := a.check(); err != nil {
			return err
		}
		return s.checkOrganizationPolicies(plan.Scopes)
	}
	if err := s.checkOrganizationWrite(); err != nil {
		return nil, err
	}
	path := filepath.Join(a.dir(), id+".progress.json")
	progress := organizationProgress{Digest: plan.Digest()}
	err = readOrganizationJSON(path, &progress)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("could not read plan progress")
	}
	if progress.Digest != plan.Digest() {
		return nil, errors.New("plan changed after execution started")
	}
	if len(progress.Items) == 0 {
		for _, item := range plan.Items {
			progress.Items = append(progress.Items, organizationProgressItem{ID: item.Before.ID, ScopeID: item.Before.ScopeID, Name: item.Before.Name, Revision: item.Before.Revision})
		}
	}
	if len(progress.Items) != len(plan.Items) {
		return nil, errors.New("invalid plan progress")
	}
	if progress.Complete {
		return progress, nil
	}
	update := func(index, stage int) error {
		current := &progress.Items[index]
		inventory, err := s.OrganizationInventory(OrganizationFilter{Scope: current.ScopeID})
		if err != nil {
			return err
		}
		itemIndex := slices.IndexFunc(inventory, func(item OrganizationItem) bool { return item.Name == current.Name })
		if itemIndex < 0 {
			return errors.New("item not found after change")
		}
		current.ID = inventory[itemIndex].ID
		current.Revision = inventory[itemIndex].Revision
		current.Stage = stage
		if stage == 3 {
			return nil // Publish all final references together, so retries retain the original move sources.
		}
		return writeOrganizationJSON(path, progress)
	}
	if !progress.Moving {
		// Validate the complete remaining batch before its first write.
		for _, current := range progress.Items {
			inventory, err := s.OrganizationInventory(OrganizationFilter{Scope: current.ScopeID})
			if err != nil {
				return nil, errors.New("item metadata unavailable")
			}
			if !slices.ContainsFunc(inventory, func(item OrganizationItem) bool { return item.ID == current.ID && item.Revision == current.Revision }) {
				return nil, errors.New("item changed since review or an interrupted write; review a fresh plan")
			}
		}
		remaining := plan
		remaining.Items = slices.Clone(plan.Items)
		for i := range remaining.Items {
			remaining.Items[i].Before.ScopeID = progress.Items[i].ScopeID
			remaining.Items[i].Before.Name = progress.Items[i].Name
		}
		if err := a.checkPlanTargets(s, remaining); err != nil {
			return nil, err
		}
		if err := writeOrganizationJSON(path, progress); err != nil {
			return nil, errors.New("could not save plan progress")
		}
		for i, entry := range plan.Items {
			current := &progress.Items[i]
			if current.Stage < 1 {
				if entry.Change.Title != nil {
					if err := s.SetOrganizationTitle(ctx, current.ScopeID, current.Name, *entry.Change.Title); err != nil {
						return progress, errors.New("title change failed; inspect progress before retrying")
					}
				}
				if entry.Change.Tags != nil {
					if err := s.ChangeItemTags(ctx, current.ScopeID, current.Name, "set", *entry.Change.Tags); err != nil {
						return progress, errors.New("tag change failed; inspect progress before retrying")
					}
				}
				if err := update(i, 1); err != nil {
					return progress, errors.New("could not record tag progress; review a fresh plan")
				}
			}
			if current.Stage < 2 {
				if entry.Change.Name != nil {
					r, err := s.GetTypedSecret(current.ScopeID, current.Name)
					if err != nil {
						return progress, errors.New("item unavailable")
					}
					kind, err := OrganizationKind(r.Type)
					if err != nil {
						return progress, errors.New("unsupported item")
					}
					next := kind.Prefix + *entry.Change.Name
					if next != current.Name {
						if err := s.RenameOrganizationItem(ctx, r, *entry.Change.Name); err != nil {
							return progress, errors.New("rename failed; inspect progress before retrying")
						}
						current.Name = next
					}
				}
				if err := update(i, 2); err != nil {
					return progress, errors.New("could not record rename progress; review a fresh plan")
				}
			}
		}
	}
	moves := []OrganizationMove{}
	for i, entry := range plan.Items {
		if entry.Change.TargetScopeID != "" {
			current := progress.Items[i]
			moves = append(moves, OrganizationMove{ScopeID: current.ScopeID, Name: current.Name, TargetScopeID: entry.Change.TargetScopeID})
		}
	}
	if len(moves) > 0 {
		progress.Moving = true
		if err := writeOrganizationJSON(path, progress); err != nil {
			return progress, errors.New("could not record move progress")
		}
		if err := s.MoveOrganizationItems(ctx, moves); err != nil {
			return progress, errors.New("move incomplete; sources are retained until destinations are verified; inspect the trusted client and retry this plan")
		}
		for i, entry := range plan.Items {
			if entry.Change.TargetScopeID != "" {
				progress.Items[i].ScopeID = entry.Change.TargetScopeID
			}
		}
	}
	for i := range progress.Items {
		if err := update(i, 3); err != nil {
			return progress, errors.New("could not record final progress")
		}
	}
	progress.Complete = true
	if err := writeOrganizationJSON(path, progress); err != nil {
		return progress, errors.New("could not record completion")
	}
	if err := a.check(); err != nil {
		return nil, err
	}
	return progress, nil
}

// DecodeOrganizationArguments rejects fields not in the operation allowlist.
func DecodeOrganizationArguments(raw []byte, value any) error {
	if len(raw) > 256<<10 {
		return errors.New("request exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid organization arguments")
	}
	return nil
}

// Keep method and filesystem selection outside model-controlled arguments.
func (a *OrganizationAccess) Call(ctx context.Context, name string, raw []byte) (any, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	switch name {
	case "organization_session":
		if err := DecodeOrganizationArguments(raw, &struct{}{}); err != nil {
			return nil, err
		}
		return a.Info()
	case "organization_list":
		var args struct {
			Offset int    `json:"offset"`
			Limit  int    `json:"limit"`
			Query  string `json:"query"`
		}
		if err := DecodeOrganizationArguments(raw, &args); err != nil {
			return nil, err
		}
		if args.Offset < 0 || args.Limit < 0 || args.Limit > 100 {
			return nil, errors.New("invalid page range")
		}
		if args.Limit == 0 {
			args.Limit = 50
		}
		items, err := a.Inventory(ctx)
		if err != nil {
			return nil, err
		}
		items = slices.DeleteFunc(items, func(item OrganizationItem) bool {
			return args.Query != "" && !strings.Contains(strings.ToLower(item.Name+" "+item.Title+" "+strings.Join(item.Tags, " ")), strings.ToLower(args.Query))
		})
		start := min(args.Offset, len(items))
		end := min(start+args.Limit, len(items))
		return map[string]any{"items": items[start:end], "nextOffset": end, "hasMore": end < len(items)}, nil
	case "organization_propose":
		var args struct {
			Changes []OrganizationChange `json:"changes"`
		}
		if err := DecodeOrganizationArguments(raw, &args); err != nil {
			return nil, err
		}
		return a.Propose(ctx, args.Changes)
	case "organization_status":
		var args struct {
			PlanID string `json:"planId"`
		}
		if err := DecodeOrganizationArguments(raw, &args); err != nil {
			return nil, err
		}
		return ReviewOrganizationPlan(a.grant.ID, args.PlanID)
	case "organization_execute":
		var args struct {
			PlanID string `json:"planId"`
		}
		if err := DecodeOrganizationArguments(raw, &args); err != nil {
			return nil, err
		}
		return a.Execute(ctx, args.PlanID)
	default:
		return nil, errors.New("operation is not available through organization access")
	}
}

func (s *Session) organizationScopePolicy(scope string) (OrganizationScopePolicy, error) {
	st, err := s.replayAndCheckScope(scope)
	if err != nil {
		return OrganizationScopePolicy{}, err
	}
	if st.Left || s.Body.Scopes[scope].Leaving || !slices.ContainsFunc(st.MemberSet, func(pub []byte) bool { return bytes.Equal(pub, s.UserSuperPub) }) {
		return OrganizationScopePolicy{}, errors.New("scope is no longer available")
	}
	raw, _ := json.Marshal(struct {
		Members [][]byte
		Label   string
	}{st.MemberSet, s.Body.Scopes[scope].Label})
	return OrganizationScopePolicy{ID: scope, Label: s.Body.Scopes[scope].Label, Members: len(st.MemberSet), Revision: fmt.Sprintf("%x", sha256.Sum256(raw))}, nil
}
func (s *Session) checkOrganizationPolicies(policies []OrganizationScopePolicy) error {
	for _, expected := range policies {
		current, err := s.organizationScopePolicy(expected.ID)
		if err != nil || current.Revision != expected.Revision {
			return errors.New("scope membership or label changed; review a fresh plan")
		}
	}
	return nil
}
