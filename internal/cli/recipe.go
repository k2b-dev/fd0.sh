package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/recipe"
)

// Deploy recipes (docs/SERVICES_PLAN.md, phase 3). A recipe lives in its
// service's scope as "recipe:SERVICE/NAME"; deploy results live next to it
// as "deploy:SERVICE/NAME/TARGET/DEVICE", one record per target and device.
const (
	recipeNamePrefix = "recipe:"
	resultNamePrefix = "deploy:"
)

// KindRecipe and KindDeployResult only guard their name spaces: they are not
// in itemKinds, so the generic item operations (move, rename, tags) do not
// apply. A recipe's approval pins its scope and name.
var (
	KindRecipe       = ItemKind{Noun: "recipe", Command: "recipe", Prefix: recipeNamePrefix}
	KindDeployResult = ItemKind{Noun: "deploy result", Command: "recipe show", Prefix: resultNamePrefix}
)

// RecipeOpts defines a recipe on add and replaces its definition on edit.
type RecipeOpts struct {
	Name        string // SERVICE/NAME
	Scope       string
	Command     []string
	Dir         string
	Fields      []string // FIELD or FIELD=AS
	Input       string
	Targets     []string
	Description string
}

func (o RecipeOpts) recipe(serviceName string) *recipe.Recipe {
	r := &recipe.Recipe{Version: recipe.Version, Service: serviceName, Command: o.Command, Dir: o.Dir,
		Input: o.Input, Targets: o.Targets, Description: o.Description}
	if len(r.Command) > 0 && r.Command[0] == "--" {
		r.Command = r.Command[1:]
	}
	for _, spec := range o.Fields {
		field, as, _ := strings.Cut(spec, "=")
		r.Fields = append(r.Fields, recipe.Mapping{Field: field, As: as})
	}
	return r
}

// RunRecipeAdd creates a recipe, or replaces one when edit is true.
func RunRecipeAdd(ctx context.Context, o RecipeOpts, edit bool) error {
	serviceName, _, err := recipe.SplitName(o.Name)
	if err != nil {
		return err
	}
	r := o.recipe(serviceName)
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	svcRec, err := s.GetTypedSecret(o.Scope, serviceNamePrefix+serviceName)
	if err != nil {
		return fmt.Errorf("recipe %s: service %q: %w", o.Name, serviceName, err)
	}
	svc, err := decodeServiceRecord(*svcRec)
	if err != nil {
		return err
	}
	if err := r.ResolveNames(svc); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if _, err := r.Prepare(svc); err != nil {
		return err
	}
	if edit {
		if _, err := recipeRecord(s, svcRec.ScopeID, o.Name); err != nil {
			return err
		}
		if err := s.UpdateTypedSecret(ctx, svcRec.ScopeID, recipeNamePrefix+o.Name, recipe.TypeRecipe, recipe.TypeRecipe, r); err != nil {
			return err
		}
		stderrln("✓ recipe %s updated; every device must approve it again (fd0 recipe approve %s)", o.Name, o.Name)
	} else {
		if err := s.CreateTypedSecret(ctx, svcRec.ScopeID, recipeNamePrefix+o.Name, recipe.TypeRecipe, r); err != nil {
			return err
		}
		stderrln("✓ recipe %s created in %s; approve it on each device that deploys (fd0 recipe approve %s)", o.Name, scopeName(s, svcRec.ScopeID), o.Name)
	}
	hintSyncForPeers()
	return nil
}

func recipeRecord(s *Session, scopeID, name string) (*TypedRecord, error) {
	rec, err := s.GetTypedSecret(scopeID, recipeNamePrefix+name)
	if err != nil {
		if errors.Is(err, ErrTypedSecretNotFound) {
			return nil, fmt.Errorf("recipe %q not found", name)
		}
		return nil, err
	}
	return rec, nil
}

func decodeRecipeRecord(rec TypedRecord) (*recipe.Recipe, error) {
	if rec.Type != recipe.TypeRecipe {
		return nil, fmt.Errorf("%q is %s, not %s", rec.Name, rec.Type, recipe.TypeRecipe)
	}
	raw, err := rec.PayloadJSON()
	if err != nil {
		return nil, err
	}
	return recipe.Decode(raw)
}

type recipeEntry struct {
	Name    string // SERVICE/NAME
	ScopeID string
	Record  TypedRecord
	Recipe  *recipe.Recipe
	Digest  string
}

// deviceHome is the home directory recipes resolve ~/ against; it is part of
// every approval digest.
func deviceHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("recipes need an absolute home directory ($HOME)")
	}
	return filepath.Clean(home), nil
}

// loadRecipes returns valid recipes, optionally limited to one service and
// scope, sorted by name. Malformed recipes are reported, never run.
func loadRecipes(s *Session, scopeID, serviceName string) ([]recipeEntry, error) {
	entries, _, err := loadRecipesChecked(s, scopeID, serviceName)
	return entries, err
}

// loadRecipesChecked also returns the names of recipes that cannot be used,
// so a deploy can refuse instead of silently skipping one of its steps.
func loadRecipesChecked(s *Session, scopeID, serviceName string) ([]recipeEntry, []string, error) {
	home, err := deviceHome()
	if err != nil {
		return nil, nil, err
	}
	// Every record in the recipe namespace counts, whatever its type, so a
	// record no step can use is reported instead of silently skipped.
	recs, err := s.ListTypedSecrets(scopeID, "")
	if err != nil {
		return nil, nil, err
	}
	out := []recipeEntry{}
	unusable := []string{}
	for _, rec := range recs {
		name, ok := strings.CutPrefix(rec.Name, recipeNamePrefix)
		if !ok {
			continue
		}
		if serviceName != "" && !strings.HasPrefix(name, serviceName+"/") {
			continue
		}
		r, err := decodeRecipeRecord(rec)
		if err != nil {
			stderrln("  ! recipe %s in %s cannot be used: %v", terminalSafe(name), scopeName(s, rec.ScopeID), err)
			unusable = append(unusable, name)
			continue
		}
		if svc, _, err := recipe.SplitName(name); err != nil || svc != r.Service {
			stderrln("  ! recipe %s in %s names service %q; ignoring it", terminalSafe(name), scopeName(s, rec.ScopeID), r.Service)
			unusable = append(unusable, name)
			continue
		}
		out = append(out, recipeEntry{Name: name, ScopeID: rec.ScopeID, Record: rec, Recipe: r, Digest: recipe.Digest(rec.ScopeID, name, r, home)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Name < out[j].Name
	})
	return out, unusable, nil
}

func approvals(s *Session) (map[string]proto.RecipeApproval, error) {
	resp, err := s.Agent.RecipeApproval(agent.RecipeApprovalReq{Action: "list"})
	if err != nil {
		return nil, err
	}
	out := map[string]proto.RecipeApproval{}
	for _, a := range resp.Approvals {
		out[a.ScopeID+"\x00"+a.Name] = a
	}
	return out, nil
}

func approvalState(e recipeEntry, approved map[string]proto.RecipeApproval) string {
	a, ok := approved[e.ScopeID+"\x00"+e.Name]
	switch {
	case !ok:
		return "not approved on this device"
	case a.Digest != e.Digest:
		return "changed since approval on this device"
	default:
		return "approved on this device"
	}
}

type recipeView struct {
	Name        string           `json:"name"`
	Scope       string           `json:"scope"`
	ScopeID     string           `json:"scopeId"`
	Service     string           `json:"service"`
	Command     []string         `json:"command"`
	Dir         string           `json:"dir,omitempty"`
	Fields      []recipe.Mapping `json:"fields"`
	Input       string           `json:"input"`
	Targets     []string         `json:"targets,omitempty"`
	Description string           `json:"description,omitempty"`
	Digest      string           `json:"digest"`
	Approval    string           `json:"approval"`
	Results     []recipe.Result  `json:"results"`
}

func viewOf(s *Session, e recipeEntry, approved map[string]proto.RecipeApproval, results []recipe.Result) recipeView {
	r := e.Recipe
	if results == nil {
		results = []recipe.Result{}
	}
	return recipeView{Name: e.Name, Scope: scopeName(s, e.ScopeID), ScopeID: e.ScopeID, Service: r.Service, Command: r.Command,
		Dir: r.Dir, Fields: r.Fields, Input: r.Input, Targets: r.Targets, Description: r.Description, Digest: e.Digest,
		Approval: approvalState(e, approved), Results: results}
}

// RecipeView is a recipe as Desktop and --json show it: definition,
// approval state on this device and the latest results. It holds no values.
type RecipeView = recipeView

// ServiceRecipes returns the recipes of one service with their results.
func ServiceRecipes(ctx context.Context, scopeID, serviceName string) ([]RecipeView, error) {
	s, err := Open(ctx)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	entries, err := loadRecipes(s, scopeID, serviceName)
	if err != nil {
		return nil, err
	}
	approved, err := approvals(s)
	if err != nil {
		return nil, err
	}
	views := make([]RecipeView, 0, len(entries))
	for _, e := range entries {
		results, err := loadResults(s, e.ScopeID, e.Name)
		if err != nil {
			return nil, err
		}
		views = append(views, viewOf(s, e, approved, results))
	}
	return views, nil
}

// ApproveRecipe approves a reviewed recipe with fresh authentication; the
// recipe must still match the reviewed digest.
func ApproveRecipe(ctx context.Context, scopeID, name, reviewedDigest string, auth *agent.UnlockReq) error {
	return approveRecipe(ctx, scopeID, name, reviewedDigest, auth)
}

// RunRecipeList lists recipes, optionally for one service.
func RunRecipeList(ctx context.Context, scopeID, serviceName string, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	entries, err := loadRecipes(s, scopeID, serviceName)
	if err != nil {
		return err
	}
	approved, err := approvals(s)
	if err != nil {
		return err
	}
	if jsonOut {
		views := make([]recipeView, 0, len(entries))
		for _, e := range entries {
			views = append(views, viewOf(s, e, approved, nil))
		}
		return json.NewEncoder(os.Stdout).Encode(views)
	}
	if len(entries) == 0 {
		stderrln("no recipes")
		return nil
	}
	for _, e := range entries {
		targets := ""
		if len(e.Recipe.Targets) > 0 {
			targets = "  targets: " + strings.Join(e.Recipe.Targets, ",")
		}
		fmt.Printf("%-32s %-16s %s%s\n", terminalSafe(e.Name), terminalSafe(scopeName(s, e.ScopeID)), approvalState(e, approved), targets)
	}
	return nil
}

// RunRecipeShow prints a recipe's definition, approval state and the last
// result per target and device. It never prints values.
func RunRecipeShow(ctx context.Context, scopeID, name string, jsonOut bool) error {
	serviceName, _, err := recipe.SplitName(name)
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	rec, err := recipeRecord(s, scopeID, name)
	if err != nil {
		return err
	}
	entries, err := loadRecipes(s, rec.ScopeID, serviceName)
	if err != nil {
		return err
	}
	var entry *recipeEntry
	for i := range entries {
		if entries[i].Name == name {
			entry = &entries[i]
		}
	}
	if entry == nil {
		return fmt.Errorf("recipe %q cannot be used (see the message above)", name)
	}
	approved, err := approvals(s)
	if err != nil {
		return err
	}
	results, err := loadResults(s, entry.ScopeID, name)
	if err != nil {
		return err
	}
	v := viewOf(s, *entry, approved, results)
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	fmt.Printf("%s   %s (%s)\n", terminalSafe(v.Name), v.Approval, terminalSafe(v.Scope))
	if v.Description != "" {
		fmt.Printf("  %s\n", terminalSafe(v.Description))
	}
	printRecipeDefinition(entry.Recipe)
	if len(results) == 0 {
		fmt.Println("  no deploy results yet")
	}
	for _, r := range results {
		target := r.Target
		if target == "" {
			target = "(single run)"
		}
		mark := "✓"
		if r.Status != "ok" {
			mark = fmt.Sprintf("✗ exit %d", r.ExitCode)
		}
		fmt.Printf("  %-16s %s  %s  from %s\n", terminalSafe(target), mark, terminalSafe(r.At), terminalSafe(r.Host))
	}
	return nil
}

func printRecipeDefinition(r *recipe.Recipe) {
	quoted := make([]string, 0, len(r.Command))
	for _, a := range r.Command {
		quoted = append(quoted, shellQuote(a))
	}
	fmt.Printf("  service: %s\n  input:   %s\n  fields:  ", terminalSafe(r.Service), terminalSafe(r.Input))
	parts := make([]string, 0, len(r.Fields))
	for _, m := range r.Fields {
		if m.As != "" {
			parts = append(parts, m.Field+" as "+m.As)
		} else {
			parts = append(parts, m.Field)
		}
	}
	fmt.Println(terminalSafe(strings.Join(parts, ", ")))
	if len(r.Targets) > 0 {
		fmt.Printf("  targets: %s ($FD0_TARGET)\n", terminalSafe(strings.Join(r.Targets, ", ")))
	}
	if r.Dir != "" {
		fmt.Printf("  dir:     %s\n", terminalSafe(r.Dir))
	}
	multiline := false
	for _, arg := range r.Command {
		multiline = multiline || strings.Contains(arg, "\n")
	}
	if !multiline {
		fmt.Printf("  command: %s\n", terminalSafe(strings.Join(quoted, " ")))
		return
	}
	// One argument per line, so a script passed to sh -c is readable before
	// it is approved; each line is still made terminal-safe.
	fmt.Println("  command:")
	for i, arg := range r.Command {
		fmt.Printf("    [%d]", i)
		if !strings.Contains(arg, "\n") {
			fmt.Printf(" %s\n", terminalSafe(shellQuote(arg)))
			continue
		}
		fmt.Println()
		for _, line := range strings.Split(strings.TrimRight(arg, "\n"), "\n") {
			fmt.Printf("      | %s\n", terminalSafe(line))
		}
	}
}

func shellQuote(a string) string {
	if a != "" && strings.IndexFunc(a, func(r rune) bool {
		return !(r == '/' || r == '-' || r == '_' || r == '.' || r == '~' || r == '=' || r == ':' || r == ',' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) < 0 {
		return a
	}
	return "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
}

// RunRecipeRemove tombstones a recipe and its deploy results.
func RunRecipeRemove(ctx context.Context, scopeID, name string, yes bool) error {
	if _, _, err := recipe.SplitName(name); err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	rec, err := recipeRecord(s, scopeID, name)
	if err != nil {
		return err
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove recipe %s? Devices can no longer deploy with it.", name)); err != nil {
		return err
	}
	if err := s.RemoveTypedSecretOfType(ctx, rec.ScopeID, rec.Name, recipe.TypeRecipe); err != nil {
		return err
	}
	stderrln("✓ recipe %s removed", name)
	hintSyncForPeers()
	return nil
}

// RunRecipeApprove shows a recipe and saves this device's approval after
// fresh authentication. Approval means: this device may run exactly this
// command as the current OS user with the selected values.
func RunRecipeApprove(ctx context.Context, scopeID, name, method string) error {
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("run fd0 recipe approve yourself in an interactive terminal; fresh authentication is required")
	}
	serviceName, _, err := recipe.SplitName(name)
	if err != nil {
		return err
	}
	entry, err := func() (*recipeEntry, error) {
		s, err := Open(ctx)
		if err != nil {
			return nil, err
		}
		defer s.Close()
		rec, err := recipeRecord(s, scopeID, name)
		if err != nil {
			return nil, err
		}
		entries, err := loadRecipes(s, rec.ScopeID, serviceName)
		if err != nil {
			return nil, err
		}
		for i := range entries {
			if entries[i].Name == name {
				fmt.Fprintf(os.Stderr, "Approve recipe %s in %s on this device:\n", terminalSafe(name), terminalSafe(scopeName(s, entries[i].ScopeID)))
				return &entries[i], nil
			}
		}
		return nil, fmt.Errorf("recipe %q cannot be used (see the message above)", name)
	}()
	if err != nil {
		return err
	}
	stdout := os.Stdout
	os.Stdout = os.Stderr
	printRecipeDefinition(entry.Recipe)
	os.Stdout = stdout
	fmt.Fprintln(os.Stderr, "This device will run exactly this command as your user, with the selected values,\nwhen you run fd0 service deploy. Any change to the recipe needs a new approval.\nAuthenticate again to approve. Ctrl+C cancels.")
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
	return approveRecipe(ctx, entry.ScopeID, name, entry.Digest,
		&agent.UnlockReq{MethodType: chosen.MethodType, Passphrase: credential.Passphrase, YubikeyPIN: credential.YubikeyPIN})
}

// approveRecipe re-reads the recipe under the vault lock and approves it
// only if it still matches what was shown.
func approveRecipe(ctx context.Context, scopeID, name, reviewed string, auth *agent.UnlockReq) error {
	serviceName, _, err := recipe.SplitName(name)
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	entries, err := loadRecipes(s, scopeID, serviceName)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name != name || e.ScopeID != scopeID {
			continue
		}
		if e.Digest != reviewed {
			return errors.New("the recipe changed while you reviewed it; run fd0 recipe approve again")
		}
		if _, err := s.Agent.RecipeApproval(agent.RecipeApprovalReq{Action: "create", ScopeID: scopeID, Name: name, Digest: reviewed, Authentication: auth}); err != nil {
			return err
		}
		stderrln("✓ recipe %s approved on this device", name)
		return nil
	}
	return fmt.Errorf("recipe %q not found", name)
}

// RunRecipeApprovals lists this device's approvals.
func RunRecipeApprovals(ctx context.Context, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	resp, err := s.Agent.RecipeApproval(agent.RecipeApprovalReq{Action: "list"})
	if err != nil {
		return err
	}
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	if len(resp.Approvals) == 0 {
		stderrln("no recipes approved on this device")
	}
	for _, a := range resp.Approvals {
		fmt.Printf("%-32s %-16s approved %s\n", terminalSafe(a.Name), terminalSafe(scopeName(s, a.ScopeID)), time.Unix(a.ApprovedAt, 0).UTC().Format("2006-01-02"))
	}
	return nil
}

// RunRecipeRevoke removes this device's approval for a recipe.
func RunRecipeRevoke(ctx context.Context, scopeID, name string) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	resp, err := s.Agent.RecipeApproval(agent.RecipeApprovalReq{Action: "list"})
	if err != nil {
		return err
	}
	var hits []proto.RecipeApproval
	for _, a := range resp.Approvals {
		if a.Name == name && (scopeID == "" || a.ScopeID == scopeID || scopeName(s, a.ScopeID) == scopeID) {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 0:
		return fmt.Errorf("recipe %q is not approved on this device", name)
	case 1:
	default:
		return fmt.Errorf("recipe %q is approved in several scopes; pass --scope", name)
	}
	if _, err := s.Agent.RecipeApproval(agent.RecipeApprovalReq{Action: "revoke", ScopeID: hits[0].ScopeID, Name: name}); err != nil {
		return err
	}
	stderrln("✓ approval for %s removed on this device", name)
	return nil
}

// DeployOpts selects what `fd0 service deploy` runs.
type DeployOpts struct {
	Scope   string
	Name    string // SERVICE or SERVICE/NAME
	Target  string // one target of the selected recipe
	Verbose bool
	DryRun  bool // show what would run; run nothing, record nothing
	// Env is merged into every command's environment before the values,
	// for callers whose own environment is not the user's (Desktop).
	Env []string
	// OnResult, when set, receives each target's result as it is known.
	OnResult func(recipe.Result)
}

// deploySync is replaced in tests that run without a server.
var deploySync = func(ctx context.Context) error { return RunSyncPrimary(ctx, "") }

type deployRun struct {
	entry    recipeEntry
	targets  []string
	prepared *recipe.Prepared
	source   string
	approval string
}

// RunServiceDeploy syncs, freezes the selected service values, releases the
// vault lock and runs every selected approved recipe in name order, once per
// target, stopping at the first failure. Results are recorded for the
// scope when the user may write values there.
func RunServiceDeploy(ctx context.Context, o DeployOpts) error {
	serviceName, recipeName := o.Name, ""
	if strings.Contains(o.Name, "/") {
		svc, _, err := recipe.SplitName(o.Name)
		if err != nil {
			return err
		}
		serviceName, recipeName = svc, o.Name
	}
	if o.Target != "" && recipeName == "" {
		return errors.New("--target needs one recipe: fd0 service deploy SERVICE/NAME --target T")
	}
	if o.DryRun {
		return dryRunDeploy(ctx, o, serviceName, recipeName)
	}
	unlock, err := lockDeploys()
	if err != nil {
		return err
	}
	defer unlock()
	// Let an interrupt finish recording the current target's result.
	done := trackCleanup()
	defer done()
	stderrln("↻ syncing before deploy")
	if err := deploySync(ctx); err != nil {
		return fmt.Errorf("deploy: sync failed, nothing was run: %w", err)
	}
	runs, scopeID, err := prepareDeploy(ctx, o, serviceName, recipeName)
	if err != nil {
		return err
	}
	home, err := deviceHome()
	if err != nil {
		return err
	}
	recorder := newResultRecorder(scopeID)
	var failure error
	for _, run := range runs {
		for _, target := range run.targets {
			label := run.entry.Name
			if target != "" {
				label += "  " + target
			}
			// Approval is checked again before every launch, so a revocation
			// or lock during a long deploy stops what has not started yet.
			if err := checkApproval(run.entry); err != nil {
				failure = fmt.Errorf("deploy stopped before %s: %w", label, err)
				break
			}
			code, err := runRecipeCommand(ctx, run, target, home, o.Verbose, o.Env)
			res := recipe.Result{Recipe: run.entry.Name, Target: target, Digest: run.entry.Digest, Source: run.source,
				Status: "ok", ExitCode: code, At: recipe.Now().Format("2006-01-02T15:04:05Z")}
			if err != nil {
				res.Status = "failed"
				stderrln("▶ %-36s ✗ %v", terminalSafe(label), err)
				failure = fmt.Errorf("deploy stopped at %s", label)
			} else {
				stderrln("▶ %-36s ✓ command succeeded", terminalSafe(label))
			}
			recorder.record(res)
			if o.OnResult != nil {
				o.OnResult(res)
			}
			if failure != nil {
				break
			}
		}
		if failure != nil {
			break
		}
	}
	recorder.share()
	return failure
}

// dryRunDeploy syncs and prints what a deploy would run, per recipe and
// target, without running or recording anything. It never prints values.
func dryRunDeploy(ctx context.Context, o DeployOpts, serviceName, recipeName string) error {
	stderrln("↻ syncing before dry run")
	if err := deploySync(ctx); err != nil {
		return fmt.Errorf("deploy: sync failed: %w", err)
	}
	runs, scopeID, err := prepareDeploy(ctx, o, serviceName, recipeName)
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	results := map[string][]recipe.Result{}
	for _, run := range runs {
		results[run.entry.Name], _ = loadResults(s, scopeID, run.entry.Name)
	}
	s.Close()
	fmt.Println("Dry run: nothing is executed or recorded.")
	for _, run := range runs {
		fmt.Printf("\n%s   %s\n", terminalSafe(run.entry.Name), run.approval)
		printRecipeDefinition(run.entry.Recipe)
		size := len(run.prepared.Data)
		for _, kv := range run.prepared.Env {
			size += len(kv)
		}
		fmt.Printf("  would deliver %d bytes via %s from service event %s\n", size, run.prepared.Channel, shortEvent(run.source))
		for _, t := range run.targets {
			if t == "" {
				t = "(single run)"
			}
			fmt.Printf("  would run: %s\n", terminalSafe(t))
		}
		if len(results[run.entry.Name]) == 0 && len(run.targets) > 1 && o.Target == "" {
			fmt.Printf("  never deployed: try one target first, e.g. fd0 service deploy %s --target %s\n", terminalSafe(run.entry.Name), terminalSafe(run.targets[0]))
		}
	}
	return nil
}

func shortEvent(id string) string {
	if len(id) > 12 {
		return id[:12] + "…"
	}
	return id
}

// lockDeploys allows one deploy at a time on this device, so an older run
// cannot overwrite a newer run's results. It is separate from the vault
// lock, which is released while commands run.
func lockDeploys() (func(), error) {
	paths, err := fdhome.Resolve()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(paths.Home, "deploy.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another fd0 service deploy is running on this device")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func checkApproval(e recipeEntry) error {
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	resp, err := agent.NewClient(paths.AgentSock).RecipeApproval(agent.RecipeApprovalReq{Action: "list"})
	if err != nil {
		return err
	}
	for _, a := range resp.Approvals {
		if a.ScopeID == e.ScopeID && a.Name == e.Name && a.Digest == e.Digest {
			return nil
		}
	}
	return errors.New("approval was revoked or changed")
}

func prepareDeploy(ctx context.Context, o DeployOpts, serviceName, recipeName string) ([]deployRun, string, error) {
	s, err := Open(ctx)
	if err != nil {
		return nil, "", err
	}
	defer s.Close() // released before any command runs
	svcRec, err := s.GetTypedSecret(o.Scope, serviceNamePrefix+serviceName)
	if err != nil {
		return nil, "", fmt.Errorf("deploy: service %q: %w", serviceName, err)
	}
	svc, err := decodeServiceRecord(*svcRec)
	if err != nil {
		return nil, "", err
	}
	entries, unusable, err := loadRecipesChecked(s, svcRec.ScopeID, serviceName)
	if err != nil {
		return nil, "", err
	}
	for _, name := range unusable {
		if recipeName == "" || name == recipeName {
			return nil, "", fmt.Errorf("deploy: recipe %s cannot be used (see above); fix or remove it, nothing was run", name)
		}
	}
	approved, err := approvals(s)
	if err != nil {
		return nil, "", err
	}
	var runs []deployRun
	for _, e := range entries {
		if recipeName != "" && e.Name != recipeName {
			continue
		}
		state := approvalState(e, approved)
		if state != "approved on this device" && !o.DryRun {
			return nil, "", fmt.Errorf("deploy: recipe %s is %s; review it with: fd0 recipe approve %s", e.Name, state, e.Name)
		}
		prepared, err := e.Recipe.Prepare(svc)
		if err != nil {
			return nil, "", err
		}
		targets := e.Recipe.Targets
		if len(targets) == 0 {
			targets = []string{""}
		}
		if o.Target != "" {
			found := false
			for _, t := range targets {
				found = found || t == o.Target
			}
			if !found {
				return nil, "", fmt.Errorf("deploy: recipe %s has no target %q", e.Name, o.Target)
			}
			targets = []string{o.Target}
		}
		runs = append(runs, deployRun{entry: e, targets: targets, prepared: prepared, source: svcRec.Revision, approval: state})
	}
	if len(runs) == 0 {
		if recipeName != "" {
			return nil, "", fmt.Errorf("deploy: recipe %q not found", recipeName)
		}
		return nil, "", fmt.Errorf("deploy: service %q has no recipes (fd0 recipe add %s/NAME …)", serviceName, serviceName)
	}
	return runs, svcRec.ScopeID, nil
}

// runRecipeCommand runs one target without a terminal. Output is discarded
// unless verbose, because commands can echo the values they receive.
func runRecipeCommand(ctx context.Context, run deployRun, target, home string, verbose bool, extraEnv []string) (int, error) {
	r := run.entry.Recipe
	argv := append([]string(nil), r.Command...)
	argv[0] = recipe.ExpandHome(argv[0], home)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if r.Dir != "" {
		cmd.Dir = recipe.ExpandHome(r.Dir, home)
	} else {
		cmd.Dir = home
	}
	// fd0's own variables are set last and never inherited, so neither the
	// caller's environment nor a value can redirect a command.
	base := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "FD0_TARGET=") && !strings.HasPrefix(kv, "FD0_SERVICE=") && !strings.HasPrefix(kv, "FD0_RECIPE=") && !strings.HasPrefix(kv, "FD0_INPUT=") {
			base = append(base, kv)
		}
	}
	meta := []string{"FD0_SERVICE=" + r.Service, "FD0_RECIPE=" + run.entry.Name}
	if target != "" {
		meta = append(meta, "FD0_TARGET="+target)
	}
	if run.prepared.Channel == recipe.ChannelFD3 {
		meta = append(meta, "FD0_INPUT=/dev/fd/3")
	}
	cmd.Env = mergeEnv(mergeEnv(mergeEnv(base, extraEnv), run.prepared.Env), meta)
	var inputPipe *os.File
	switch run.prepared.Channel {
	case recipe.ChannelStdin:
		cmd.Stdin = bytes.NewReader(run.prepared.Data)
	case recipe.ChannelFD3:
		// The value goes to fd 3 and stdin stays /dev/null, so nothing the
		// script starts first can read it by accident.
		rd, wr, err := os.Pipe()
		if err != nil {
			return -1, fmt.Errorf("command did not run: %v", err)
		}
		cmd.ExtraFiles = []*os.File{rd}
		data := run.prepared.Data
		written := make(chan struct{})
		go func() {
			defer close(written)
			_, _ = wr.Write(data)
			wr.Close() // EOF for a reader that reads to the end
		}()
		// A descendant may keep fd 3 open without reading it: closing the
		// write end when the command is done unblocks the writer, so neither
		// the goroutine nor the buffered value outlives the command.
		defer func() {
			wr.Close()
			<-written
		}()
		defer rd.Close()
		inputPipe = rd
	}
	// A descendant that keeps stdin open must not hold a finished command.
	cmd.WaitDelay = 3 * time.Second
	// Without verbose, stdout and stderr stay nil: the command writes straight
	// to /dev/null, so no pipe can keep a finished command waiting.
	if verbose {
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	}
	err := cmd.Start()
	if err == nil {
		// Only the child holds fd 3 now: if it exits without reading, the
		// writer above gets EPIPE instead of blocking.
		if inputPipe != nil {
			inputPipe.Close()
		}
		err = cmd.Wait()
	}
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), fmt.Errorf("command failed (exit %d)", exit.ExitCode())
	}
	return -1, fmt.Errorf("command did not run: %v", err)
}

// resultRecorder writes each target's result as soon as it is known, so an
// interrupted deploy keeps the results of what already ran, then shares them
// with one best-effort sync. Readers keep results on screen only.
type resultRecorder struct {
	scopeID string
	device  string
	host    string
	skip    bool
	wrote   bool
}

func newResultRecorder(scopeID string) *resultRecorder {
	r := &resultRecorder{scopeID: scopeID}
	paths, err := fdhome.Resolve()
	if err == nil {
		r.device, err = fdhome.EnsureDeviceID(paths.Config)
	}
	if err != nil {
		stderrln("⚠ results not recorded: %v", err)
		r.skip = true
	}
	r.host, _ = os.Hostname()
	return r
}

func (r *resultRecorder) record(res recipe.Result) {
	if r.skip {
		return
	}
	// A fresh, bounded context: the command context may already be cancelled
	// by an interrupt, and the result of what ran must still be saved.
	// WaitDelay plus this budget fits the interrupt cleanup window; saving is
	// still best effort when the vault is busy.
	ctx, cancel := context.WithTimeout(context.Background(), InterruptCleanupWindow-5*time.Second)
	defer cancel()
	res.Device, res.Host = r.device, r.host
	if err := r.write(ctx, res); err != nil {
		stderrln("⚠ result for %s not recorded: %v", terminalSafe(res.Recipe), err)
		return
	}
	if !r.skip {
		r.wrote = true
	}
}

func (r *resultRecorder) write(ctx context.Context, res recipe.Result) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.replayAndCheckScope(r.scopeID)
	if err != nil {
		return err
	}
	if err := s.requireValueWrite(r.scopeID, st); err != nil {
		r.skip = true
		stderrln("  results stay on screen only: %v", err)
		return nil
	}
	name := resultNamePrefix + recipe.ResultName(res.Recipe, res.Target, r.device)
	if _, err := s.GetTypedSecret(r.scopeID, name); err == nil {
		return s.UpdateTypedSecret(ctx, r.scopeID, name, recipe.TypeResult, recipe.TypeResult, res)
	} else if !errors.Is(err, ErrTypedSecretNotFound) {
		return err
	}
	return s.CreateTypedSecret(ctx, r.scopeID, name, recipe.TypeResult, res)
}

func (r *resultRecorder) share() {
	if !r.wrote {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := deploySync(ctx); err != nil {
		stderrln("⚠ results saved on this device; share them with fd0 sync: %v", err)
	}
}

func loadResults(s *Session, scopeID, recipeName string) ([]recipe.Result, error) {
	recs, err := s.ListTypedSecrets(scopeID, recipe.TypeResult)
	if err != nil {
		return nil, err
	}
	out := []recipe.Result{}
	for _, rec := range recs {
		if !strings.HasPrefix(rec.Name, resultNamePrefix+recipeName+"/") {
			continue
		}
		raw, err := rec.PayloadJSON()
		if err != nil {
			continue
		}
		res, err := recipe.DecodeResult(raw)
		if err != nil || res.Recipe != recipeName || !res.Consistent(strings.TrimPrefix(rec.Name, resultNamePrefix)) {
			continue
		}
		out = append(out, *res)
	}
	recipe.SortResults(out)
	return out, nil
}

// servicesRecipeNames reports recipe names that depend on a service, for
// operations that would orphan them.
func servicesRecipeNames(s *Session, scopeID, serviceName string) []string {
	recs, err := s.ListTypedSecrets(scopeID, "")
	if err != nil {
		return nil
	}
	names := []string{}
	for _, rec := range recs {
		if name, ok := strings.CutPrefix(rec.Name, recipeNamePrefix+serviceName+"/"); ok {
			names = append(names, serviceName+"/"+name)
		}
	}
	sort.Strings(names)
	return names
}

