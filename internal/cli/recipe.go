package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
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

func (o RecipeOpts) recipe(serviceName string) (*recipe.Recipe, error) {
	r := &recipe.Recipe{Version: recipe.Version, Service: serviceName, Command: o.Command, Dir: o.Dir,
		Input: o.Input, Targets: o.Targets, Description: o.Description}
	if len(r.Command) > 0 && r.Command[0] == "--" {
		r.Command = r.Command[1:]
	}
	for _, spec := range o.Fields {
		field, as, _ := strings.Cut(spec, "=")
		r.Fields = append(r.Fields, recipe.Mapping{Field: field, As: as})
	}
	return r, r.Validate()
}

// RunRecipeAdd creates a recipe, or replaces one when edit is true.
func RunRecipeAdd(ctx context.Context, o RecipeOpts, edit bool) error {
	serviceName, _, err := recipe.SplitName(o.Name)
	if err != nil {
		return err
	}
	r, err := o.recipe(serviceName)
	if err != nil {
		return err
	}
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

// loadRecipes returns valid recipes, optionally limited to one service and
// scope, sorted by name. Malformed recipes are reported, never run.
func loadRecipes(s *Session, scopeID, serviceName string) ([]recipeEntry, error) {
	recs, err := s.ListTypedSecrets(scopeID, recipe.TypeRecipe)
	if err != nil {
		return nil, err
	}
	out := []recipeEntry{}
	for _, rec := range recs {
		name := strings.TrimPrefix(rec.Name, recipeNamePrefix)
		if serviceName != "" && !strings.HasPrefix(name, serviceName+"/") {
			continue
		}
		r, err := decodeRecipeRecord(rec)
		if err != nil {
			stderrln("  ! recipe %s in %s cannot be used: %v", terminalSafe(name), scopeName(s, rec.ScopeID), err)
			continue
		}
		if svc, _, err := recipe.SplitName(name); err != nil || svc != r.Service {
			stderrln("  ! recipe %s in %s names service %q; ignoring it", terminalSafe(name), scopeName(s, rec.ScopeID), r.Service)
			continue
		}
		out = append(out, recipeEntry{Name: name, ScopeID: rec.ScopeID, Record: rec, Recipe: r, Digest: recipe.Digest(rec.ScopeID, name, r)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ScopeID != out[j].ScopeID {
			return out[i].ScopeID < out[j].ScopeID
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
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
		fmt.Printf("  %-16s %s  %s  from %s\n", terminalSafe(target), mark, r.At, terminalSafe(r.Host))
	}
	return nil
}

func printRecipeDefinition(r *recipe.Recipe) {
	quoted := make([]string, 0, len(r.Command))
	for _, a := range r.Command {
		quoted = append(quoted, shellQuote(a))
	}
	fmt.Printf("  service: %s\n  input:   %s\n  fields:  ", terminalSafe(r.Service), r.Input)
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
	fmt.Printf("  command: %s\n", terminalSafe(strings.Join(quoted, " ")))
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
}

// deploySync is replaced in tests that run without a server.
var deploySync = func(ctx context.Context) error { return RunSyncPrimary(ctx, "") }

type deployRun struct {
	entry    recipeEntry
	targets  []string
	prepared *recipe.Prepared
	source   string
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
	stderrln("↻ syncing before deploy")
	if err := deploySync(ctx); err != nil {
		return fmt.Errorf("deploy: sync failed, nothing was run: %w", err)
	}
	runs, scopeID, err := prepareDeploy(ctx, o, serviceName, recipeName)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	results := []recipe.Result{}
	var failure error
	for _, run := range runs {
		for _, target := range run.targets {
			label := run.entry.Name
			if target != "" {
				label += "  " + target
			}
			code, err := runRecipeCommand(ctx, run, target, home, o.Verbose)
			res := recipe.Result{Recipe: run.entry.Name, Target: target, Digest: run.entry.Digest, Source: run.source,
				Status: "ok", ExitCode: code, At: recipe.Now().Format("2006-01-02T15:04:05Z")}
			if err != nil {
				res.Status = "failed"
				stderrln("▶ %-36s ✗ %v", terminalSafe(label), err)
				results = append(results, res)
				failure = fmt.Errorf("deploy stopped at %s", label)
				break
			}
			stderrln("▶ %-36s ✓ command succeeded", terminalSafe(label))
			results = append(results, res)
		}
		if failure != nil {
			break
		}
	}
	if err := recordResults(ctx, scopeID, results); err != nil {
		stderrln("⚠ results not recorded: %v", err)
	}
	return failure
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
	entries, err := loadRecipes(s, svcRec.ScopeID, serviceName)
	if err != nil {
		return nil, "", err
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
		if state := approvalState(e, approved); state != "approved on this device" {
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
		runs = append(runs, deployRun{entry: e, targets: targets, prepared: prepared, source: svcRec.Revision})
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
func runRecipeCommand(ctx context.Context, run deployRun, target, home string, verbose bool) (int, error) {
	r := run.entry.Recipe
	argv := append([]string(nil), r.Command...)
	argv[0] = recipe.ExpandHome(argv[0], home)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if r.Dir != "" {
		cmd.Dir = recipe.ExpandHome(r.Dir, home)
	} else {
		cmd.Dir = home
	}
	extra := []string{"FD0_SERVICE=" + r.Service, "FD0_RECIPE=" + run.entry.Name}
	if target != "" {
		extra = append(extra, "FD0_TARGET="+target)
	}
	extra = append(extra, run.prepared.Env...)
	cmd.Env = mergeEnv(os.Environ(), extra)
	if run.prepared.Stdin != nil {
		cmd.Stdin = bytes.NewReader(run.prepared.Stdin)
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if verbose {
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	}
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), fmt.Errorf("command failed (exit %d)", exit.ExitCode())
	}
	return -1, fmt.Errorf("command did not run: %v", err)
}

// recordResults writes one result record per target for this device and
// shares them with a best-effort sync. Readers keep no shared results.
func recordResults(ctx context.Context, scopeID string, results []recipe.Result) error {
	if len(results) == 0 {
		return nil
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	device, err := fdhome.EnsureDeviceID(paths.Config)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	st, err := s.replayAndCheckScope(scopeID)
	if err != nil {
		s.Close()
		return err
	}
	if err := s.requireValueWrite(scopeID, st); err != nil {
		s.Close()
		stderrln("  results stay on screen only: %v", err)
		return nil
	}
	for _, res := range results {
		res.Device, res.Host = device, host
		name := resultNamePrefix + recipe.ResultName(res.Recipe, res.Target, device)
		if _, err := s.GetTypedSecret(scopeID, name); err == nil {
			err = s.UpdateTypedSecret(ctx, scopeID, name, recipe.TypeResult, recipe.TypeResult, res)
			if err != nil {
				s.Close()
				return err
			}
		} else if errors.Is(err, ErrTypedSecretNotFound) {
			if err := s.CreateTypedSecret(ctx, scopeID, name, recipe.TypeResult, res); err != nil {
				s.Close()
				return err
			}
		} else {
			s.Close()
			return err
		}
	}
	s.Close()
	if err := deploySync(ctx); err != nil {
		return fmt.Errorf("results saved locally; share them with fd0 sync: %w", err)
	}
	return nil
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
		if err != nil || res.Recipe != recipeName {
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
	entries, err := loadRecipes(s, scopeID, serviceName)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
}

