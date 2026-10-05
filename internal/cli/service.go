package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/secretgrant"
	"github.com/valentinkolb/fd0.sh/internal/service"
)

const serviceNamePrefix = "service:"

// KindService holds credentials that programs consume (docs/SERVICES_PLAN.md).
var KindService = ItemKind{Noun: "service", Command: "service", Prefix: serviceNamePrefix}

// serviceStdinLimit bounds every stdin read for service values.
const serviceStdinLimit = service.MaxPayloadBytes

func openService(ctx context.Context, scopeID, name string) (*Session, *TypedRecord, *service.Service, error) {
	if err := validItemName(name); err != nil {
		return nil, nil, nil, err
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	rec, err := s.GetTypedSecret(scopeID, serviceNamePrefix+name)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	svc, err := decodeServiceRecord(*rec)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	return s, rec, svc, nil
}

func decodeServiceRecord(r TypedRecord) (*service.Service, error) {
	if r.Type != service.TypeService {
		return nil, fmt.Errorf("%q is %s, not %s", r.Name, r.Type, service.TypeService)
	}
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	return service.Decode(raw)
}

func writeService(ctx context.Context, s *Session, rec *TypedRecord, svc *service.Service) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	return s.UpdateTypedSecret(ctx, rec.ScopeID, rec.Name, service.TypeService, service.TypeService, svc)
}

// readServiceStdin reads a bounded value before any vault lock is taken.
func readServiceStdin(op string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, serviceStdinLimit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read stdin: %w", op, err)
	}
	if len(data) > serviceStdinLimit {
		return nil, fmt.Errorf("%s: stdin exceeds %d bytes", op, serviceStdinLimit)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s: stdin was empty; nothing was changed", op)
	}
	return data, nil
}

// ServiceAddOpts creates an empty service.
type ServiceAddOpts struct {
	Name        string
	Scope       string
	Description string
	Tags        []string
}

func RunServiceAdd(ctx context.Context, o ServiceAddOpts) error {
	if err := validItemName(o.Name); err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scope, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}
	svc := &service.Service{Description: o.Description, Fields: []service.Field{}}
	if err := svc.Validate(); err != nil {
		return err
	}
	if err := s.CreateTypedSecret(ctx, scope, serviceNamePrefix+o.Name, service.TypeService, svc); err != nil {
		return err
	}
	if len(o.Tags) > 0 {
		if err := s.ChangeItemTags(ctx, scope, serviceNamePrefix+o.Name, "add", o.Tags); err != nil {
			return err
		}
	}
	stderrln("✓ service %q created in %s", o.Name, scopeName(s, scope))
	hintSyncForPeers()
	return nil
}

type serviceListRow struct {
	Name        string   `json:"name"`
	ScopeID     string   `json:"scopeId"`
	Scope       string   `json:"scope"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags"`
	Fields      int      `json:"fields"`
}

func RunServiceList(ctx context.Context, scopeID string, jsonOut bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	recs, err := s.ListTypedSecrets(scopeID, service.TypeService)
	if err != nil {
		return err
	}
	rows := []serviceListRow{}
	for _, r := range recs {
		svc, err := decodeServiceRecord(r)
		if err != nil {
			stderrln("  ! malformed service %q in scope %s: %v", r.Name, scopeName(s, r.ScopeID), err)
			continue
		}
		tags := r.OrganizationTags
		if tags == nil {
			tags = []string{}
		}
		rows = append(rows, serviceListRow{
			Name: strings.TrimPrefix(r.Name, serviceNamePrefix), ScopeID: r.ScopeID, Scope: scopeName(s, r.ScopeID),
			Description: svc.Description, Tags: tags, Fields: len(svc.Fields),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Scope != rows[j].Scope {
			return rows[i].Scope < rows[j].Scope
		}
		return rows[i].Name < rows[j].Name
	})
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	if len(rows) == 0 {
		stderrln("no services")
		return nil
	}
	for _, r := range rows {
		fmt.Printf("%-28s %-18s %2d fields  %s\n", r.Name, r.Scope, r.Fields, r.Description)
	}
	return nil
}

type serviceShowJSON struct {
	Name        string            `json:"name"`
	ScopeID     string            `json:"scopeId"`
	Scope       string            `json:"scope"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags"`
	Fields      []service.Summary `json:"fields"`
}

// RunServiceShow prints metadata and text values; secret and file values are
// never printed here.
func RunServiceShow(ctx context.Context, scopeID, name string, jsonOut bool) error {
	s, rec, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	tags := rec.OrganizationTags
	if tags == nil {
		tags = []string{}
	}
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(serviceShowJSON{
			Name: name, ScopeID: rec.ScopeID, Scope: scopeName(s, rec.ScopeID),
			Description: svc.Description, Tags: tags, Fields: svc.Summaries(),
		})
	}
	fmt.Println("name        :", name)
	fmt.Println("scope       :", scopeName(s, rec.ScopeID))
	if svc.Description != "" {
		fmt.Println("description :", svc.Description)
	}
	if len(tags) > 0 {
		fmt.Println("tags        :", strings.Join(tags, ", "))
	}
	if len(svc.Fields) == 0 {
		fmt.Println("fields      : none")
		return nil
	}
	fmt.Println("fields      :")
	for _, f := range svc.Summaries() {
		value := "••••••"
		if f.Type == service.FieldText {
			field, _ := svc.Field(f.Name)
			value = field.Value
		} else if f.Type == service.FieldFile {
			value = fmt.Sprintf("(%d bytes)", f.Bytes)
		}
		env := ""
		if f.Env != "" {
			env = "env " + f.Env
		}
		fmt.Printf("  %-26s %-6s %-30s %-28s changed %s\n", f.Name, f.Type, value, env, f.ChangedAt)
	}
	return nil
}

// RunServiceEdit changes the description.
func RunServiceEdit(ctx context.Context, scopeID, name string, description *string) error {
	if description == nil {
		return errors.New("service edit: nothing to change (use --description)")
	}
	s, rec, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	if svc.Description == *description {
		stderrln("service %q unchanged", name)
		return nil
	}
	svc.Description = *description
	if err := writeService(ctx, s, rec, svc); err != nil {
		return err
	}
	stderrln("✓ service %q updated", name)
	hintSyncForPeers()
	return nil
}

func RunServiceRename(ctx context.Context, scopeID, oldName, newName string, force bool) error {
	if err := validItemName(oldName); err != nil {
		return err
	}
	if err := validItemName(newName); err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := refuseWithRecipes(s, scopeID, oldName, "rename"); err != nil {
		return err
	}
	return s.RenameItem(ctx, KindService, scopeID, oldName, newName, force, nil)
}

func RunServiceMove(ctx context.Context, name, fromScope, toScope string, force bool) error {
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := refuseWithRecipes(s, fromScope, name, "move"); err != nil {
		return err
	}
	return s.MoveItem(ctx, KindService, name, fromScope, toScope, force)
}

func RunServiceRemove(ctx context.Context, scopeID, name string, yes bool) error {
	s, rec, _, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	if names := servicesRecipeNames(s, rec.ScopeID, name); len(names) > 0 {
		stderrln("⚠ recipes %s use this service and stop working without it", strings.Join(names, ", "))
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove service %q from %s?", name, scopeName(s, rec.ScopeID))); err != nil {
		return err
	}
	if err := s.RemoveTypedSecretOfType(ctx, rec.ScopeID, rec.Name, service.TypeService); err != nil {
		return err
	}
	stderrln("✓ service %q removed from %s", name, scopeName(s, rec.ScopeID))
	hintSyncForPeers()
	return nil
}

// RunServiceRestore restores an earlier version and stamps every field as
// changed now, so a restored old value is visible as a change.
func RunServiceRestore(ctx context.Context, scopeID, name string, seq uint64) error {
	if err := RunItemRestore(ctx, KindService, scopeID, name, seq); err != nil {
		return err
	}
	s, rec, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	svc.Restamp(nowFunc())
	return writeService(ctx, s, rec, svc)
}

// ServiceSetOpts writes one field from stdin, or every line of an env file.
type ServiceSetOpts struct {
	Name    string
	Scope   string
	Field   string
	Type    string
	Env     string
	EnvFile bool
}

func RunServiceSet(ctx context.Context, o ServiceSetOpts) error {
	if o.EnvFile {
		if o.Field != "" || o.Type != "" || o.Env != "" {
			return errors.New("service set: --env-file cannot be combined with FIELD, --type or --env")
		}
	} else {
		if err := service.ValidateFieldName(o.Field); err != nil {
			return err
		}
		if o.Env != "" {
			if err := service.ValidateEnvName(o.Env); err != nil {
				return err
			}
		}
	}
	data, err := readServiceStdin("service set")
	if err != nil {
		return err
	}
	s, rec, svc, err := openService(ctx, o.Scope, o.Name)
	if err != nil {
		return err
	}
	defer s.Close()
	now := nowFunc()
	changed := false
	if o.EnvFile {
		pairs, err := service.ParseEnvFile(data)
		if err != nil {
			return err
		}
		for _, pair := range pairs {
			c, err := svc.Set(service.FieldNameForEnv(pair[0]), "", []byte(pair[1]), pair[0], now)
			if err != nil {
				return err
			}
			changed = changed || c
		}
	} else {
		value := data
		if o.Type != service.FieldFile && len(value) > 0 && value[len(value)-1] == '\n' {
			value = value[:len(value)-1]
		}
		if len(value) == 0 {
			return errors.New("service set: value is empty; nothing was changed")
		}
		if changed, err = svc.Set(o.Field, o.Type, value, o.Env, now); err != nil {
			return err
		}
	}
	if !changed {
		stderrln("service %q unchanged", o.Name)
		return nil
	}
	if err := writeService(ctx, s, rec, svc); err != nil {
		return err
	}
	if o.EnvFile {
		stderrln("✓ env fields set on service %q", o.Name)
	} else {
		stderrln("✓ field %q set on service %q", o.Field, o.Name)
	}
	hintSyncForPeers()
	return nil
}

// RunServiceFieldRemove deletes one field.
func RunServiceFieldRemove(ctx context.Context, scopeID, name, field string, yes bool) error {
	s, rec, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := confirmDanger(yes, fmt.Sprintf("Remove field %q from service %q?", field, name)); err != nil {
		return err
	}
	if err := svc.Remove(field); err != nil {
		return err
	}
	if err := writeService(ctx, s, rec, svc); err != nil {
		return err
	}
	stderrln("✓ field %q removed from service %q", field, name)
	hintSyncForPeers()
	return nil
}

// RunServiceGet prints one value. Without --raw a trailing newline is added
// for terminals.
func RunServiceGet(ctx context.Context, scopeID, name, field string, raw bool) error {
	s, _, svc, err := openService(ctx, scopeID, name)
	if errors.Is(err, ErrAgentLocked) {
		v, gerr := grantedValue(secretgrant.KindService, scopeID, name, field)
		if gerr != nil {
			return gerr
		}
		defer crypto.Wipe(v)
		printValue(v, raw)
		return nil
	}
	if err != nil {
		return err
	}
	defer s.Close()
	f, err := svc.Field(field)
	if err != nil {
		return err
	}
	value, err := f.Bytes()
	if err != nil {
		return err
	}
	if f.Type == service.FieldFile && IsTTY(os.Stdout) {
		return errors.New("service get: refusing to print a file field to a terminal; pipe or redirect stdout")
	}
	if _, err := os.Stdout.Write(value); err != nil {
		return err
	}
	if !raw && f.Type != service.FieldFile {
		fmt.Println()
	}
	return nil
}

func refuseTerminal(op string) error {
	if IsTTY(os.Stdout) {
		return fmt.Errorf("%s: refusing to print values to a terminal; pipe or redirect stdout", op)
	}
	return nil
}

// RunServiceEnv renders env-named fields in one dialect.
func RunServiceEnv(ctx context.Context, scopeID, name string, fields []string, dialect string) error {
	if err := refuseTerminal("service env"); err != nil {
		return err
	}
	s, _, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	selected, err := svc.Select(fields)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		return fmt.Errorf("service env: %q has no fields with env names", name)
	}
	out, err := service.RenderEnv(selected, dialect)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

// RunServiceExec replaces fd0 with command, adding the selected fields to
// the environment (docs/SERVICES_PLAN.md, phase 2). The vault lock is
// released first; signals and the exit status belong to the command.
func RunServiceExec(ctx context.Context, scopeID, name string, fields []string, command []string) error {
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}
	if len(command) == 0 {
		return errors.New("run: missing command after --")
	}
	bin, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	add, err := serviceRunEnv(ctx, scopeID, name, fields)
	if err != nil {
		return err
	}
	return syscall.Exec(bin, command, mergeEnv(os.Environ(), add))
}

// serviceRunEnv returns the KEY=VALUE entries fd0 run adds; the session and
// its lock are closed before it returns.
func serviceRunEnv(ctx context.Context, scopeID, name string, fields []string) ([]string, error) {
	s, _, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	selected, err := svc.Select(fields)
	if err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("run: %q has no fields with env names", name)
	}
	return service.ExecEnv(selected)
}

// mergeEnv returns base with every variable in add set, replacing earlier
// values of the same name.
func mergeEnv(base, add []string) []string {
	names := make(map[string]bool, len(add))
	for _, kv := range add {
		names[kv[:strings.IndexByte(kv, '=')]] = true
	}
	out := make([]string, 0, len(base)+len(add))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && names[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, add...)
}

// RunServiceK8sSecret renders an Opaque Secret manifest.
func RunServiceK8sSecret(ctx context.Context, scopeID, name, namespace, secretName string, keys []string) error {
	if err := refuseTerminal("service k8s-secret"); err != nil {
		return err
	}
	parsed, err := service.ParseSecretKeys(keys)
	if err != nil {
		return err
	}
	s, _, svc, err := openService(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	out, err := service.RenderK8sSecret(svc, name, namespace, secretName, parsed)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

// refuseWithRecipes stops a rename or move that would orphan recipes: a
// recipe names its service and its approvals pin the scope.
func refuseWithRecipes(s *Session, scopeID, name, verb string) error {
	if names := servicesRecipeNames(s, scopeID, name); len(names) > 0 {
		return fmt.Errorf("service %q has recipes (%s); remove them before you %s it, then add and approve them again", name, strings.Join(names, ", "), verb)
	}
	return nil
}
