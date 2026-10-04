// Package recipe models deploy recipes for services (docs/SERVICES_PLAN.md,
// phase 3): a saved local command that receives selected service fields on
// stdin or in its environment, optionally once per named target.
//
// A recipe is shared in its scope, so it is code that another member can
// write. Devices run a recipe only after approving its exact definition; the
// digest below is what an approval pins. Nothing here runs commands.
package recipe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/valentinkolb/fd0.sh/internal/service"
)

const (
	// TypeRecipe identifies a recipe record's payload.
	TypeRecipe = "fd0.recipe"
	// TypeResult identifies a deploy result record's payload.
	TypeResult = "fd0.deploy-result"
	// Version is the recipe schema this build understands. Newer recipes are
	// refused rather than run with fields this build would ignore.
	Version = 1
)

// Input modes. Values reach a command only through stdin or its environment,
// never through its arguments.
const (
	InputEnv        = "env"
	InputSystemdEnv = "stdin:systemd-env"
	InputDockerEnv  = "stdin:docker-env"
	InputShell      = "stdin:sh"
	InputFile       = "stdin:file"
	inputK8sPrefix  = "stdin:k8s-secret:"
)

const (
	maxArgs       = 64
	maxArgBytes   = 16 * 1024
	maxTargets    = 64
	maxFields     = service.MaxFields
	maxRecipeSize = 32 * 1024
)

var (
	nameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	envRE    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
	k8sKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// Mapping selects one service field and optionally renames it: the
// environment variable name for env-style inputs, the Secret key for
// Kubernetes. An empty As uses the field's env name or, for Kubernetes, the
// field name.
type Mapping struct {
	Field string `json:"field"`
	As    string `json:"as,omitempty"`
}

// Recipe is the stored payload. The record name is "SERVICE/NAME"; Service
// repeats the service name so the payload alone says what it reads.
type Recipe struct {
	Version     int       `json:"version"`
	Service     string    `json:"service"`
	Command     []string  `json:"command"`
	Dir         string    `json:"dir,omitempty"`
	Fields      []Mapping `json:"fields"`
	Input       string    `json:"input"`
	Targets     []string  `json:"targets,omitempty"`
	Description string    `json:"description,omitempty"`
}

// Decode parses a stored recipe, refusing unknown fields and newer versions
// so a device never runs a definition it only partly understands.
func Decode(raw []byte) (*Recipe, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Recipe
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("recipe: decode: %w (update fd0 if this recipe was written by a newer version)", err)
	}
	if r.Version > Version {
		return nil, fmt.Errorf("recipe: version %d is newer than this fd0 understands; update fd0", r.Version)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// SplitName splits "SERVICE/NAME".
func SplitName(full string) (serviceName, name string, err error) {
	serviceName, name, ok := strings.Cut(full, "/")
	if !ok || !nameRE.MatchString(serviceName) || !nameRE.MatchString(name) {
		return "", "", fmt.Errorf("recipe %q: use SERVICE/NAME with letters, digits, '.', '_' or '-'", full)
	}
	return serviceName, name, nil
}

// ValidateTarget checks one target name.
func ValidateTarget(t string) error {
	if !nameRE.MatchString(t) {
		return fmt.Errorf("recipe: invalid target %q (letters, digits, '.', '_' or '-')", t)
	}
	return nil
}

// Validate checks every invariant a stored recipe must hold.
func (r *Recipe) Validate() error {
	if r.Version != Version {
		return fmt.Errorf("recipe: unsupported version %d", r.Version)
	}
	if !nameRE.MatchString(r.Service) {
		return fmt.Errorf("recipe: invalid service name %q", r.Service)
	}
	if len(r.Command) == 0 || len(r.Command) > maxArgs {
		return fmt.Errorf("recipe: command must have 1 to %d arguments", maxArgs)
	}
	for _, a := range r.Command {
		if !utf8.ValidString(a) || strings.ContainsRune(a, 0) || len(a) > maxArgBytes {
			return errors.New("recipe: command arguments must be text without NUL bytes")
		}
	}
	if !isAbsOrHome(r.Command[0]) {
		return fmt.Errorf("recipe: the program %q must be an absolute path or start with ~/ so it does not depend on PATH", r.Command[0])
	}
	if r.Dir != "" && !isAbsOrHome(r.Dir) {
		return fmt.Errorf("recipe: working directory %q must be absolute or start with ~/", r.Dir)
	}
	if len(r.Fields) == 0 || len(r.Fields) > maxFields {
		return fmt.Errorf("recipe: select 1 to %d fields explicitly", maxFields)
	}
	seen := map[string]bool{}
	for _, m := range r.Fields {
		if err := service.ValidateFieldName(m.Field); err != nil {
			return err
		}
		if seen[m.Field] {
			return fmt.Errorf("recipe: field %q selected twice", m.Field)
		}
		seen[m.Field] = true
	}
	if err := r.validateInput(); err != nil {
		return err
	}
	if len(r.Targets) > maxTargets {
		return fmt.Errorf("recipe: at most %d targets", maxTargets)
	}
	targets := map[string]bool{}
	for _, t := range r.Targets {
		if err := ValidateTarget(t); err != nil {
			return err
		}
		if targets[t] {
			return fmt.Errorf("recipe: target %q listed twice", t)
		}
		targets[t] = true
	}
	if !utf8.ValidString(r.Description) || len(r.Description) > 1024 {
		return errors.New("recipe: description must be valid text up to 1024 bytes")
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > maxRecipeSize {
		return fmt.Errorf("recipe: too large (%d bytes > %d)", len(raw), maxRecipeSize)
	}
	return nil
}

func (r *Recipe) validateInput() error {
	switch r.Input {
	case InputEnv, InputSystemdEnv, InputDockerEnv, InputShell:
		names := map[string]bool{}
		for _, m := range r.Fields {
			// Names are stored, never taken from the service at run time, so
			// the approval covers exactly which variables a command receives.
			if !envRE.MatchString(m.As) {
				return fmt.Errorf("recipe: field %q needs a valid variable name (FIELD=NAME); got %q", m.Field, m.As)
			}
			if strings.HasPrefix(m.As, "FD0_") {
				return fmt.Errorf("recipe: %s is reserved for fd0", m.As)
			}
			if names[m.As] {
				return fmt.Errorf("recipe: variable %s is used twice", m.As)
			}
			names[m.As] = true
		}
		return nil
	case InputFile:
		if len(r.Fields) != 1 || r.Fields[0].As != "" {
			return errors.New("recipe: stdin:file takes exactly one field and no rename")
		}
		return nil
	}
	if ns, name, ok := r.k8sTarget(); ok {
		if ns == "" || name == "" {
			return errors.New("recipe: use stdin:k8s-secret:NAMESPACE/SECRET")
		}
		keys := map[string]bool{}
		for _, m := range r.Fields {
			key := m.As
			if key == "" {
				key = m.Field
			}
			if !k8sKeyRE.MatchString(key) {
				return fmt.Errorf("recipe: %q is not a valid Secret key", key)
			}
			if keys[key] {
				return fmt.Errorf("recipe: Secret key %s is used twice", key)
			}
			keys[key] = true
		}
		return nil
	}
	return fmt.Errorf("recipe: unknown input %q (env, stdin:systemd-env, stdin:docker-env, stdin:sh, stdin:file, stdin:k8s-secret:NS/NAME)", r.Input)
}

func (r *Recipe) k8sTarget() (namespace, name string, ok bool) {
	rest, ok := strings.CutPrefix(r.Input, inputK8sPrefix)
	if !ok {
		return "", "", false
	}
	namespace, name, _ = strings.Cut(rest, "/")
	return namespace, name, true
}

func isAbsOrHome(p string) bool {
	return filepath.IsAbs(p) || strings.HasPrefix(p, "~/")
}

// ExpandHome resolves a leading ~/ against home.
func ExpandHome(p, home string) string {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

// Digest is what a device approval pins: the scope, the recipe's record name
// and every part of the definition that affects what runs or what it
// receives. The description is left out, so editing it needs no new
// approval; anything else does.
//
// home is this device's home directory, against which ~/ and the default
// working directory resolve; a different home needs a new approval.
func Digest(scopeID, recordName string, r *Recipe, home string) string {
	canonical := struct {
		Domain  string    `json:"domain"`
		Home    string    `json:"home"`
		Scope   string    `json:"scope"`
		Name    string    `json:"name"`
		Version int       `json:"version"`
		Service string    `json:"service"`
		Command []string  `json:"command"`
		Dir     string    `json:"dir"`
		Fields  []Mapping `json:"fields"`
		Input   string    `json:"input"`
		Targets []string  `json:"targets"`
	}{"fd0-recipe-approval-v1", home, scopeID, recordName, r.Version, r.Service, r.Command, r.Dir, r.Fields, r.Input, r.Targets}
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ResolveNames fills empty variable names from the service's env names, so a
// saved recipe always states them explicitly.
func (r *Recipe) ResolveNames(svc *service.Service) error {
	switch r.Input {
	case InputEnv, InputSystemdEnv, InputDockerEnv, InputShell:
	default:
		return nil
	}
	for i, m := range r.Fields {
		if m.As != "" {
			continue
		}
		f, err := svc.Field(m.Field)
		if err != nil {
			return fmt.Errorf("recipe: service %q: %w", r.Service, err)
		}
		if f.Env == "" {
			return fmt.Errorf("recipe: field %q has no env name; write it as %s=NAME", m.Field, m.Field)
		}
		r.Fields[i].As = f.Env
	}
	return nil
}

// Prepared is what one run of a recipe hands to its command.
type Prepared struct {
	Stdin []byte   // nil for env input
	Env   []string // KEY=VALUE entries for env input
}

// Prepare renders the selected fields of svc for the recipe's input mode.
func (r *Recipe) Prepare(svc *service.Service) (*Prepared, error) {
	fields := make([]service.Field, 0, len(r.Fields))
	for _, m := range r.Fields {
		f, err := svc.Field(m.Field)
		if err != nil {
			return nil, fmt.Errorf("recipe: service %q: %w", r.Service, err)
		}
		fields = append(fields, *f)
	}
	switch r.Input {
	case InputEnv, InputSystemdEnv, InputDockerEnv, InputShell:
		for i, m := range r.Fields {
			fields[i].Env = m.As
		}
		if r.Input == InputEnv {
			env, err := service.ExecEnv(fields)
			if err != nil {
				return nil, err
			}
			return &Prepared{Env: env}, nil
		}
		out, err := service.RenderEnv(fields, strings.TrimPrefix(r.Input, "stdin:"))
		if err != nil {
			return nil, err
		}
		return &Prepared{Stdin: out}, nil
	case InputFile:
		b, err := fields[0].Bytes()
		if err != nil {
			return nil, err
		}
		return &Prepared{Stdin: b}, nil
	}
	ns, name, _ := r.k8sTarget()
	keys := make([]service.SecretKey, 0, len(r.Fields))
	for _, m := range r.Fields {
		key := m.As
		if key == "" {
			key = m.Field
		}
		keys = append(keys, service.SecretKey{Field: m.Field, Key: key})
	}
	out, err := service.RenderK8sSecret(svc, r.Service, ns, name, keys)
	if err != nil {
		return nil, err
	}
	return &Prepared{Stdin: out}, nil
}

// Result records one target's last run from one device. Only that device
// writes its result record, so results from several devices never conflict.
type Result struct {
	Recipe   string `json:"recipe"`   // SERVICE/NAME
	Target   string `json:"target"`   // empty without targets
	Device   string `json:"device"`   // device ID
	Host     string `json:"host"`     // host name, for people
	Digest   string `json:"digest"`   // approved recipe digest that ran
	Source   string `json:"source"`   // service record event that was delivered
	Status   string `json:"status"`   // "ok" or "failed"
	ExitCode int    `json:"exitCode"` // -1 when the command did not start or was killed
	At       string `json:"at"`       // RFC 3339, UTC
}

// ResultName is the record name of a result, without the kind prefix.
func ResultName(recipeName, target, device string) string {
	if target == "" {
		target = "-"
	}
	return recipeName + "/" + target + "/" + device
}

// DecodeResult parses a stored result. Unknown fields are tolerated: results
// are informational and never executed.
func DecodeResult(raw []byte) (*Result, error) {
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("deploy result: decode: %w", err)
	}
	return &r, nil
}

// Consistent reports whether a result record's payload matches its name, so a
// record cannot claim to be another recipe's, target's or device's result.
func (res *Result) Consistent(recordName string) bool {
	if recordName != ResultName(res.Recipe, res.Target, res.Device) {
		return false
	}
	if _, err := time.Parse(time.RFC3339, res.At); err != nil {
		return false
	}
	switch res.Status {
	case "ok":
		return res.ExitCode == 0
	case "failed":
		return res.ExitCode != 0
	}
	return false
}

// SortResults orders results by target, then newest first.
func SortResults(rs []Result) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Target != rs[j].Target {
			return rs[i].Target < rs[j].Target
		}
		return rs[i].At > rs[j].At
	})
}

// Now is the clock used for result stamps; tests replace it.
var Now = func() time.Time { return time.Now().UTC() }
