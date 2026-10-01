// Package service models credentials that programs consume: one record per
// service holding typed fields, optional environment names and change stamps.
// Rendering helpers turn a service into environment files or a Kubernetes
// Secret manifest for the operator's own pipelines; nothing here talks to a
// network or a cluster.
package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// TypeService identifies a service record's payload.
const TypeService = "fd0.service"

// Field types. A field keeps its type for its whole life; updates never
// change it implicitly.
const (
	FieldSecret = "secret"
	FieldText   = "text"
	FieldFile   = "file"
)

const (
	// MaxFields bounds a service so it stays small and readable.
	MaxFields = 64
	// MaxValueBytes caps one field value (file content before encoding).
	MaxValueBytes = 16 * 1024
	// MaxPayloadBytes keeps the encoded payload well under the server's
	// 64 KB limit for one encrypted record, leaving room for CBOR framing
	// and encryption overhead.
	MaxPayloadBytes = 40 * 1024
)

var (
	fieldNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	envNameRE   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
)

// Field is one credential or setting. File values are stored base64-encoded
// so arbitrary bytes survive the JSON payload.
type Field struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Env       string `json:"env,omitempty"`
	Note      string `json:"note,omitempty"`
	ChangedAt string `json:"changedAt"`
	Revision  int    `json:"revision"`
}

// Service is the stored payload. The record name and scope are the record's
// location, not part of the payload, so move and rename copy it verbatim.
type Service struct {
	Description string  `json:"description,omitempty"`
	Fields      []Field `json:"fields"`
}

// Decode parses and validates a stored payload.
func Decode(raw []byte) (*Service, error) {
	var s Service
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("service: decode: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks every invariant a stored service must hold.
func (s *Service) Validate() error {
	if len(s.Fields) > MaxFields {
		return fmt.Errorf("service: too many fields (%d > %d)", len(s.Fields), MaxFields)
	}
	if !utf8.ValidString(s.Description) || len(s.Description) > 1024 {
		return errors.New("service: description must be valid text up to 1024 bytes")
	}
	names := map[string]bool{}
	envs := map[string]string{}
	for _, f := range s.Fields {
		if err := f.validate(); err != nil {
			return err
		}
		if names[f.Name] {
			return fmt.Errorf("service: duplicate field %q", f.Name)
		}
		names[f.Name] = true
		if f.Env != "" {
			if other, ok := envs[f.Env]; ok {
				return fmt.Errorf("service: fields %q and %q both use env %s", other, f.Name, f.Env)
			}
			envs[f.Env] = f.Name
		}
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(raw) > MaxPayloadBytes {
		return fmt.Errorf("service: too large (%d bytes > %d)", len(raw), MaxPayloadBytes)
	}
	return nil
}

func (f Field) validate() error {
	if err := ValidateFieldName(f.Name); err != nil {
		return err
	}
	switch f.Type {
	case FieldSecret, FieldText:
		if !utf8.ValidString(f.Value) || strings.ContainsRune(f.Value, 0) {
			return fmt.Errorf("service: field %q must be text without NUL bytes", f.Name)
		}
		if len(f.Value) > MaxValueBytes {
			return fmt.Errorf("service: field %q exceeds %d bytes", f.Name, MaxValueBytes)
		}
	case FieldFile:
		data, err := base64.StdEncoding.DecodeString(f.Value)
		if err != nil {
			return fmt.Errorf("service: file field %q is not valid base64", f.Name)
		}
		if len(data) > MaxValueBytes {
			return fmt.Errorf("service: file field %q exceeds %d bytes", f.Name, MaxValueBytes)
		}
		if f.Env != "" {
			return fmt.Errorf("service: file field %q cannot have an env name", f.Name)
		}
	default:
		return fmt.Errorf("service: field %q has unknown type %q", f.Name, f.Type)
	}
	if f.Env != "" {
		if err := ValidateEnvName(f.Env); err != nil {
			return err
		}
	}
	if len(f.Note) > 512 || !utf8.ValidString(f.Note) {
		return fmt.Errorf("service: note of field %q must be text up to 512 bytes", f.Name)
	}
	if f.ChangedAt != "" {
		if _, err := time.Parse(time.RFC3339, f.ChangedAt); err != nil {
			return fmt.Errorf("service: field %q has an invalid change time", f.Name)
		}
	}
	if f.Revision < 0 {
		return fmt.Errorf("service: field %q has a negative revision", f.Name)
	}
	return nil
}

// ValidateFieldName accepts names usable as file, env-file and Secret keys.
func ValidateFieldName(name string) error {
	if !fieldNameRE.MatchString(name) {
		return fmt.Errorf("service: field name %q must start with a letter or digit and use letters, digits, '.', '_' or '-' (max 64)", name)
	}
	return nil
}

// ValidateEnvName accepts conventional upper-case environment names.
func ValidateEnvName(name string) error {
	if !envNameRE.MatchString(name) {
		return fmt.Errorf("service: env name %q must match [A-Z_][A-Z0-9_]*", name)
	}
	return nil
}

// Field returns the named field.
func (s *Service) Field(name string) (*Field, error) {
	for i := range s.Fields {
		if s.Fields[i].Name == name {
			return &s.Fields[i], nil
		}
	}
	return nil, fmt.Errorf("service: no field %q", name)
}

// Set creates or updates a field. An existing field keeps its type unless
// fieldType names the same type; a different type is refused. env "" keeps
// the existing env name; changed reports whether anything was written.
func (s *Service) Set(name, fieldType string, value []byte, env string, now time.Time) (changed bool, err error) {
	if err := ValidateFieldName(name); err != nil {
		return false, err
	}
	stored, err := encodeValue(fieldType, value)
	if err != nil {
		return false, err
	}
	stamp := now.UTC().Format(time.RFC3339)
	if f, err := s.Field(name); err == nil {
		if fieldType != "" && fieldType != f.Type {
			return false, fmt.Errorf("service: field %q is %s; remove it to store a %s", name, f.Type, fieldType)
		}
		stored, err = encodeValue(f.Type, value)
		if err != nil {
			return false, err
		}
		if env != "" && env != f.Env {
			f.Env = env
			changed = true
		}
		if stored != f.Value {
			f.Value = stored
			f.ChangedAt = stamp
			f.Revision++
			changed = true
		}
		return changed, s.Validate()
	}
	if fieldType == "" {
		fieldType = FieldSecret
	}
	stored, err = encodeValue(fieldType, value)
	if err != nil {
		return false, err
	}
	s.Fields = append(s.Fields, Field{Name: name, Type: fieldType, Value: stored, Env: env, ChangedAt: stamp, Revision: 1})
	return true, s.Validate()
}

// Remove deletes a field.
func (s *Service) Remove(name string) error {
	for i := range s.Fields {
		if s.Fields[i].Name == name {
			s.Fields = append(s.Fields[:i], s.Fields[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("service: no field %q", name)
}

// Restamp marks every field as changed now. Restoring an older version uses
// it so the restored values are visible as a change rather than looking as
// old as they were.
func (s *Service) Restamp(now time.Time) {
	stamp := now.UTC().Format(time.RFC3339)
	for i := range s.Fields {
		s.Fields[i].ChangedAt = stamp
		s.Fields[i].Revision++
	}
}

func encodeValue(fieldType string, value []byte) (string, error) {
	if fieldType == FieldFile {
		return base64.StdEncoding.EncodeToString(value), nil
	}
	return string(value), nil
}

// Bytes returns a field's raw value.
func (f Field) Bytes() ([]byte, error) {
	if f.Type == FieldFile {
		return base64.StdEncoding.DecodeString(f.Value)
	}
	return []byte(f.Value), nil
}

// Select returns the named fields in the given order, or every field with an
// env name when names is empty.
func (s *Service) Select(names []string) ([]Field, error) {
	if len(names) == 0 {
		var out []Field
		for _, f := range s.Fields {
			if f.Env != "" {
				out = append(out, f)
			}
		}
		return out, nil
	}
	out := make([]Field, 0, len(names))
	for _, n := range names {
		f, err := s.Field(n)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, nil
}

// ParseEnvFile reads KEY=VALUE lines, as written by `docker-env` or a plain
// .env file: blank lines and # comments are skipped, an optional `export `
// prefix is dropped, and values wrapped in matching single or double quotes
// are unwrapped without further escape processing.
func ParseEnvFile(data []byte) ([][2]string, error) {
	var out [][2]string
	seen := map[string]bool{}
	for i, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		trimmed = strings.TrimPrefix(trimmed, "export ")
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			return nil, fmt.Errorf("service: env line %d has no '='", i+1)
		}
		key = strings.TrimSpace(key)
		if err := ValidateEnvName(key); err != nil {
			return nil, fmt.Errorf("service: env line %d: %w", i+1, err)
		}
		if seen[key] {
			return nil, fmt.Errorf("service: env key %s appears twice", key)
		}
		seen[key] = true
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		out = append(out, [2]string{key, value})
	}
	if len(out) == 0 {
		return nil, errors.New("service: env input has no KEY=VALUE lines")
	}
	return out, nil
}

// FieldNameForEnv derives a field name from an environment name.
func FieldNameForEnv(env string) string {
	return strings.ReplaceAll(strings.ToLower(env), "_", "-")
}

// Summary is a value-free description of one field.
type Summary struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Env       string `json:"env,omitempty"`
	Note      string `json:"note,omitempty"`
	ChangedAt string `json:"changedAt,omitempty"`
	Revision  int    `json:"revision"`
	Bytes     int    `json:"bytes"`
}

// Summaries lists fields without values, sorted by name.
func (s *Service) Summaries() []Summary {
	out := make([]Summary, 0, len(s.Fields))
	for _, f := range s.Fields {
		raw, _ := f.Bytes()
		out = append(out, Summary{Name: f.Name, Type: f.Type, Env: f.Env, Note: f.Note, ChangedAt: f.ChangedAt, Revision: f.Revision, Bytes: len(raw)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
