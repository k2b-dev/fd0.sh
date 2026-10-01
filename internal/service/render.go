package service

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Environment dialects. Each consumer parses environment files differently,
// so the format is explicit and every value is escaped for that parser or
// refused when it cannot be represented safely.
const (
	DialectSystemd = "systemd-env" // systemd EnvironmentFile=
	DialectDocker  = "docker-env"  // docker/compose --env-file (no quoting)
	DialectShell   = "sh"          // POSIX shell, sourced
)

// RenderEnv renders text and secret fields that have env names.
func RenderEnv(fields []Field, dialect string) ([]byte, error) {
	var b strings.Builder
	for _, f := range fields {
		if f.Type == FieldFile {
			return nil, fmt.Errorf("service: file field %q cannot be rendered as an environment variable", f.Name)
		}
		if f.Env == "" {
			return nil, fmt.Errorf("service: field %q has no env name; set one with --env", f.Name)
		}
		line, err := envLine(f.Env, f.Value, dialect)
		if err != nil {
			return nil, fmt.Errorf("service: field %q: %w", f.Name, err)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func envLine(key, value, dialect string) (string, error) {
	switch dialect {
	case DialectSystemd:
		// Double quotes; systemd unescapes \\ \" and C escapes inside them.
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("value contains a line break, which %s cannot hold", dialect)
		}
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
		return key + `="` + escaped + `"`, nil
	case DialectDocker:
		// Docker takes everything after '=' verbatim, without unquoting.
		if strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("value contains a line break, which %s cannot hold", dialect)
		}
		if value != strings.TrimSpace(value) {
			return "", fmt.Errorf("value has leading or trailing whitespace, which %s does not preserve reliably", dialect)
		}
		return key + "=" + value, nil
	case DialectShell:
		// Single quotes: nothing is expanded; a quote ends and reopens them.
		return "export " + key + "='" + strings.ReplaceAll(value, `'`, `'\''`) + "'", nil
	default:
		return "", fmt.Errorf("unknown format %q (use %s, %s or %s)", dialect, DialectSystemd, DialectDocker, DialectShell)
	}
}

var (
	dnsLabelRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	dnsNameRE   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	secretKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
)

// SecretKey maps one field to a Kubernetes Secret key.
type SecretKey struct {
	Field string
	Key   string
}

// RenderK8sSecret renders an Opaque Secret manifest labelled with the service
// name, for `kubectl apply --server-side --field-manager=fd0-NAME -f -`.
// Values go into base64 `data`, so files and arbitrary bytes survive.
func RenderK8sSecret(svc *Service, serviceName, namespace, secretName string, keys []SecretKey) ([]byte, error) {
	if !dnsLabelRE.MatchString(namespace) {
		return nil, fmt.Errorf("service: invalid namespace %q", namespace)
	}
	if !dnsNameRE.MatchString(secretName) {
		return nil, fmt.Errorf("service: invalid Secret name %q", secretName)
	}
	if !dnsNameRE.MatchString(strings.ToLower(serviceName)) || len(serviceName) > 63 {
		return nil, fmt.Errorf("service: name %q cannot be used as a label value", serviceName)
	}
	if len(keys) == 0 {
		for _, f := range svc.Fields {
			keys = append(keys, SecretKey{Field: f.Name, Key: f.Name})
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("service: %q has no fields", serviceName)
	}
	var b strings.Builder
	b.WriteString("apiVersion: v1\nkind: Secret\ntype: Opaque\nmetadata:\n")
	fmt.Fprintf(&b, "  name: %s\n  namespace: %s\n", secretName, namespace)
	fmt.Fprintf(&b, "  labels:\n    fd0.sh/service: %q\n", serviceName)
	b.WriteString("data:\n")
	seen := map[string]bool{}
	for _, k := range keys {
		if !secretKeyRE.MatchString(k.Key) {
			return nil, fmt.Errorf("service: invalid Secret key %q", k.Key)
		}
		if seen[k.Key] {
			return nil, fmt.Errorf("service: Secret key %q is used twice", k.Key)
		}
		seen[k.Key] = true
		f, err := svc.Field(k.Field)
		if err != nil {
			return nil, err
		}
		raw, err := f.Bytes()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  %s: %s\n", k.Key, base64.StdEncoding.EncodeToString(raw))
	}
	return []byte(b.String()), nil
}

// ParseSecretKeys parses `field` or `field=KEY` entries.
func ParseSecretKeys(specs []string) ([]SecretKey, error) {
	out := make([]SecretKey, 0, len(specs))
	for _, spec := range specs {
		field, key, ok := strings.Cut(spec, "=")
		if !ok {
			key = field
		}
		if err := ValidateFieldName(field); err != nil {
			return nil, err
		}
		out = append(out, SecretKey{Field: field, Key: key})
	}
	return out, nil
}
