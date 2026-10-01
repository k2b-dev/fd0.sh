package desktopbridge

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/service"
)

func TestServiceDetailFieldsNeverCarrySecretValues(t *testing.T) {
	var svc service.Service
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, f := range []struct{ name, typ, value, env string }{
		{"postgres-password", service.FieldSecret, "do-not-show-secret", "POSTGRES_PASSWORD"},
		{"host", service.FieldText, "db.internal", "PGHOST"},
		{"ca.crt", service.FieldFile, "do-not-show-file", ""},
	} {
		if _, err := svc.Set(f.name, f.typ, []byte(f.value), f.env, now); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(svc)
	if err != nil {
		t.Fatal(err)
	}
	record := cli.TypedRecord{Type: service.TypeService, Name: "service:pg-1", Payload: string(raw)}
	fields, err := detailFields(record, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(fields)
	if strings.Contains(string(encoded), "do-not-show") {
		t.Fatalf("detail fields leaked a value: %s", encoded)
	}
	if !strings.Contains(string(encoded), "db.internal") || len(fields) != 3 {
		t.Fatalf("detail fields: %s", encoded)
	}
	kind, name, err := moveItemKind(service.TypeService, "service:pg-1")
	if err != nil || kind != cli.KindService || name != "pg-1" {
		t.Fatalf("move kind: %v %q %v", kind, name, err)
	}
}
