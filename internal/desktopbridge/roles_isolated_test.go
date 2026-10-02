package desktopbridge

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Role assignments ask the sync server for support first, so the isolated
// development vault must refuse them before any network call.
func TestIsolatedModeRefusesRoleAssignments(t *testing.T) {
	t.Setenv("FD0_HOME", t.TempDir())
	service := &Service{Mode: "isolated"}
	for method, params := range map[string]string{
		"scope.addMember":     `{"scopeId":"x","label":"benny","role":"reader"}`,
		"scope.setMemberRole": `{"scopeId":"x","memberId":"y","role":"admin"}`,
	} {
		_, err := service.Handle(context.Background(), method, json.RawMessage(params))
		var me *methodError
		if !errors.As(err, &me) || me.bridge.Code != "sync_disabled" {
			t.Fatalf("%s: got %v, want sync_disabled", method, err)
		}
	}
}
