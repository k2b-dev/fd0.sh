package desktopbridge

import (
	"context"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/service"
	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

type MoveItemParams struct {
	Source        RecordRef `json:"source"`
	TargetScopeID string    `json:"targetScopeId"`
}

func moveItemKind(recordType, recordName string) (cli.ItemKind, string, error) {
	switch {
	case recordType == "kv.string":
		return cli.KindSecret, recordName, nil
	case recordType == passitem.TypePassItem:
		return cli.KindPass, strings.TrimPrefix(recordName, cli.KindPass.Prefix), nil
	case recordType == sshhost.TypeHost:
		return cli.KindHost, strings.TrimPrefix(recordName, cli.KindHost.Prefix), nil
	case isSSHKeyType(recordType):
		return cli.KindKey, strings.TrimPrefix(recordName, cli.KindKey.Prefix), nil
	case recordType == kubeconfig.TypeKubeconfig:
		return cli.KindKube, strings.TrimPrefix(recordName, cli.KindKube.Prefix), nil
	case recordType == talosctx.TypeTalosContext:
		return cli.KindTalos, strings.TrimPrefix(recordName, cli.KindTalos.Prefix), nil
	case recordType == service.TypeService:
		return cli.KindService, strings.TrimPrefix(recordName, cli.KindService.Prefix), nil
	default:
		return cli.ItemKind{}, "", fail(
			"unsupported_item",
			"This item type cannot be moved in the desktop app.",
			"Use the CLI to inspect the raw record.",
			false,
		)
	}
}

func (s *Service) moveItem(ctx context.Context, params MoveItemParams) (map[string]bool, error) {
	if err := params.Source.Validate(); err != nil {
		return nil, err
	}
	if _, err := proto.ParseScopeID(params.TargetScopeID); err != nil {
		return nil, fail("validation", "That destination vault reference is invalid.", "", false)
	}
	if params.Source.ScopeID == params.TargetScopeID {
		return nil, fail("validation", "Choose another vault.", "", false)
	}

	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()

	record, err := session.GetTypedSecret(params.Source.ScopeID, params.Source.Name)
	if err != nil {
		return nil, mapDomainError(err)
	}
	kind, name, err := moveItemKind(record.Type, record.Name)
	if err != nil {
		return nil, err
	}
	if err := session.MoveItem(ctx, kind, name, params.Source.ScopeID, params.TargetScopeID, false); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}
