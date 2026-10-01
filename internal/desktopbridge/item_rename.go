package desktopbridge

import (
	"context"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/kubeconfig"
	"github.com/valentinkolb/fd0.sh/internal/service"
	"github.com/valentinkolb/fd0.sh/internal/talosctx"
)

type RenameItemParams struct {
	Source RecordRef `json:"source"`
	Name   string    `json:"name"`
}

func (s *Service) renameItem(ctx context.Context, params RenameItemParams) (map[string]bool, error) {
	if err := params.Source.Validate(); err != nil {
		return nil, err
	}
	params.Name = strings.TrimSpace(params.Name)
	if params.Name == "" {
		return nil, fail("validation", "Item name is required.", "", false)
	}

	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	record, err := session.GetTypedSecret(params.Source.ScopeID, params.Source.Name)
	session.Close()
	if err != nil {
		return nil, mapDomainError(err)
	}

	var renameErr error
	switch record.Type {
	case kubeconfig.TypeKubeconfig:
		renameErr = cli.RunKubeRename(
			ctx,
			params.Source.ScopeID,
			strings.TrimPrefix(params.Source.Name, "kube:"),
			params.Name,
			false,
		)
	case talosctx.TypeTalosContext:
		renameErr = cli.RunTalosRename(
			ctx,
			params.Source.ScopeID,
			strings.TrimPrefix(params.Source.Name, "talos:"),
			params.Name,
			false,
		)
	case service.TypeService:
		renameErr = cli.RunServiceRename(
			ctx,
			params.Source.ScopeID,
			strings.TrimPrefix(params.Source.Name, cli.KindService.Prefix),
			params.Name,
			false,
		)
	default:
		return nil, fail(
			"unsupported",
			"Rename this item through its editor.",
			"SSH keys keep their original name so server assignments cannot break.",
			false,
		)
	}
	if renameErr != nil {
		return nil, mapDomainError(renameErr)
	}
	return map[string]bool{"ok": true}, nil
}
