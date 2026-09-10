package desktopbridge

import (
	"context"
	"slices"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

type ItemTagsParams struct {
	RecordRef
	Tags         []string  `json:"tags"`
	ExpectedTags *[]string `json:"expectedTags,omitempty"`
}

func (s *Service) setItemTags(ctx context.Context, params ItemTagsParams) (map[string]bool, error) {
	if err := params.RecordRef.Validate(); err != nil {
		return nil, err
	}
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	if params.ExpectedTags != nil {
		record, err := session.GetTypedSecret(params.ScopeID, params.Name)
		if err != nil {
			return nil, mapDomainError(err)
		}
		current, err := record.ItemTags()
		if err != nil {
			return nil, mapDomainError(err)
		}
		if !slices.Equal(current, *params.ExpectedTags) {
			return nil, fail("conflict", "Tags changed while this editor was open.", "Close and reopen the tag editor to review the current tags.", false)
		}
	}
	if err = session.ChangeItemTags(ctx, params.ScopeID, params.Name, "set", params.Tags); err != nil {
		return nil, mapDomainError(err)
	}
	return map[string]bool{"ok": true}, nil
}

func (s *Service) organizationInventory(ctx context.Context) ([]cli.OrganizationItem, error) {
	session, err := cli.Open(ctx)
	if err != nil {
		return nil, mapDomainError(err)
	}
	defer session.Close()
	items, err := session.OrganizationInventory(cli.OrganizationFilter{})
	return items, mapDomainError(err)
}
func (s *Service) organizationBatch(ctx context.Context, params cli.OrganizationBatch) (cli.OrganizationBatchResult, error) {
	session, err := cli.Open(ctx)
	if err != nil {
		return cli.OrganizationBatchResult{}, mapDomainError(err)
	}
	defer session.Close()
	result, err := session.ApplyOrganizationBatch(ctx, params)
	return result, mapDomainError(err)
}
