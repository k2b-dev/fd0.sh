package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

// Item commands expose only organization metadata, even with --json.
type itemCmd struct {
	Batch  itemBatchCmd  `cmd:"" help:"Preview or apply tags/moves to multiple items; use a saved metadata request for drift checks."`
	List   itemListCmd   `cmd:"" aliases:"ls" help:"List organization metadata across item types; never prints values."`
	Tags   itemTagsCmd   `cmd:"" help:"List, add, remove, replace or clear item tags."`
	Rename itemRenameCmd `cmd:"" help:"Rename an item by ID."`
	Move   itemMoveCmd   `cmd:"" help:"Move an item by ID to another scope."`
}
type itemListCmd struct {
	Scope    string   `help:"Scope label or ID; omit to list all scopes."`
	Type     string   `enum:"all,pass,secret,ssh,key,kube,talos" default:"all" help:"Item type."`
	Query    string   `help:"Search names, titles, scope labels and tags."`
	Tag      []string `sep:"none" help:"Require each tag; repeat --tag."`
	Untagged bool     `help:"Only entries without tags."`
	JSON     bool     `help:"Structured metadata output."`
}
type itemRefCmd struct {
	ID    string `arg:"" help:"Stable item ID from item list."`
	Scope string `required:"" help:"Source scope label or ID."`
}
type itemTagChangeCmd struct {
	itemRefCmd
	Tag []string `sep:"none" help:"Tag text; repeat --tag."`
}
type itemTagsCmd struct {
	List   itemListCmd      `cmd:"" help:"List distinct tags and counts in the matching inventory."`
	Add    itemTagChangeCmd `cmd:"" help:"Add tags without replacing existing tags."`
	Remove itemTagChangeCmd `cmd:"" aliases:"rm" help:"Remove selected tags."`
	Set    itemTagChangeCmd `cmd:"" help:"Replace all tags; use clear to remove all."`
	Clear  itemRefCmd       `cmd:"" help:"Remove all tags."`
}
type itemRenameCmd struct {
	itemRefCmd
	Name string `required:"" help:"New item name (without its type prefix)."`
}
type itemMoveCmd struct {
	itemRefCmd
	ToScope string `required:"" help:"Destination scope label or ID."`
}

type itemBatchCmd struct {
	Resume    bool     `help:"Resume the exact saved move request from --input after interruption."`
	Input     string   `help:"JSON OrganizationBatch file, or - for stdin; preserves reviewed item revisions."`
	Scope     string   `help:"Source scope for --id selections."`
	ID        []string `sep:"none" help:"Item ID; repeat --id (at most 100)."`
	Operation string   `enum:"add,remove,set,clear,move" default:"add" help:"Batch operation."`
	Tag       []string `sep:"none" help:"Tag text; repeat --tag."`
	ToScope   string   `help:"Destination for move."`
	DryRun    bool     `help:"Validate and print the request without changing items. Save this output and apply it with --input."`
}

func runItem(ctx context.Context, command string, c itemCmd) error {
	s, err := cli.Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	if command == "item batch" {
		opts := c.Batch
		request := cli.OrganizationBatch{Operation: opts.Operation, Tags: opts.Tag, TargetScopeID: opts.ToScope}
		if opts.Input != "" {
			if len(opts.ID) > 0 || opts.Scope != "" || len(opts.Tag) > 0 || opts.ToScope != "" {
				return fmt.Errorf("use --input without selection or mutation flags")
			}
			var reader io.Reader = os.Stdin
			if opts.Input != "-" {
				file, err := os.Open(opts.Input)
				if err != nil {
					return err
				}
				defer file.Close()
				reader = file
			}
			raw, err := io.ReadAll(io.LimitReader(reader, (1<<20)+1))
			if err != nil {
				return err
			}
			if err := cli.DecodeOrganizationArguments(raw, &request); err != nil {
				return err
			}
		} else {
			if opts.Scope == "" || len(opts.ID) == 0 {
				return fmt.Errorf("provide --scope and --id, or a reviewed --input file")
			}
			items, err := s.OrganizationInventory(cli.OrganizationFilter{Scope: opts.Scope})
			if err != nil {
				return err
			}
			for _, id := range opts.ID {
				index := slices.IndexFunc(items, func(item cli.OrganizationItem) bool { return item.ID == id })
				if index < 0 {
					return fmt.Errorf("item ID not found in selected scope")
				}
				request.Items = append(request.Items, items[index])
			}
		}
		if opts.Resume && opts.Input == "" {
			return fmt.Errorf("--resume requires --input")
		}
		request.Resume = opts.Resume
		request.DryRun = opts.DryRun
		result, err := s.ApplyOrganizationBatch(ctx, request)
		if err != nil {
			_ = json.NewEncoder(os.Stdout).Encode(result)
			return err
		}
		if opts.DryRun {
			request.Scopes = result.Scopes
			return json.NewEncoder(os.Stdout).Encode(request)
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	if command == "item list" || command == "item ls" || command == "item tags list" {
		opts := c.List
		if command == "item tags list" {
			opts = c.Tags.List
		}
		if opts.Type == "all" {
			opts.Type = ""
		}
		items, err := s.OrganizationInventory(cli.OrganizationFilter{Scope: opts.Scope, Kind: opts.Type, Query: opts.Query, Tags: opts.Tag, Untagged: opts.Untagged})
		if err != nil {
			return err
		}
		if command == "item tags list" {
			counts := map[string]int{}
			for _, item := range items {
				for _, tag := range item.Tags {
					counts[tag]++
				}
			}
			return json.NewEncoder(os.Stdout).Encode(counts)
		}
		if opts.JSON {
			return json.NewEncoder(os.Stdout).Encode(items)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tTYPE\tNAME\tSCOPE\tTAGS")
		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%q\t%q\t%q\n", item.ID, item.Kind, item.Name, item.Scope, strings.Join(item.Tags, ", "))
		}
		return w.Flush()
	}
	var ref itemRefCmd
	var tags []string
	var operation string
	switch command {
	case "item tags add <id>":
		ref = c.Tags.Add.itemRefCmd
		tags = c.Tags.Add.Tag
		operation = "add"
	case "item tags remove <id>", "item tags rm <id>":
		ref = c.Tags.Remove.itemRefCmd
		tags = c.Tags.Remove.Tag
		operation = "remove"
	case "item tags set <id>":
		ref = c.Tags.Set.itemRefCmd
		tags = c.Tags.Set.Tag
		operation = "set"
	case "item tags clear <id>":
		ref = c.Tags.Clear
		operation = "clear"
	case "item rename <id>":
		ref = c.Rename.itemRefCmd
	case "item move <id>":
		ref = c.Move.itemRefCmd
	default:
		return fmt.Errorf("unknown item command")
	}
	items, err := s.OrganizationInventory(cli.OrganizationFilter{Scope: ref.Scope})
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ID != ref.ID {
			continue
		}
		if operation != "" {
			if operation != "clear" && len(tags) == 0 {
				return fmt.Errorf("provide at least one --tag (or use tags clear)")
			}
			return s.ChangeItemTags(ctx, item.ScopeID, item.Name, operation, tags)
		}
		record, err := s.GetTypedSecret(item.ScopeID, item.Name)
		if err != nil {
			return err
		}
		kind, err := cli.OrganizationKind(record.Type)
		if err != nil {
			return err
		}
		if command == "item move <id>" {
			return s.MoveItem(ctx, kind, strings.TrimPrefix(item.Name, kind.Prefix), item.ScopeID, c.Move.ToScope, false)
		}
		return s.RenameOrganizationItem(ctx, record, c.Rename.Name)
	}
	return fmt.Errorf("item ID not found in selected scope")
}
