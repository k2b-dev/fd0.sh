package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/cli"
)

type organizeCmd struct {
	Serve   organizeServeCmd   `cmd:"" help:"Serve restricted metadata-only MCP tools over stdio. Requires an agent with no other credential-bearing tools."`
	Review  organizePlanCmd    `cmd:"" help:"Show an immutable proposal and its review digest in a trusted terminal."`
	Approve organizeApproveCmd `cmd:"" help:"Approve the exact reviewed digest; never delegate this command to the organizing agent."`
	Revoke  organizeRevokeCmd  `cmd:"" help:"Revoke an organization session immediately."`
}
type organizeServeCmd struct {
	Scope   []string      `required:"" sep:"none" help:"Allowed source scope; repeat for each scope."`
	ToScope []string      `sep:"none" help:"Allowed move destination; repeat for each scope."`
	Allow   []string      `required:"" sep:"," help:"Allowed operations: tags,rename,move."`
	TTL     time.Duration `default:"30m" help:"Session lifetime, at most 4h; locking also revokes access."`
}
type organizePlanCmd struct {
	Session string `arg:"" help:"Organization session ID."`
	Plan    string `arg:"" help:"Plan ID returned by the organization tool."`
}
type organizeApproveCmd struct {
	organizePlanCmd
	Digest string `required:"" help:"Exact SHA-256 digest shown by organize review."`
}
type organizeRevokeCmd struct {
	Session string `arg:"" help:"Organization session ID."`
}

func runOrganize(ctx context.Context, command string, c organizeCmd) error {
	switch command {
	case "organize serve":
		access, err := cli.NewOrganizationAccess(ctx, cli.OrganizationAccessOptions{Scopes: c.Serve.Scope, Destinations: c.Serve.ToScope, Operations: c.Serve.Allow, TTL: c.Serve.TTL})
		if err != nil {
			return err
		}
		// Model hosts can capture stderr. Suppress domain diagnostics from trusted
		// projection/sync helpers; only the allowlisted MCP results cross this pipe.
		sink, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return errors.New("could not start isolated organization output")
		}
		previous := os.Stderr
		os.Stderr = sink
		defer func() { os.Stderr = previous; sink.Close() }()
		return access.Serve(ctx, os.Stdin, os.Stdout)
	case "organize review <session> <plan>":
		plan, err := cli.ReviewOrganizationPlan(c.Review.Session, c.Review.Plan)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	case "organize approve <session> <plan>":
		return cli.ApproveOrganizationPlan(c.Approve.Session, c.Approve.Plan, c.Approve.Digest)
	case "organize revoke <session>":
		return cli.RevokeOrganizationAccess(c.Revoke.Session)
	default:
		return errors.New("unknown organization command")
	}
}
