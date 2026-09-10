package main

import (
	"github.com/alecthomas/kong"
	"testing"
)

func TestOrganizationCLIParsing(t *testing.T) {
	for _, args := range [][]string{
		{"item", "batch", "--scope", "work", "--id", "one", "--id", "two", "--operation", "add", "--tag", "Team A", "--dry-run"},
		{"item", "batch", "--input", "plan.json", "--resume"},
		{"organize", "serve", "--scope", "work", "--scope", "personal", "--to-scope", "work", "--allow", "tags,rename,move", "--ttl", "30m"},
		{"organize", "approve", "session", "plan", "--digest", "digest"},
		{"item", "list", "--type", "secret", "--tag", "Team A", "--json"},
		{"item", "tags", "add", "s_item", "--scope", "work", "--tag", "Prod", "--tag", "prod"},
		{"item", "tags", "clear", "s_item", "--scope", "work"},
		{"item", "move", "s_item", "--scope", "work", "--to-scope", "private"},
	} {
		var c rootCLI
		parser, err := kong.New(&c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = parser.Parse(args); err != nil {
			t.Fatal(args, err)
		}
		if len(args) > 2 && args[2] == "add" && len(c.Item.Tags.Add.Tag) != 2 {
			t.Fatal("repeatable tags lost")
		}
	}
}
