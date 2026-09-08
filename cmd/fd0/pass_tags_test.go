package main

import (
	"reflect"
	"testing"

	"github.com/alecthomas/kong"
)

func TestPassTagsCommandsParse(t *testing.T) {
	for _, tc := range []struct {
		argv    []string
		command string
	}{
		{[]string{"pass", "tags", "add", "GitHub", "Work", "Team A", "--scope", "work"}, "pass tags add <name> <tags>"},
		{[]string{"pass", "tags", "rm", "GitHub", "Work"}, "pass tags rm <name> <tags>"},
		{[]string{"pass", "tags", "clear", "GitHub"}, "pass tags clear <name>"},
		{[]string{"pass", "tags", "list", "--json"}, "pass tags list"},
	} {
		var root rootCLI
		parser, err := kong.New(&root)
		if err != nil {
			t.Fatal(err)
		}
		ctx, err := parser.Parse(tc.argv)
		if err != nil {
			t.Fatal(err)
		}
		if ctx.Command() != tc.command {
			t.Fatalf("%s != %s", ctx.Command(), tc.command)
		}
	}
	var root rootCLI
	parser, _ := kong.New(&root)
	if _, err := parser.Parse([]string{"pass", "add", "GitHub", "--tag", "A,B", "--tag", "Team A"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(root.Pass.Add.Tag, []string{"A,B", "Team A"}) {
		t.Fatal(root.Pass.Add.Tag)
	}
	for _, command := range []string{"list", "find", "browse"} {
		var root rootCLI
		parser, _ := kong.New(&root)
		if _, err := parser.Parse([]string{"pass", command, "--tag", "Work", "--tag", "Team A"}); err != nil {
			t.Fatal(command, err)
		}
		var invalid rootCLI
		parser, _ = kong.New(&invalid)
		if _, err := parser.Parse([]string{"pass", command, "--tag", "Work", "--untagged"}); err == nil {
			t.Fatal(command, "accepted conflicting filters")
		}
	}
}
