package main

type passTagsCmd struct {
	Add   passTagsChangeCmd `cmd:"" help:"Add tags without replacing existing tags."`
	Rm    passTagsChangeCmd `cmd:"" aliases:"remove" help:"Remove selected tags."`
	Clear passTagsClearCmd  `cmd:"" help:"Remove all tags from an item."`
	List  passTagsListCmd   `cmd:"" aliases:"ls" help:"List tags and item counts per scope."`
}

type passTagsChangeCmd struct {
	Name  string   `arg:"" help:"Item name."`
	Tags  []string `arg:"" sep:"none" required:"" help:"Tags; quote tags containing spaces."`
	Scope string   `name:"scope" help:"Scope label or id."`
}

type passTagsClearCmd struct {
	Name  string `arg:"" help:"Item name."`
	Scope string `name:"scope" help:"Scope label or id."`
}

type passTagsListCmd struct {
	Scope string `name:"scope" help:"Scope label or id."`
	JSON  bool   `name:"json" help:"Print scopeId, scope, tag and count as JSON."`
}
