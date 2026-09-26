package main

import "github.com/valentinkolb/fd0.sh/internal/agent"

// Only exact, active destinations bypass interactive auto-unlock. Inventory,
// tag filtering and ambiguous/prefix selection retain their normal behavior.
func commandHasSSHGrant(command string, c *rootCLI, grants []agent.SSHGrantView) bool {
	var host, scope string
	switch command {
	case "ssh", "ssh connect", "ssh connect <alias>", "ssh connect <alias> <cmd>":
		if len(c.Ssh.Connect.Tag) > 0 {
			return false
		}
		host, scope = c.Ssh.Connect.Alias, c.Ssh.Connect.Scope
	case "sftp", "sftp connect", "sftp connect <host>":
		host, scope = c.Sftp.Connect.Host, c.Sftp.Connect.Scope
	case "sftp list <host>", "sftp list <host> <path>", "sftp ls <host>", "sftp ls <host> <path>":
		host, scope = c.Sftp.List.Host, c.Sftp.List.Scope
	case "sftp tree <host>", "sftp tree <host> <path>":
		host, scope = c.Sftp.Tree.Host, c.Sftp.Tree.Scope
	case "sftp stat <host> <path>":
		host, scope = c.Sftp.Stat.Host, c.Sftp.Stat.Scope
	case "sftp cp <host> <source> <dest>":
		host, scope = c.Sftp.Copy.Host, c.Sftp.Copy.Scope
	case "sftp mkdir <host> <path>":
		host, scope = c.Sftp.Mkdir.Host, c.Sftp.Mkdir.Scope
	case "sftp mv <host> <old> <new>":
		host, scope = c.Sftp.Move.Host, c.Sftp.Move.Scope
	case "sftp rm <host> <path>":
		host, scope = c.Sftp.Remove.Host, c.Sftp.Remove.Scope
	default:
		return false
	}
	if host == "" {
		return false
	}
	count := 0
	for _, g := range grants {
		if g.Active && g.Name == host && (scope == "" || scope == g.ScopeID) {
			count++
		}
	}
	return count == 1
}
