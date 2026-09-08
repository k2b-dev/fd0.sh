// fd0 is the user-facing CLI. All cryptographic operations route through
// fd0-agent (Unix socket at $FD0_HOME/agent.sock).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

// distribution is set to "desktop" for the CLI embedded in fd0 Desktop.
var distribution = "standalone"

type rootCLI struct {
	Init     initCmd     `cmd:"" help:"Create a new identity and vault."`
	Unlock   unlockCmd   `cmd:"" help:"Start the agent and unlock the vault."`
	Lock     lockCmd     `cmd:"" help:"Lock the vault in the running agent."`
	Agent    agentCmd    `cmd:"" help:"Manage the local fd0-agent process."`
	Status   statusCmd   `cmd:"" help:"Show agent status."`
	Secret   secretCmd   `cmd:"" help:"Manage plain string secrets."`
	Scope    scopeCmd    `cmd:"" help:"Scope management."`
	Sync     syncCmd     `cmd:"" help:"Sync with the fd0 server."`
	Card     cardCmd     `cmd:"" help:"Identity card (export your super_pub for invites)."`
	Recovery recoveryCmd `cmd:"" help:"Offline backup of super_priv (for new devices or disaster recovery)."`
	Auth     authCmd     `cmd:"" help:"Manage unlock methods (passphrases, YubiKeys)."`
	Doctor   doctorCmd   `cmd:"" help:"Diagnose vault, chain, and tip-binding consistency."`
	Key      keyCmd      `cmd:"" help:"Manage cryptographic keys (top-level; SSH and future consumers use them)."`
	Ssh      sshCmd      `cmd:"" help:"Manage SSH hosts + connect. Without args opens a fuzzy picker."`
	Sftp     sftpCmd     `cmd:"" help:"Browse and transfer files on fd0 SSH hosts."`
	Pass     passCmd     `cmd:"" help:"Manage structured passwords, TOTP, passkeys, and small files."`
	Browser  browserCmd  `cmd:"" help:"Connect fd0 to a web browser."`
	Talos    talosCmd    `cmd:"" help:"Manage Talos Linux contexts + secrets.yaml DR bundles."`
	Kube     kubeCmd     `cmd:"" help:"Manage Kubernetes kubeconfig clusters (Talos, EKS, GKE, AKS, …)."`
	Version  versionCmd  `cmd:"" help:"Print version and exit."`
	Update   updateCmd   `cmd:"" help:"Update fd0 and fd0-agent from the latest client release."`

	// Plain secrets predate the noun-per-module layout and were spelled
	// `fd0 get/copy/set/rm/list`. Those spellings are in scripts, docs and
	// muscle memory, so they keep working forever — but they are hidden, so
	// help teaches only `fd0 secret …` and the modules read alike. Same types
	// as the secretCmd fields: one grammar, two mount points.
	Get  getCmd  `cmd:"" hidden:"" help:"Deprecated spelling of 'fd0 secret get'."`
	Copy copyCmd `cmd:"" hidden:"" help:"Deprecated spelling of 'fd0 secret copy'."`
	Set  setCmd  `cmd:"" hidden:"" help:"Deprecated spelling of 'fd0 secret set'."`
	Rm   rmCmd   `cmd:"" hidden:"" help:"Deprecated spelling of 'fd0 secret rm'."`
	List listCmd `cmd:"" aliases:"ls" hidden:"" help:"Deprecated spelling of 'fd0 secret list'."`
}

type browserCmd struct {
	Enable  browserEnableCmd  `cmd:"" help:"Register the Chrome Native Messaging host."`
	Disable browserDisableCmd `cmd:"" help:"Remove the Chrome Native Messaging host."`
}

type browserEnableCmd struct {
	Host string `name:"host" type:"path" help:"Path to fd0-browser-host (development builds only)."`
}

type browserDisableCmd struct{}

// stringListFlag is a repeatable string flag that also records whether it was
// given at all — the list-valued half of the pointer-flag convention the edit
// commands use.
//
// A bare *[]string looks like the right shape but is not: kong's pointer mapper
// builds a fresh slice on every occurrence, so `--tag a --tag b` would keep only
// "b". A command whose contract is "replace the whole list" must not silently
// drop half of what the user typed. An empty value contributes nothing, which is
// how the flag spells "clear it".
type stringListFlag struct {
	values []string
	given  bool
}

func (f *stringListFlag) Decode(ctx *kong.DecodeContext) error {
	var v string
	if err := ctx.Scan.PopValueInto("string", &v); err != nil {
		return err
	}
	f.given = true
	if v != "" {
		f.values = append(f.values, v)
	}
	return nil
}

// Ptr renders the flag as the *[]string the cli edit opts take: nil when the
// flag never appeared, so "not given" stays distinct from "cleared".
func (f *stringListFlag) Ptr() *[]string {
	if !f.given {
		return nil
	}
	return &f.values
}

// itemHistoryCmd is the version-history surface every item module exposes.
// Declared once and embedded per module so the flags, arguments and help text
// cannot drift apart between `fd0 ssh history` and `fd0 pass history`.
type itemHistoryCmd struct {
	Show    itemHistoryShowCmd    `cmd:"" default:"withargs" help:"List an item's versions, newest first."`
	Restore itemHistoryRestoreCmd `cmd:"" help:"Restore the content of an earlier version."`
}

type itemHistoryShowCmd struct {
	Name  string `arg:"" help:"Item name."`
	Scope string `name:"scope" help:"Scope label or id."`
	JSON  bool   `name:"json" help:"Machine-readable output."`
}

type itemHistoryRestoreCmd struct {
	Name  string `arg:"" help:"Item name."`
	Seq   uint64 `arg:"" help:"Sequence number, from the history listing."`
	Scope string `name:"scope" help:"Scope label or id."`
}

// ───── key ────────────────────────────────────────────────────────────
type keyCmd struct {
	Add     keyAddCmd      `cmd:"" help:"Generate a new key, or import an existing one with --import."`
	Edit    keyEditCmd     `cmd:"" help:"Change metadata on an existing key."`
	List    keyListCmd     `cmd:"" aliases:"ls" help:"List all keys across scopes."`
	Show    keyShowCmd     `cmd:"" help:"Print a key's details, or just the public key with --pub."`
	Rename  keyRenameCmd   `cmd:"" help:"Rename a key."`
	Rm      keyRmCmd       `cmd:"" help:"Remove a key (tombstone)."`
	Move    keyMoveCmd     `cmd:"" help:"Move a key between scopes."`
	History itemHistoryCmd `cmd:"" help:"Show or restore earlier versions of a key."`
}
type keyEditCmd struct {
	Name    string  `arg:"" help:"Key name."`
	Comment *string `name:"comment" help:"Free-form comment."`
	Scope   string  `name:"scope" help:"Scope label or id."`
}
type keyRenameCmd struct {
	Name  string `arg:"" help:"Current key name."`
	New   string `arg:"" name:"new-name" help:"New key name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing key with the new name."`
}
type keyAddCmd struct {
	Name       string `arg:"" help:"Key name (no prefix)."`
	Type       string `name:"type" help:"Algorithm: only ed25519 supported for new keys." default:"ed25519"`
	Import     string `name:"import" help:"Path to an existing OpenSSH private-key file to import instead of generating."`
	Passphrase string `name:"passphrase" help:"Passphrase for an encrypted imported key. Not recommended interactively." env:"FD0_KEY_IMPORT_PASSPHRASE"`
	Comment    string `name:"comment" help:"Free-form comment; defaults to <name>@fd0."`
	Scope      string `name:"scope" help:"Scope label or id."`
	Force      bool   `name:"force" help:"Overwrite an existing key with the same name."`
}
type keyListCmd struct {
	Scope string `name:"scope" help:"Scope label or id."`
	JSON  bool   `name:"json" help:"Print JSON."`
}
type keyShowCmd struct {
	Name  string `arg:"" help:"Key name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Pub   bool   `name:"pub" help:"Print only the public-key authorized_keys line."`
}
type keyRmCmd struct {
	Name  string `arg:"" help:"Key name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type keyMoveCmd struct {
	Name    string `arg:"" help:"Key name."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an existing key in the destination scope."`
}

// ───── ssh ────────────────────────────────────────────────────────────
type sshCmd struct {
	Enable  sshEnableCmd  `cmd:"" help:"One-time setup: writes Include line + creates fd0.conf."`
	Disable sshDisableCmd `cmd:"" help:"Reverse the one-time setup."`
	Sock    sshSockCmd    `cmd:"" help:"Print the agent socket path."`

	Add     sshAddCmd      `cmd:"" help:"Add a host."`
	Edit    sshEditCmd     `cmd:"" help:"Change fields on an existing host."`
	List    sshListCmd     `cmd:"" aliases:"ls" help:"List hosts."`
	Show    sshShowCmd     `cmd:"" help:"Show one host."`
	Rename  sshRenameCmd   `cmd:"" help:"Rename a host."`
	Rm      sshRmCmd       `cmd:"" help:"Remove a host (tombstone)."`
	Tag     sshTagCmd      `cmd:"" help:"Add or remove tags on a host."`
	Move    sshMoveCmd     `cmd:"" help:"Move a host between scopes."`
	History itemHistoryCmd `cmd:"" help:"Show or restore earlier versions of a host."`

	Connect sshConnectCmd `cmd:"" default:"withargs" help:"Connect to a host, or open the picker."`
}

type sshEditCmd struct {
	Alias        string            `arg:"" help:"Host alias."`
	Hostname     *string           `name:"hostname" help:"Hostname or address."`
	User         *string           `name:"user" help:"SSH user."`
	Port         *int              `name:"port" help:"SSH port."`
	KeyName      *string           `name:"key" help:"Name of an fd0 key to bind."`
	ProxyJump    *string           `name:"jump" help:"ProxyJump alias."`
	Description  *string           `name:"description" help:"Free-form description."`
	Tags         stringListFlag    `name:"tag" placeholder:"TAG" help:"Replace all tags (repeat for multiple)."`
	Options      map[string]string `name:"opt" help:"Set a synchronized ssh_config option (repeatable)."`
	ClearOptions bool              `name:"clear-opts" help:"Remove all synchronized options."`
	Scope        string            `name:"scope" help:"Scope label or id."`
}

type sshRenameCmd struct {
	Alias string `arg:"" help:"Current host alias."`
	New   string `arg:"" name:"new-alias" help:"New host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing host with the new alias."`
}

type sshEnableCmd struct{}
type sshDisableCmd struct{}
type sshSockCmd struct{}

type sshAddCmd struct {
	Alias       string            `arg:"" help:"Host alias (the name you ssh to)."`
	Conn        string            `arg:"" optional:"" help:"Optional [user@]hostname[:port] shorthand."`
	User        string            `name:"user" help:"SSH user (overrides conn-string)."`
	Port        int               `name:"port" help:"SSH port (overrides conn-string)."`
	Hostname    string            `name:"hostname" help:"Override conn-string hostname."`
	Key         string            `name:"key" help:"Name of an existing fd0 key to bind."`
	WithKey     bool              `name:"with-key" help:"Generate a new ed25519 key alongside the host."`
	WithKeyName string            `name:"with-key-name" help:"Custom name for the auto-generated key (default: alias)."`
	Jump        string            `name:"jump" help:"ProxyJump alias."`
	Tag         []string          `name:"tag" help:"Add a tag (repeat for multiple)."`
	Description string            `name:"description" help:"Free-form description."`
	Opt         map[string]string `name:"opt" help:"Safe synchronized ssh_config option (repeatable); command, forwarding, and local-path options are rejected."`
	Scope       string            `name:"scope" help:"Scope label or id."`
	Force       bool              `name:"force" help:"Overwrite an existing host with the same alias (and auto-generated key)."`
}
type sshListCmd struct {
	Scope string   `name:"scope" help:"Scope label or id."`
	Tag   []string `name:"tag" help:"Filter by tag (AND across multiple)."`
	NoTag []string `name:"no-tag" help:"Exclude hosts with this tag."`
	JSON  bool     `name:"json" help:"Print JSON."`
}
type sshShowCmd struct {
	Alias string `arg:"" help:"Host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type sshRmCmd struct {
	Alias string `arg:"" help:"Host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type sshTagCmd struct {
	Alias  string   `arg:"" help:"Host alias."`
	Scope  string   `name:"scope" help:"Scope label or id."`
	Add    []string `name:"add" help:"Add this tag."`
	Remove []string `name:"remove" help:"Remove this tag."`
}
type sshMoveCmd struct {
	Alias   string `arg:"" help:"Host alias."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an existing host with the same alias in the destination."`
}
type sshConnectCmd struct {
	Alias string   `arg:"" optional:"" help:"Host alias. Empty opens picker."`
	Scope string   `name:"scope" help:"Scope label or id."`
	Tag   []string `name:"tag" help:"Pre-filter picker by tag."`
	Cmd   []string `arg:"" optional:"" passthrough:"" help:"Command to execute on the host (passed to ssh)."`
}

// ───── sftp ──────────────────────────────────────────────────────────
type sftpCmd struct {
	Connect sftpConnectCmd `cmd:"" default:"withargs" help:"Open an interactive SFTP session."`
	List    sftpListCmd    `cmd:"" aliases:"ls" help:"List a remote directory."`
	Tree    sftpTreeCmd    `cmd:"" help:"Print a bounded remote directory tree."`
	Stat    sftpStatCmd    `cmd:"" help:"Show remote file metadata."`
	Copy    sftpCopyCmd    `cmd:"" name:"cp" help:"Copy between this device and a remote host."`
	Mkdir   sftpMkdirCmd   `cmd:"" help:"Create a remote directory."`
	Move    sftpMoveCmd    `cmd:"" name:"mv" help:"Rename or move a remote path."`
	Remove  sftpRemoveCmd  `cmd:"" name:"rm" help:"Remove a remote path."`
}

type sftpConnectCmd struct {
	Host  string `arg:"" help:"Host alias."`
	Scope string `name:"scope" help:"Scope label or id."`
}

type sftpListCmd struct {
	Host  string `arg:"" help:"Host alias."`
	Path  string `arg:"" optional:"" help:"Remote directory. Default: remote home."`
	Scope string `name:"scope" help:"Scope label or id."`
	JSON  bool   `name:"json" help:"Print JSON."`
}

type sftpTreeCmd struct {
	Host  string `arg:"" help:"Host alias."`
	Path  string `arg:"" optional:"" help:"Remote directory. Default: remote home."`
	Scope string `name:"scope" help:"Scope label or id."`
	Depth int    `name:"depth" default:"3" help:"Maximum directory depth."`
	JSON  bool   `name:"json" help:"Print JSON."`
}

type sftpStatCmd struct {
	Host  string `arg:"" help:"Host alias."`
	Path  string `arg:"" help:"Remote path."`
	Scope string `name:"scope" help:"Scope label or id."`
	JSON  bool   `name:"json" help:"Print JSON."`
}

type sftpCopyCmd struct {
	Host      string `arg:"" help:"Host alias."`
	Source    string `arg:"" help:"Local path or remote:PATH."`
	Dest      string `arg:"" help:"Local path or remote:PATH."`
	Scope     string `name:"scope" help:"Scope label or id."`
	Recursive bool   `name:"recursive" short:"r" help:"Copy directories recursively without following symlinks."`
	Force     bool   `name:"force" help:"Replace an existing file destination."`
}

type sftpMkdirCmd struct {
	Host    string `arg:"" help:"Host alias."`
	Path    string `arg:"" help:"Remote directory."`
	Scope   string `name:"scope" help:"Scope label or id."`
	Parents bool   `name:"parents" short:"p" help:"Create missing parent directories."`
}

type sftpMoveCmd struct {
	Host  string `arg:"" help:"Host alias."`
	Old   string `arg:"" help:"Existing remote path."`
	New   string `arg:"" help:"New remote path."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Replace an existing destination when supported."`
}

type sftpRemoveCmd struct {
	Host      string `arg:"" help:"Host alias."`
	Path      string `arg:"" help:"Remote path."`
	Scope     string `name:"scope" help:"Scope label or id."`
	Recursive bool   `name:"recursive" short:"r" help:"Remove a directory and its contents without following symlinks."`
	Yes       bool   `name:"yes" short:"y" help:"Confirm the destructive operation."`
}

// ───── pass ───────────────────────────────────────────────────────────
type passCmd struct {
	Tags     passTagsCmd     `cmd:"" help:"Organize password items with tags."`
	Browse   passBrowseCmd   `cmd:"" default:"withargs" help:"Open the interactive pass browser."`
	Add      passAddCmd      `cmd:"" help:"Create a pass item."`
	Edit     passEditCmd     `cmd:"" help:"Change an item's title or URLs."`
	Find     passFindCmd     `cmd:"" help:"Find pass items by title, URL, or tag."`
	List     passListCmd     `cmd:"" aliases:"ls" help:"List pass items."`
	Show     passShowCmd     `cmd:"" help:"Show a pass item with secrets masked by default."`
	Rename   passRenameCmd   `cmd:"" help:"Rename a pass item."`
	Rm       passRmCmd       `cmd:"" help:"Remove a pass item."`
	Move     passMoveCmd     `cmd:"" help:"Move a pass item between scopes."`
	History  itemHistoryCmd  `cmd:"" help:"Show or restore earlier versions of a pass item."`
	Copy     passCopyCmd     `cmd:"" help:"Copy a field value, secret, or current TOTP code."`
	Generate passGenerateCmd `cmd:"" help:"Generate a password without storing it."`
	Field    passFieldCmd    `cmd:"" help:"Set, get, or remove fields by slash path."`
	Notes    passNotesCmd    `cmd:"" help:"Read, write, or remove the item's free-text note."`
	Section  passSectionCmd  `cmd:"" help:"Manage section fields."`
	TOTP     passTOTPCmd     `cmd:"" name:"totp" help:"Manage or print TOTP fields."`
	File     passFileCmd     `cmd:"" help:"Attach or export small files."`
}
type passMoveCmd struct {
	Name    string `arg:"" help:"Item name."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an item of the same name in the destination."`
}

type passBrowseCmd struct {
	Tag        []string `name:"tag" sep:"none" xor:"tag-filter" help:"Require this tag (repeatable; all must match)."`
	Untagged   bool     `name:"untagged" xor:"tag-filter" help:"Only items without tags."`
	Query      string   `arg:"" optional:"" help:"Initial search query."`
	Scope      string   `name:"scope" help:"Scope label or id."`
	ClearAfter string   `name:"clear-after" help:"Override clipboard clear delay."`
}
type passAddCmd struct {
	Tag   []string `name:"tag" sep:"none" help:"Add a tag (repeatable)."`
	Name  string   `arg:"" help:"Item name."`
	URL   []string `name:"url" help:"Login URL or matching URL (repeatable)."`
	Scope string   `name:"scope" help:"Scope label or id."`
	Force bool     `name:"force" help:"Overwrite an existing pass item with the same name."`
	Notes string   `name:"notes" help:"Free-text note to store on the new item."`
}
type passEditCmd struct {
	Name  string         `arg:"" help:"Item name."`
	Title *string        `name:"title" help:"Display title."`
	URL   stringListFlag `name:"url" placeholder:"URL" help:"Replace all URLs (repeat for multiple)."`
	Scope string         `name:"scope" help:"Scope label or id."`
}
type passRenameCmd struct {
	Name  string `arg:"" help:"Current item name."`
	New   string `arg:"" name:"new-name" help:"New item name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing pass item with the new name."`
}
type passFindCmd struct {
	Tag      []string `name:"tag" sep:"none" xor:"tag-filter" help:"Require this tag (repeatable; all must match)."`
	Untagged bool     `name:"untagged" xor:"tag-filter" help:"Only items without tags."`
	Query    string   `arg:"" optional:"" help:"Text to match against title, URLs and tags."`
	URL      string   `name:"url" help:"URL to match for browser/autofill lookups."`
	Scope    string   `name:"scope" help:"Scope label or id."`
	JSON     bool     `name:"json" help:"Print JSON."`
}
type passListCmd struct {
	Tag      []string `name:"tag" sep:"none" xor:"tag-filter" help:"Require this tag (repeatable; all must match)."`
	Untagged bool     `name:"untagged" xor:"tag-filter" help:"Only items without tags."`
	Scope    string   `name:"scope" help:"Scope label or id."`
	JSON     bool     `name:"json" help:"Print JSON."`
}
type passShowCmd struct {
	Name   string `arg:"" help:"Item name."`
	Scope  string `name:"scope" help:"Scope label or id."`
	Reveal bool   `name:"reveal" help:"Reveal secret field values in terminal output."`
	JSON   bool   `name:"json" help:"Print decrypted item JSON."`
}
type passRmCmd struct {
	Name  string `arg:"" help:"Item name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type passCopyCmd struct {
	Name       string `arg:"" help:"Item name."`
	Field      string `arg:"" optional:"" help:"Field path. Defaults to password."`
	Scope      string `name:"scope" help:"Scope label or id."`
	ClearAfter string `name:"clear-after" help:"Override clipboard clear delay."`
}
type passGenerateCmd struct {
	Length int  `name:"length" short:"l" help:"Password length." default:"32"`
	Raw    bool `name:"raw" help:"Print without trailing newline."`
}
type passFieldCmd struct {
	Set passFieldSetCmd `cmd:"" help:"Set a text, secret, or passkey field."`
	Get passFieldGetCmd `cmd:"" help:"Print a text, secret, or TOTP field value."`
	Rm  passFieldRmCmd  `cmd:"" help:"Remove a field."`
}
type passFieldSetCmd struct {
	Name     string `arg:"" help:"Item name."`
	Path     string `arg:"" help:"Field path, e.g. password or Recovery/code-1."`
	Value    string `arg:"" optional:"" help:"Value. Use - to read from stdin."`
	Type     string `name:"type" help:"Field type: text, secret, passkey." default:"text"`
	Secret   bool   `name:"secret" help:"Shortcut for --type secret."`
	Generate bool   `name:"generate" help:"Generate a secret value."`
	Length   int    `name:"length" help:"Generated password length." default:"32"`
	Scope    string `name:"scope" help:"Scope label or id."`
}
type passFieldGetCmd struct {
	Name  string `arg:"" help:"Item name."`
	Path  string `arg:"" help:"Field path."`
	Scope string `name:"scope" help:"Scope label or id."`
	Raw   bool   `name:"raw" help:"Print without trailing newline."`
}
type passFieldRmCmd struct {
	Name  string `arg:"" help:"Item name."`
	Path  string `arg:"" help:"Field path."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type passNotesCmd struct {
	Show passNotesShowCmd `cmd:"" default:"withargs" help:"Print the item's note."`
	Set  passNotesSetCmd  `cmd:"" help:"Set the item's note."`
	Rm   passNotesRmCmd   `cmd:"" help:"Remove the item's note."`
}
type passNotesShowCmd struct {
	Name  string `arg:"" help:"Item name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type passNotesSetCmd struct {
	Name  string `arg:"" help:"Item name."`
	Text  string `arg:"" optional:"" help:"Note text. Omitted: read stdin when piped, else open $EDITOR."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type passNotesRmCmd struct {
	Name  string `arg:"" help:"Item name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type passSectionCmd struct {
	Add passSectionAddCmd `cmd:"" help:"Add a section by slash path."`
}
type passSectionAddCmd struct {
	Name  string `arg:"" help:"Item name."`
	Path  string `arg:"" help:"Section path."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type passTOTPCmd struct {
	Add  passTOTPAddCmd  `cmd:"" help:"Store an otpauth:// TOTP URI."`
	Code passTOTPCodeCmd `cmd:"" default:"withargs" help:"Print the current TOTP code."`
}
type passTOTPAddCmd struct {
	Name  string `arg:"" help:"Item name."`
	URI   string `arg:"" help:"otpauth://totp/... URI."`
	Path  string `name:"field" help:"Field path. Defaults to totp."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type passTOTPCodeCmd struct {
	Name  string `arg:"" help:"Item name."`
	Path  string `arg:"" optional:"" help:"TOTP field path. Defaults to first TOTP field."`
	Scope string `name:"scope" help:"Scope label or id."`
	Raw   bool   `name:"raw" help:"Print only the code."`
}
type passFileCmd struct {
	Add    passFileAddCmd    `cmd:"" help:"Attach a small file to an item."`
	Export passFileExportCmd `cmd:"" help:"Export an attached file field."`
}
type passFileAddCmd struct {
	Name  string `arg:"" help:"Item name."`
	File  string `arg:"" help:"File path."`
	Path  string `arg:"" optional:"" help:"Field path. Defaults to basename."`
	MIME  string `name:"mime" help:"MIME type hint."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type passFileExportCmd struct {
	Name  string `arg:"" help:"Item name."`
	Path  string `arg:"" help:"File field path."`
	Out   string `name:"out" help:"Explicit local output path. Defaults to the stored basename in the current directory."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing output file."`
}

// ───── talos ──────────────────────────────────────────────────────────
type talosCmd struct {
	Enable  talosEnableCmd  `cmd:"" help:"Enable automatic talosconfig refresh after fd0 sync."`
	Disable talosDisableCmd `cmd:"" help:"Disable automatic talosconfig refresh after fd0 sync."`
	Add     talosAddCmd     `cmd:"" help:"Import an existing talosconfig context (or one from --from-config)."`
	New     talosNewCmd     `cmd:"" help:"Day-0: generate cluster PKI + talosconfig from scratch (calls talosctl)."`
	Edit    talosEditCmd    `cmd:"" help:"Change fields on an existing talos context."`
	List    talosListCmd    `cmd:"" aliases:"ls" help:"List talos contexts."`
	Show    talosShowCmd    `cmd:"" help:"Show one talos context."`
	Rename  talosRenameCmd  `cmd:"" help:"Rename a talos context."`
	Rm      talosRmCmd      `cmd:"" help:"Remove a talos context (tombstone)."`
	Move    talosMoveCmd    `cmd:"" help:"Move a talos context between scopes."`
	History itemHistoryCmd  `cmd:"" help:"Show or restore earlier versions of a context."`

	Sync       talosSyncCmd       `cmd:"" help:"Re-render ~/.talos/config.fd0 (and merge with --merge)."`
	RoleAdd    talosRoleAddCmd    `cmd:"" name:"role-add" help:"Mint a role-scoped client cert via talosctl + store it."`
	Kubeconfig talosKubeconfigCmd `cmd:"" help:"Fetch a fresh admin kubeconfig from a Talos cluster + store it."`

	Secrets talosSecretsCmd `cmd:"" help:"DR-grade secrets.yaml bundles."`
}

type talosEnableCmd struct {
	Merge bool `name:"merge" help:"After every fd0 sync, also merge fd0 contexts into ~/.talos/config."`
}
type talosDisableCmd struct{}
type talosAddCmd struct {
	Name          string   `arg:"" optional:"" help:"Context name. Required unless --from-config."`
	Endpoint      []string `name:"endpoint" help:"Talos machine API endpoint (repeat or comma-separate)."`
	Node          []string `name:"node" help:"Default node target (repeat or comma-separate)."`
	CA            string   `name:"ca" help:"base64-encoded CA cert (or use --ca-file)."`
	CAFile        string   `name:"ca-file" help:"PEM file to read into ca."`
	Crt           string   `name:"crt" help:"base64-encoded client cert (or use --crt-file)."`
	CrtFile       string   `name:"crt-file" help:"PEM file to read into crt."`
	Key           string   `name:"key" help:"base64-encoded client key (or use --key-file)."`
	KeyFile       string   `name:"key-file" help:"PEM file to read into key."`
	FromConfig    string   `name:"from-config" help:"Path to an existing talosconfig YAML to import."`
	ImportContext string   `name:"import-context" help:"With --from-config, import only this named context."`
	Role          string   `name:"role" help:"Cert role (os:admin / os:operator / os:reader / …)."`
	Description   string   `name:"description" help:"Free-form description."`
	Tag           []string `name:"tag" help:"Add a tag (repeat for multiple)."`
	Scope         string   `name:"scope" help:"Scope label or id."`
	Force         bool     `name:"force" help:"Overwrite an existing context with the same name."`
}

type talosNewCmd struct {
	Name        string   `arg:"" help:"Cluster name (becomes the talosconfig context name)."`
	Endpoint    string   `name:"endpoint" required:"" help:"Kubernetes API URL, e.g. https://10.0.1.10:6443."`
	OutputDir   string   `name:"out" help:"Where to write controlplane.yaml + worker.yaml (default: current dir)."`
	Scope       string   `name:"scope" help:"Scope for the talosconfig context."`
	VaultScope  string   `name:"vault-scope" help:"Separate scope for the secrets.yaml DR bundle (default: same as --scope)."`
	Description string   `name:"description" help:"Free-form description."`
	Tag         []string `name:"tag" help:"Add a tag."`
	Force       bool     `name:"force" help:"Overwrite an existing stored cluster with the same name (destructive — see talos secrets export first)."`
}

type talosEditCmd struct {
	Name        string         `arg:"" help:"Context name."`
	Endpoint    stringListFlag `name:"endpoint" placeholder:"ENDPOINT" help:"Replace all endpoints (repeat or comma-separate)."`
	Node        stringListFlag `name:"node" placeholder:"NODE" help:"Replace all default node targets (repeat or comma-separate)."`
	Role        *string        `name:"role" help:"Cert role label (os:admin / os:operator / os:reader / …)."`
	Description *string        `name:"description" help:"Free-form description."`
	Tag         stringListFlag `name:"tag" placeholder:"TAG" help:"Replace all tags (repeat for multiple)."`
	Scope       string         `name:"scope" help:"Scope label or id."`
}
type talosRenameCmd struct {
	Name  string `arg:"" help:"Current context name."`
	New   string `arg:"" name:"new-name" help:"New context name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing context with the new name."`
}
type talosListCmd struct {
	Scope string   `name:"scope" help:"Scope label or id."`
	Tag   []string `name:"tag" help:"Filter by tag (AND)."`
	NoTag []string `name:"no-tag" help:"Exclude tag."`
	JSON  bool     `name:"json" help:"Print JSON."`
}
type talosShowCmd struct {
	Name  string `arg:"" help:"Context name."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type talosRmCmd struct {
	Name  string `arg:"" help:"Context name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type talosMoveCmd struct {
	Name    string `arg:"" help:"Context name."`
	From    string `name:"scope" help:"Source scope."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope."`
	Force   bool   `name:"force" help:"Overwrite an existing context with the same name in destination."`
}
type talosSyncCmd struct {
	Merge         bool `name:"merge" help:"After rendering, fold into ~/.talos/config."`
	ReplaceActive bool `name:"replace-active" help:"Allow this merge to replace the active local context."`
}
type talosRoleAddCmd struct {
	From        string   `name:"from" required:"" help:"Existing fd0-managed talos context with admin privileges (issuer)."`
	NewName     string   `name:"name" required:"" help:"Name for the new context."`
	Role        string   `name:"role" required:"" help:"Role to embed in the new cert (os:operator, os:reader, …)."`
	TTL         string   `name:"ttl" help:"Cert validity (talosctl --crt-ttl). Empty = default (1y)."`
	Scope       string   `name:"scope" help:"Scope for the new context."`
	Description string   `name:"description" help:"Free-form description."`
	Tag         []string `name:"tag" help:"Tag."`
}
type talosKubeconfigCmd struct {
	Name  string `arg:"" help:"Talos context name to pull kubeconfig from."`
	Scope string `name:"scope" help:"Scope for the resulting kubeconfig record."`
}
type talosSecretsCmd struct {
	Export talosSecretsExportCmd `cmd:"" help:"Write a stored secrets.yaml bundle to a file (DR-grade)."`
	Import talosSecretsImportCmd `cmd:"" help:"Read a secrets.yaml from disk into the vault."`
	List   talosSecretsListCmd   `cmd:"" aliases:"ls" help:"List stored bundles."`
}
type talosSecretsExportCmd struct {
	Name  string `arg:"" help:"Bundle name (matches the cluster name passed to 'fd0 talos new')."`
	Out   string `name:"out" required:"" help:"Output path."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing file at --out."`
}
type talosSecretsImportCmd struct {
	Name  string `arg:"" help:"Bundle name."`
	In    string `name:"in" required:"" help:"Path to the secrets.yaml file."`
	Scope string `name:"scope" help:"Scope."`
}
type talosSecretsListCmd struct {
	Scope string `name:"scope" help:"Scope."`
}

// ───── kube ───────────────────────────────────────────────────────────
type kubeCmd struct {
	Enable  kubeEnableCmd  `cmd:"" help:"Enable automatic kubeconfig refresh after fd0 sync."`
	Disable kubeDisableCmd `cmd:"" help:"Disable automatic kubeconfig refresh after fd0 sync."`
	Add     kubeAddCmd     `cmd:"" help:"Add a kubeconfig cluster."`
	Edit    kubeEditCmd    `cmd:"" help:"Change fields on an existing kubeconfig."`
	List    kubeListCmd    `cmd:"" aliases:"ls" help:"List kubeconfig clusters."`
	Show    kubeShowCmd    `cmd:"" help:"Show one kubeconfig."`
	Rename  kubeRenameCmd  `cmd:"" help:"Rename a kubeconfig."`
	Rm      kubeRmCmd      `cmd:"" help:"Remove a kubeconfig (tombstone)."`
	Move    kubeMoveCmd    `cmd:"" help:"Move a kubeconfig between scopes."`
	History itemHistoryCmd `cmd:"" help:"Show or restore earlier versions of a cluster."`
	Sync    kubeSyncCmd    `cmd:"" help:"Re-render ~/.kube/config.fd0 (and merge with --merge)."`
}
type kubeEnableCmd struct {
	Merge bool `name:"merge" help:"After every fd0 sync, also merge fd0 clusters into ~/.kube/config."`
}
type kubeDisableCmd struct{}
type kubeAddCmd struct {
	Name                  string   `arg:"" optional:"" help:"Cluster name. Required unless --from-config."`
	Server                string   `name:"server" help:"https://host:6443"`
	CA                    string   `name:"ca" help:"base64-encoded CA cert."`
	CAFile                string   `name:"ca-file" help:"PEM file to read into CA."`
	ClientCert            string   `name:"client-cert" help:"base64-encoded client cert."`
	ClientCertFile        string   `name:"client-cert-file" help:"PEM file."`
	ClientKey             string   `name:"client-key" help:"base64-encoded client key."`
	ClientKeyFile         string   `name:"client-key-file" help:"PEM file."`
	Token                 string   `name:"token" help:"Bearer token (alternative to client cert)."`
	Namespace             string   `name:"namespace" help:"Default namespace."`
	InsecureSkipTLSVerify bool     `name:"insecure-skip-tls-verify" help:"Disable cluster TLS verification."`
	FromConfig            string   `name:"from-config" help:"Path to existing kubeconfig YAML to import."`
	ImportContext         string   `name:"import-context" help:"With --from-config, import only this named context."`
	Description           string   `name:"description" help:"Free-form description."`
	Tag                   []string `name:"tag" help:"Tag."`
	Scope                 string   `name:"scope" help:"Scope."`
	Force                 bool     `name:"force" help:"Overwrite an existing kubeconfig with the same name."`
}
type kubeEditCmd struct {
	Name        string         `arg:"" help:"Cluster name."`
	Server      *string        `name:"server" help:"https://host:6443"`
	Namespace   *string        `name:"namespace" help:"Default namespace."`
	Description *string        `name:"description" help:"Free-form description."`
	Tag         stringListFlag `name:"tag" placeholder:"TAG" help:"Replace all tags (repeat for multiple)."`
	Scope       string         `name:"scope" help:"Scope."`
}
type kubeRenameCmd struct {
	Name  string `arg:"" help:"Current cluster name."`
	New   string `arg:"" name:"new-name" help:"New cluster name."`
	Scope string `name:"scope" help:"Scope."`
	Force bool   `name:"force" help:"Overwrite an existing kubeconfig with the new name."`
}
type kubeListCmd struct {
	Scope string   `name:"scope" help:"Scope."`
	Tag   []string `name:"tag" help:"Filter by tag (AND)."`
	NoTag []string `name:"no-tag" help:"Exclude tag."`
	JSON  bool     `name:"json" help:"Print JSON."`
}
type kubeShowCmd struct {
	Name  string `arg:"" help:"Cluster name."`
	Scope string `name:"scope" help:"Scope."`
}
type kubeRmCmd struct {
	Name  string `arg:"" help:"Cluster name."`
	Scope string `name:"scope" help:"Scope."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type kubeMoveCmd struct {
	Name    string `arg:"" help:"Cluster name."`
	From    string `name:"scope" help:"Source scope."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope."`
	Force   bool   `name:"force" help:"Overwrite an existing kubeconfig with the same name in destination."`
}
type kubeSyncCmd struct {
	Merge         bool `name:"merge" help:"After rendering, fold into ~/.kube/config."`
	ReplaceActive bool `name:"replace-active" help:"Allow this merge to replace the active local context and its cluster/user."`
}

type initCmd struct{}
type unlockCmd struct {
	AgentBin string `name:"agent-bin" help:"Path to fd0-agent binary." env:"FD0_AGENT_BIN"`
	Method   string `name:"method" help:"Auth method type or method_id to use ('passphrase', 'yubikey', or am_...). Overrides [auth].default_method."`
}
type lockCmd struct{}
type statusCmd struct{}
type agentCmd struct {
	Status  agentStatusCmd  `cmd:"" help:"Show fd0-agent process, vault, and SSH socket state."`
	Restart agentRestartCmd `cmd:"" help:"Restart fd0-agent and prompt to unlock again if needed."`
	Stop    agentStopCmd    `cmd:"" help:"Stop fd0-agent and clean stale sockets when safe."`
}
type agentStatusCmd struct{}
type agentRestartCmd struct {
	AgentBin string `name:"agent-bin" help:"Path to fd0-agent binary." env:"FD0_AGENT_BIN"`
}
type agentStopCmd struct{}
type getCmd struct {
	Name  string `arg:"" optional:"" help:"Secret name."`
	Scope string `name:"scope" help:"Scope ID."`
	Raw   bool   `name:"raw" help:"Print value without trailing newline."`
}
type copyCmd struct {
	Name       string `arg:"" optional:"" help:"Secret name."`
	Scope      string `name:"scope" help:"Scope label or id."`
	ClearAfter string `name:"clear-after" help:"Override clear delay ('30s', '0' to disable). Default: [clipboard].clear_after_seconds in config, else 30s."`
}
type setCmd struct {
	Name  string `arg:"" help:"Secret name."`
	Value string `arg:"" help:"Secret value (use - to read from stdin)."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type rmCmd struct {
	Name  string `arg:"" help:"Secret name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type listCmd struct {
	JSON bool `name:"json" help:"Print JSON."`
	All  bool `name:"all" help:"Include records owned by other modules (hosts, keys, pass items, clusters)."`
}

// ───── secret ─────────────────────────────────────────────────────────
// The verb commands are the very structs the hidden legacy top-level
// spellings use, so `fd0 get` and `fd0 secret get` cannot grow different
// flags. Rename/move/history come from the same shared surfaces every other
// module embeds.
type secretCmd struct {
	Get     getCmd          `cmd:"" help:"Print a secret to stdout. Interactive when called without NAME."`
	Copy    copyCmd         `cmd:"" help:"Copy a secret to the clipboard with auto-clear."`
	Set     setCmd          `cmd:"" help:"Add or update a secret."`
	List    listCmd         `cmd:"" aliases:"ls" help:"List secrets."`
	Rename  secretRenameCmd `cmd:"" help:"Rename a secret."`
	Rm      rmCmd           `cmd:"" help:"Remove a secret (writes a tombstone)."`
	Move    secretMoveCmd   `cmd:"" help:"Move a secret between scopes."`
	History itemHistoryCmd  `cmd:"" help:"Show or restore earlier versions of a secret."`
}
type secretRenameCmd struct {
	Name  string `arg:"" help:"Current secret name."`
	New   string `arg:"" name:"new-name" help:"New secret name."`
	Scope string `name:"scope" help:"Scope label or id."`
	Force bool   `name:"force" help:"Overwrite an existing secret with the new name."`
}
type secretMoveCmd struct {
	Name    string `arg:"" help:"Secret name."`
	From    string `name:"scope" help:"Source scope label or id."`
	ToScope string `name:"to-scope" required:"" help:"Destination scope label or id."`
	Force   bool   `name:"force" help:"Overwrite an existing secret with the same name in the destination."`
}

type scopeCmd struct {
	Create       scopeCreateCmd       `cmd:"" help:"Create a new scope."`
	List         scopeListCmd         `cmd:"" aliases:"ls" help:"List scopes."`
	Members      scopeMembersCmd      `cmd:"" help:"List members of a scope."`
	AddMember    scopeAddMemberCmd    `cmd:"" name:"add-member" help:"Add a member by card URL or pinned label."`
	RemoveMember scopeRemoveMemberCmd `cmd:"" name:"remove-member" help:"Remove a member."`
	Leave        scopeLeaveCmd        `cmd:"" help:"Leave a scope (remove self + drop locally)."`
	Rename       scopeRenameCmd       `cmd:"" help:"Rename a scope's shared label."`
}
type scopeCreateCmd struct {
	Label string `name:"label" help:"Optional human-readable label."`
}
type scopeListCmd struct{}
type scopeMembersCmd struct {
	Scope string `arg:"" optional:"" help:"Scope label or id."`
}
type scopeAddMemberCmd struct {
	Card  string `arg:"" help:"Member card URL or pinned label."`
	Scope string `name:"scope" help:"Scope label or id."`
}
type scopeRemoveMemberCmd struct {
	Card  string `arg:"" help:"Member card URL or pinned label."`
	Scope string `name:"scope" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type scopeLeaveCmd struct {
	Scope string `arg:"" optional:"" help:"Scope label or id."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before leaving."`
}
type scopeRenameCmd struct {
	Scope    string `arg:"" help:"Scope label or id."`
	NewLabel string `arg:"" name:"new-label" help:"New label."`
}

type cardCmd struct {
	Export cardExportCmd `cmd:"" help:"Print this user's identity card URL."`
	Import cardImportCmd `cmd:"" help:"Import a card URL and pin it under a label."`
	List   cardListCmd   `cmd:"" aliases:"ls" help:"List pinned identities."`
	Remove cardRemoveCmd `cmd:"" name:"rm" help:"Unpin a label."`
}
type cardExportCmd struct{}
type cardImportCmd struct {
	URL   string `arg:"" name:"url" help:"Card URL: fd0://card/..."`
	Label string `name:"label" help:"Local label for this identity (defaults to the card's shortId)."`
	Yes   bool   `name:"yes" short:"y" help:"Skip the safety-number confirm prompt."`
}
type cardListCmd struct{}
type cardRemoveCmd struct {
	Label string `arg:"" help:"Pinned label to unpin."`
	Yes   bool   `name:"yes" short:"y" help:"Do not prompt before unpinning."`
}

type recoveryCmd struct {
	Export recoveryExportCmd `cmd:"" help:"Encrypt super_priv to a recovery file."`
	Import recoveryImportCmd `cmd:"" help:"Bootstrap a fresh device from a recovery file."`
}
type recoveryExportCmd struct {
	Out string `arg:"" name:"out" help:"Output path for the recovery file."`
}
type recoveryImportCmd struct {
	In  string `arg:"" name:"in" help:"Path to the recovery file."`
	Yes bool   `name:"yes" short:"y" help:"Do not prompt before bootstrapping this fd0 home."`
}

type syncCmd struct {
	Server   string `name:"server" help:"fd0-server URL." env:"FD0_SERVER"`
	WaitLock string `name:"wait-lock" help:"Block up to this duration acquiring ~/.fd0/.lock (Go duration string)." env:"FD0_LOCK_WAIT"`
}

type doctorCmd struct{}

type authCmd struct {
	List    authListCmd    `cmd:"" aliases:"ls" help:"List active auth methods."`
	Default authDefaultCmd `cmd:"" help:"Show or set the device-local default unlock method."`
	Add     authAddCmd     `cmd:"" help:"Add a new passphrase or YubiKey as an additional auth method."`
	Remove  authRemoveCmd  `cmd:"" name:"rm" help:"Remove an auth method by id."`
}
type authListCmd struct{}
type authDefaultCmd struct {
	Method string `arg:"" optional:"" help:"Auth method type or method_id ('passphrase', 'yubikey', or am_...). Empty shows current default."`
	Clear  bool   `name:"clear" help:"Clear the device-local default unlock method."`
}
type authAddCmd struct {
	Yubikey bool   `name:"yubikey" help:"Enroll a YubiKey instead of a passphrase. Requires the yubikey release flavor."`
	Touch   string `name:"touch" help:"YubiKey touch policy: 'always' (default, secure), 'never' (no touch), 'cached' (15s cache after first touch)."`
	Force   bool   `name:"force" help:"Overwrite an existing key on slot 9d without prompting (DESTRUCTIVE: invalidates any prior YubiKey enrollment binding to the same card)."`
}
type authRemoveCmd struct {
	ID  string `arg:"" help:"method_id (am_...) — see 'fd0 auth ls'."`
	Yes bool   `name:"yes" short:"y" help:"Do not prompt before removing."`
}
type versionCmd struct{}
type updateCmd struct {
	Check          bool   `name:"check" help:"Check for an update without installing. Exits 10 when an update is available."`
	Yes            bool   `name:"yes" short:"y" help:"Do not prompt before installing."`
	Version        string `name:"version" help:"Release tag or semver to install. Default: latest client release." env:"FD0_VERSION"`
	Flavor         string `name:"flavor" help:"Release flavor: auto, standard, or yubikey. Default: preserve the installed flavor." default:"auto"`
	Prefix         string `name:"prefix" help:"Install into this directory. Default: directory of the running fd0 binary."`
	System         bool   `name:"system" help:"Install into /usr/local/bin."`
	AllowDowngrade bool   `name:"allow-downgrade" help:"Permit an explicitly selected older release. Never applies to latest-release resolution."`
}

func main() {
	// Hidden helper: the `fd0 copy` command spawns a detached child of itself
	// that clears the clipboard after a delay. We special-case that branch
	// before kong parses argv so it doesn't show up in help output.
	if len(os.Args) >= 3 && os.Args[1] == cli.ClipboardClearHelperArgv {
		secs, _ := strconv.Atoi(os.Args[2])
		cli.RunClipboardClearHelper(secs)
		return
	}

	memguard.CatchSignal(func(_ os.Signal) {
		if cli.RestoreTerminal() {
			fmt.Fprintln(os.Stderr)
		}
	}, os.Interrupt)
	defer memguard.Purge()

	var c rootCLI
	ctx := kong.Parse(&c,
		kong.Name("fd0"),
		kong.Description("zero-knowledge secret store · v"+version+" "+buildinfo.Flavor),
		kong.UsageOnError(),
	)
	if err := maybeAutoUnlock(ctx, &c); err != nil {
		fmt.Fprintln(os.Stderr, "✗ "+err.Error())
		os.Exit(1)
	}
	if err := dispatch(ctx, &c); err != nil {
		if errors.Is(err, cli.ErrUpdateAvailable) {
			os.Exit(10)
		}
		fmt.Fprintln(os.Stderr, "✗ "+err.Error())
		os.Exit(1)
	}
}

func maybeAutoUnlock(kctx *kong.Context, c *rootCLI) error {
	if !commandNeedsUnlockedVault(kctx.Command()) {
		return nil
	}
	if !cli.IsTTY(os.Stdin) || !cli.IsTTY(os.Stderr) {
		return nil
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return err
	}
	if !cli.VaultExists(paths) {
		return fmt.Errorf("no vault found — run `fd0 init` first")
	}
	ac := agent.NewClient(paths.AgentSock)
	if ac.IsRunning() {
		st, err := ac.Status()
		if err == nil && st.Unlocked {
			return nil
		}
	}
	return cli.RunUnlock(context.Background(), c.Unlock.AgentBin, "")
}

func commandNeedsUnlockedVault(command string) bool {
	// The `secret ` forms and the hidden legacy spellings are the same
	// commands, so fold them together before asking rather than listing each
	// verb twice and risking one half going stale.
	command = legacySecretSpelling(command)
	switch command {
	case "get", "get <name>",
		"copy", "copy <name>",
		"set <name> <value>",
		"rm <name>",
		"list", "ls",
		"secret rename <name> <new-name>",
		"secret move <name>",
		"secret history <name>", "secret history show <name>",
		"secret history restore <name> <seq>",
		"scope create",
		"scope list", "scope ls",
		"scope members", "scope members <scope>",
		"scope add-member <card>",
		"scope remove-member <card>",
		"scope leave", "scope leave <scope>",
		"scope rename <scope> <new-label>",
		"card export",
		"card import <url>",
		"card list", "card ls",
		"card rm <label>",
		"recovery export <out>",
		"sync",
		"auth list", "auth ls",
		"auth add",
		"auth rm <id>",
		"key add <name>",
		"key edit <name>",
		"key list", "key ls",
		"key show <name>",
		"key rename <name> <new-name>",
		"key rm <name>",
		"key move <name>",
		"ssh add <alias>", "ssh add <alias> <conn>",
		"ssh list", "ssh ls",
		"ssh show <alias>",
		"ssh rm <alias>",
		"ssh tag <alias>",
		"ssh edit <alias>",
		"ssh rename <alias> <new-alias>",
		"ssh move <alias>",
		"key history <name>", "key history show <name>",
		"key history restore <name> <seq>",
		"ssh history <name>", "ssh history show <name>",
		"ssh history restore <name> <seq>",
		"pass history <name>", "pass history show <name>",
		"pass history restore <name> <seq>",
		"kube history <name>", "kube history show <name>",
		"kube history restore <name> <seq>",
		"talos history <name>", "talos history show <name>",
		"talos history restore <name> <seq>",
		"pass move <name>",
		"ssh", "ssh connect", "ssh connect <alias>", "ssh connect <alias> <cmd>",
		"sftp", "sftp connect", "sftp connect <host>",
		"sftp list <host>", "sftp list <host> <path>",
		"sftp ls <host>", "sftp ls <host> <path>",
		"sftp tree <host>", "sftp tree <host> <path>",
		"sftp stat <host> <path>",
		"sftp cp <host> <source> <dest>",
		"sftp mkdir <host> <path>",
		"sftp mv <host> <old> <new>",
		"sftp rm <host> <path>",
		"pass", "pass <query>", "pass browse", "pass browse <query>",
		"pass add <name>",
		"pass edit <name>",
		"pass find", "pass find <query>",
		"pass list", "pass ls",
		"pass show <name>",
		"pass rename <name> <new-name>",
		"pass rm <name>",
		"pass copy <name>", "pass copy <name> <field>",
		"pass field set <name> <path>", "pass field set <name> <path> <value>",
		"pass field get <name> <path>",
		"pass field rm <name> <path>",
		"pass notes <name>", "pass notes show <name>",
		"pass notes set <name>", "pass notes set <name> <text>",
		"pass notes rm <name>",
		"pass section add <name> <path>",
		"pass totp add <name> <uri>",
		"pass totp", "pass totp <name>", "pass totp <name> <path>",
		"pass totp code <name>", "pass totp code <name> <path>",
		"pass file add <name> <file>", "pass file add <name> <file> <path>",
		"pass file export <name> <path>",
		"talos enable",
		"talos add", "talos add <name>",
		"talos new <name>",
		"talos edit <name>",
		"talos list", "talos ls",
		"talos show <name>",
		"talos rename <name> <new-name>",
		"talos rm <name>",
		"talos move <name>",
		"talos sync",
		"talos role-add",
		"talos kubeconfig <name>",
		"talos secrets export <name>",
		"talos secrets import <name>",
		"talos secrets list", "talos secrets ls",
		"kube enable",
		"kube add", "kube add <name>",
		"kube edit <name>",
		"kube list", "kube ls",
		"kube show <name>",
		"kube rename <name> <new-name>",
		"kube rm <name>",
		"kube move <name>",
		"kube sync":
		return true
	default:
		return false
	}
}

// legacySecretSpelling maps `secret <verb>` onto the equivalent hidden
// top-level spelling, and leaves everything else alone.
//
// The two spellings are the same command, but kong parses them into two
// separate copies of the same structs. Reducing one to the other lets a single
// dispatch arm serve both, which is the only way they cannot drift.
// `secret rename/move/history` have no legacy form and pass through untouched.
func legacySecretSpelling(command string) string {
	rest, ok := strings.CutPrefix(command, "secret ")
	if !ok {
		return command
	}
	switch rest {
	case "get", "get <name>",
		"copy", "copy <name>",
		"set <name> <value>",
		"rm <name>",
		"list", "ls":
		return rest
	default:
		return command
	}
}

func dispatch(kctx *kong.Context, c *rootCLI) error {
	ctx := context.Background()
	command := legacySecretSpelling(kctx.Command())
	if command != kctx.Command() {
		// Reduced to its legacy spelling: read the flags kong actually filled.
		c.Get, c.Copy, c.Set, c.Rm, c.List =
			c.Secret.Get, c.Secret.Copy, c.Secret.Set, c.Secret.Rm, c.Secret.List
	}
	switch command {
	case "init":
		return cli.RunInit(ctx)
	case "unlock":
		return cli.RunUnlock(ctx, c.Unlock.AgentBin, c.Unlock.Method)
	case "lock":
		return cli.RunLock(ctx)
	case "agent status":
		return cli.RunAgentStatus(ctx)
	case "agent restart":
		return cli.RunAgentRestart(ctx, c.Agent.Restart.AgentBin)
	case "agent stop":
		return cli.RunAgentStop(ctx)
	case "status":
		return cli.RunStatus(ctx)
	case "get", "get <name>":
		return cli.RunGet(ctx, c.Get.Scope, c.Get.Name, c.Get.Raw)
	case "copy", "copy <name>":
		clearAfter, err := resolveClipboardClear(c.Copy.ClearAfter)
		if err != nil {
			return err
		}
		return cli.RunCopy(ctx, c.Copy.Scope, c.Copy.Name, clearAfter)
	case "set <name> <value>":
		return cli.RunSecretSet(ctx, c.Set.Scope, c.Set.Name, c.Set.Value)
	case "rm <name>":
		return cli.RunSecretRemove(ctx, c.Rm.Scope, c.Rm.Name, c.Rm.Yes)
	case "list", "ls":
		return cli.RunSecretList(ctx, c.List.JSON, c.List.All)
	case "secret rename <name> <new-name>":
		s, err := cli.Open(ctx)
		if err != nil {
			return err
		}
		defer s.Close()
		// nil retitle: a plain secret's payload is the value, with no name
		// inside it to keep in step.
		return s.RenameItem(ctx, cli.KindSecret, c.Secret.Rename.Scope,
			c.Secret.Rename.Name, c.Secret.Rename.New, c.Secret.Rename.Force, nil)
	case "secret move <name>":
		s, err := cli.Open(ctx)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.MoveItem(ctx, cli.KindSecret, c.Secret.Move.Name, c.Secret.Move.From, c.Secret.Move.ToScope, c.Secret.Move.Force)
	case "secret history <name>", "secret history show <name>":
		return cli.RunItemHistory(ctx, cli.KindSecret, c.Secret.History.Show.Scope, c.Secret.History.Show.Name, c.Secret.History.Show.JSON)
	case "secret history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindSecret, c.Secret.History.Restore.Scope, c.Secret.History.Restore.Name, c.Secret.History.Restore.Seq)
	case "scope create":
		return cli.RunScopeCreate(ctx, c.Scope.Create.Label)
	case "scope list", "scope ls":
		return cli.RunScopeList(ctx)
	case "scope members", "scope members <scope>":
		return cli.RunScopeMembers(ctx, c.Scope.Members.Scope)
	case "scope add-member <card>":
		return cli.RunScopeAddMember(ctx, c.Scope.AddMember.Scope, c.Scope.AddMember.Card)
	case "scope remove-member <card>":
		return cli.RunScopeRemoveMember(ctx, c.Scope.RemoveMember.Scope, c.Scope.RemoveMember.Card, c.Scope.RemoveMember.Yes)
	case "scope leave", "scope leave <scope>":
		return cli.RunScopeLeave(ctx, c.Scope.Leave.Scope, c.Scope.Leave.Yes)
	case "scope rename <scope> <new-label>":
		return cli.RunScopeRename(ctx, c.Scope.Rename.Scope, c.Scope.Rename.NewLabel)
	case "card export":
		return cli.RunCardExport(ctx)
	case "card import <url>":
		return cli.RunCardImport(ctx, c.Card.Import.URL, c.Card.Import.Label, c.Card.Import.Yes)
	case "card list", "card ls":
		return cli.RunCardList(ctx)
	case "card rm <label>":
		return cli.RunCardRemove(ctx, c.Card.Remove.Label, c.Card.Remove.Yes)
	case "recovery export <out>":
		return cli.RunRecoveryExport(ctx, c.Recovery.Export.Out)
	case "recovery import <in>":
		return cli.RunRecoveryImport(ctx, c.Recovery.Import.In, c.Recovery.Import.Yes)
	case "sync":
		if c.Sync.WaitLock != "" {
			os.Setenv("FD0_LOCK_WAIT", c.Sync.WaitLock)
		}
		return cli.RunSyncPrimary(ctx, c.Sync.Server)
	case "doctor":
		return cli.RunDoctor(ctx)
	case "auth list", "auth ls":
		return cli.RunAuthList(ctx)
	case "auth default", "auth default <method>":
		return cli.RunAuthDefault(ctx, c.Auth.Default.Method, c.Auth.Default.Clear)
	case "auth add":
		if c.Auth.Add.Yubikey {
			return cli.RunAuthAddYubikey(ctx, c.Auth.Add.Touch, c.Auth.Add.Force)
		}
		return cli.RunAuthAdd(ctx)
	case "auth rm <id>":
		return cli.RunAuthRemove(ctx, c.Auth.Remove.ID, c.Auth.Remove.Yes)
	case "version":
		fmt.Printf("fd0 %s %s\n", version, buildinfo.Flavor)
		return nil
	case "update":
		return cli.RunUpdate(ctx, cli.UpdateOptions{
			CurrentVersion:   version,
			CurrentFlavor:    buildinfo.Flavor,
			ManagedByDesktop: distribution == "desktop",
			Version:          c.Update.Version,
			Flavor:           c.Update.Flavor,
			Prefix:           c.Update.Prefix,
			System:           c.Update.System,
			CheckOnly:        c.Update.Check,
			Yes:              c.Update.Yes,
			AllowDowngrade:   c.Update.AllowDowngrade,
		})
	case "browser enable":
		return cli.RunBrowserEnable(c.Browser.Enable.Host)
	case "browser disable":
		return cli.RunBrowserDisable()

	// ─── key ──────────────────────────────────────────────────────────
	case "key add <name>":
		return cli.RunKeyAdd(ctx, cli.KeyOpts{
			Name:       c.Key.Add.Name,
			Scope:      c.Key.Add.Scope,
			Type:       c.Key.Add.Type,
			Comment:    c.Key.Add.Comment,
			ImportPath: c.Key.Add.Import,
			Passphrase: c.Key.Add.Passphrase,
			Force:      c.Key.Add.Force,
		})
	case "key edit <name>":
		return cli.RunKeyEdit(ctx, cli.KeyEditOpts{
			Name:    c.Key.Edit.Name,
			Scope:   c.Key.Edit.Scope,
			Comment: c.Key.Edit.Comment,
		})
	case "key list", "key ls":
		return cli.RunKeyList(ctx, c.Key.List.Scope, nil, nil, c.Key.List.JSON)
	case "key show <name>":
		return cli.RunKeyShow(ctx, c.Key.Show.Scope, c.Key.Show.Name, c.Key.Show.Pub)
	case "key rename <name> <new-name>":
		return cli.RunKeyRename(ctx, c.Key.Rename.Scope, c.Key.Rename.Name, c.Key.Rename.New, c.Key.Rename.Force)
	case "key rm <name>":
		return cli.RunKeyRemove(ctx, c.Key.Rm.Scope, c.Key.Rm.Name, c.Key.Rm.Yes)
	case "key move <name>":
		return cli.RunKeyMove(ctx, c.Key.Move.Name, c.Key.Move.From, c.Key.Move.ToScope, c.Key.Move.Force)

	// ─── ssh ──────────────────────────────────────────────────────────
	case "ssh enable":
		return cli.RunSSHEnable(ctx)
	case "ssh disable":
		return cli.RunSSHDisable(ctx)
	case "ssh sock":
		return cli.RunSSHSock(ctx)

	case "ssh add <alias>", "ssh add <alias> <conn>":
		return cli.RunHostAdd(ctx, cli.HostAddOpts{
			Alias:       c.Ssh.Add.Alias,
			ConnString:  c.Ssh.Add.Conn,
			User:        c.Ssh.Add.User,
			Port:        c.Ssh.Add.Port,
			Hostname:    c.Ssh.Add.Hostname,
			KeyName:     c.Ssh.Add.Key,
			WithKey:     c.Ssh.Add.WithKey,
			WithKeyName: c.Ssh.Add.WithKeyName,
			ProxyJump:   c.Ssh.Add.Jump,
			Tags:        c.Ssh.Add.Tag,
			Description: c.Ssh.Add.Description,
			Options:     c.Ssh.Add.Opt,
			Scope:       c.Ssh.Add.Scope,
			Force:       c.Ssh.Add.Force,
		})
	case "ssh list", "ssh ls":
		return cli.RunHostList(ctx, c.Ssh.List.Scope, c.Ssh.List.Tag, c.Ssh.List.NoTag, c.Ssh.List.JSON)
	case "ssh show <alias>":
		return cli.RunHostShow(ctx, c.Ssh.Show.Scope, c.Ssh.Show.Alias)
	case "ssh rm <alias>":
		return cli.RunHostRemove(ctx, c.Ssh.Rm.Scope, c.Ssh.Rm.Alias, c.Ssh.Rm.Yes)
	case "ssh tag <alias>":
		return cli.RunHostTag(ctx, c.Ssh.Tag.Scope, c.Ssh.Tag.Alias, c.Ssh.Tag.Add, c.Ssh.Tag.Remove)
	case "ssh edit <alias>":
		return cli.RunHostEdit(ctx, cli.HostEditOpts{
			Alias:        c.Ssh.Edit.Alias,
			Scope:        c.Ssh.Edit.Scope,
			Hostname:     c.Ssh.Edit.Hostname,
			User:         c.Ssh.Edit.User,
			Port:         c.Ssh.Edit.Port,
			KeyName:      c.Ssh.Edit.KeyName,
			ProxyJump:    c.Ssh.Edit.ProxyJump,
			Description:  c.Ssh.Edit.Description,
			Tags:         c.Ssh.Edit.Tags.Ptr(),
			Options:      c.Ssh.Edit.Options,
			ClearOptions: c.Ssh.Edit.ClearOptions,
		})
	case "ssh rename <alias> <new-alias>":
		return cli.RunHostRename(ctx, c.Ssh.Rename.Scope, c.Ssh.Rename.Alias, c.Ssh.Rename.New, c.Ssh.Rename.Force)
	case "key history <name>", "key history show <name>":
		return cli.RunItemHistory(ctx, cli.KindKey, c.Key.History.Show.Scope, c.Key.History.Show.Name, c.Key.History.Show.JSON)
	case "key history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindKey, c.Key.History.Restore.Scope, c.Key.History.Restore.Name, c.Key.History.Restore.Seq)
	case "ssh history <name>", "ssh history show <name>":
		return cli.RunItemHistory(ctx, cli.KindHost, c.Ssh.History.Show.Scope, c.Ssh.History.Show.Name, c.Ssh.History.Show.JSON)
	case "ssh history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindHost, c.Ssh.History.Restore.Scope, c.Ssh.History.Restore.Name, c.Ssh.History.Restore.Seq)
	case "pass history <name>", "pass history show <name>":
		return cli.RunItemHistory(ctx, cli.KindPass, c.Pass.History.Show.Scope, c.Pass.History.Show.Name, c.Pass.History.Show.JSON)
	case "pass history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindPass, c.Pass.History.Restore.Scope, c.Pass.History.Restore.Name, c.Pass.History.Restore.Seq)
	case "kube history <name>", "kube history show <name>":
		return cli.RunItemHistory(ctx, cli.KindKube, c.Kube.History.Show.Scope, c.Kube.History.Show.Name, c.Kube.History.Show.JSON)
	case "kube history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindKube, c.Kube.History.Restore.Scope, c.Kube.History.Restore.Name, c.Kube.History.Restore.Seq)
	case "talos history <name>", "talos history show <name>":
		return cli.RunItemHistory(ctx, cli.KindTalos, c.Talos.History.Show.Scope, c.Talos.History.Show.Name, c.Talos.History.Show.JSON)
	case "talos history restore <name> <seq>":
		return cli.RunItemRestore(ctx, cli.KindTalos, c.Talos.History.Restore.Scope, c.Talos.History.Restore.Name, c.Talos.History.Restore.Seq)
	case "pass move <name>":
		s, err := cli.Open(ctx)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.MoveItem(ctx, cli.KindPass, c.Pass.Move.Name, c.Pass.Move.From, c.Pass.Move.ToScope, c.Pass.Move.Force)
	case "ssh move <alias>":
		return cli.RunHostMove(ctx, c.Ssh.Move.Alias, c.Ssh.Move.From, c.Ssh.Move.ToScope, c.Ssh.Move.Force)

	case "ssh", "ssh connect", "ssh connect <alias>", "ssh connect <alias> <cmd>":
		return cli.RunSSHConnect(ctx, c.Ssh.Connect.Scope, c.Ssh.Connect.Alias, c.Ssh.Connect.Cmd, c.Ssh.Connect.Tag)

	// ─── sftp ────────────────────────────────────────────────────────
	case "sftp", "sftp connect", "sftp connect <host>":
		return cli.RunSFTPInteractive(ctx, c.Sftp.Connect.Host, c.Sftp.Connect.Scope)
	case "sftp list <host>", "sftp list <host> <path>", "sftp ls <host>", "sftp ls <host> <path>":
		return cli.RunSFTPList(ctx, cli.SFTPListOpts{
			Host: c.Sftp.List.Host, Path: c.Sftp.List.Path, Scope: c.Sftp.List.Scope, JSON: c.Sftp.List.JSON,
		})
	case "sftp tree <host>", "sftp tree <host> <path>":
		return cli.RunSFTPTree(ctx, cli.SFTPTreeOpts{
			SFTPListOpts: cli.SFTPListOpts{
				Host: c.Sftp.Tree.Host, Path: c.Sftp.Tree.Path, Scope: c.Sftp.Tree.Scope, JSON: c.Sftp.Tree.JSON,
			},
			Depth: c.Sftp.Tree.Depth,
		})
	case "sftp stat <host> <path>":
		return cli.RunSFTPStat(ctx, cli.SFTPListOpts{
			Host: c.Sftp.Stat.Host, Path: c.Sftp.Stat.Path, Scope: c.Sftp.Stat.Scope, JSON: c.Sftp.Stat.JSON,
		})
	case "sftp cp <host> <source> <dest>":
		return cli.RunSFTPCopy(ctx, cli.SFTPCopyOpts{
			Host:      c.Sftp.Copy.Host,
			Source:    c.Sftp.Copy.Source,
			Dest:      c.Sftp.Copy.Dest,
			Scope:     c.Sftp.Copy.Scope,
			Recursive: c.Sftp.Copy.Recursive,
			Force:     c.Sftp.Copy.Force,
		})
	case "sftp mkdir <host> <path>":
		return cli.RunSFTPMkdir(ctx, cli.SFTPMkdirOpts{
			Host: c.Sftp.Mkdir.Host, Path: c.Sftp.Mkdir.Path, Scope: c.Sftp.Mkdir.Scope, Parents: c.Sftp.Mkdir.Parents,
		})
	case "sftp mv <host> <old> <new>":
		return cli.RunSFTPMove(ctx, cli.SFTPMoveOpts{
			Host: c.Sftp.Move.Host, Old: c.Sftp.Move.Old, New: c.Sftp.Move.New, Scope: c.Sftp.Move.Scope, Force: c.Sftp.Move.Force,
		})
	case "sftp rm <host> <path>":
		return cli.RunSFTPRemove(ctx, cli.SFTPRemoveOpts{
			Host:      c.Sftp.Remove.Host,
			Path:      c.Sftp.Remove.Path,
			Scope:     c.Sftp.Remove.Scope,
			Recursive: c.Sftp.Remove.Recursive,
			Yes:       c.Sftp.Remove.Yes,
		})

	// ─── pass ─────────────────────────────────────────────────────────
	case "pass", "pass <query>", "pass browse", "pass browse <query>":
		clearAfter, err := resolveClipboardClear(c.Pass.Browse.ClearAfter)
		if err != nil {
			return err
		}
		return cli.RunPassBrowse(ctx, c.Pass.Browse.Scope, c.Pass.Browse.Query, clearAfter, cli.PassTagFilter{Tags: c.Pass.Browse.Tag, Untagged: c.Pass.Browse.Untagged})
	case "pass tags add <name> <tags>":
		return cli.RunPassTagsChange(ctx, c.Pass.Tags.Add.Scope, c.Pass.Tags.Add.Name, "add", c.Pass.Tags.Add.Tags)
	case "pass tags rm <name> <tags>":
		return cli.RunPassTagsChange(ctx, c.Pass.Tags.Rm.Scope, c.Pass.Tags.Rm.Name, "rm", c.Pass.Tags.Rm.Tags)
	case "pass tags clear <name>":
		return cli.RunPassTagsChange(ctx, c.Pass.Tags.Clear.Scope, c.Pass.Tags.Clear.Name, "clear", nil)
	case "pass tags list":
		return cli.RunPassTagsList(ctx, c.Pass.Tags.List.Scope, c.Pass.Tags.List.JSON)
	case "pass add <name>":
		return cli.RunPassAdd(ctx, cli.PassAddOpts{
			Name:  c.Pass.Add.Name,
			Tags:  c.Pass.Add.Tag,
			URL:   c.Pass.Add.URL,
			Scope: c.Pass.Add.Scope,
			Force: c.Pass.Add.Force,
			Notes: c.Pass.Add.Notes,
		})
	case "pass edit <name>":
		return cli.RunPassEdit(ctx, cli.PassEditOpts{
			Name:  c.Pass.Edit.Name,
			Scope: c.Pass.Edit.Scope,
			Title: c.Pass.Edit.Title,
			URLs:  c.Pass.Edit.URL.Ptr(),
		})
	case "pass find", "pass find <query>":
		return cli.RunPassFind(ctx, c.Pass.Find.Scope, c.Pass.Find.Query, c.Pass.Find.URL, c.Pass.Find.JSON, cli.PassTagFilter{Tags: c.Pass.Find.Tag, Untagged: c.Pass.Find.Untagged})
	case "pass list", "pass ls":
		return cli.RunPassList(ctx, c.Pass.List.Scope, c.Pass.List.JSON, cli.PassTagFilter{Tags: c.Pass.List.Tag, Untagged: c.Pass.List.Untagged})
	case "pass show <name>":
		return cli.RunPassShow(ctx, c.Pass.Show.Scope, c.Pass.Show.Name, c.Pass.Show.Reveal, c.Pass.Show.JSON)
	case "pass rename <name> <new-name>":
		return cli.RunPassRename(ctx, c.Pass.Rename.Scope, c.Pass.Rename.Name, c.Pass.Rename.New, c.Pass.Rename.Force)
	case "pass rm <name>":
		return cli.RunPassRemove(ctx, c.Pass.Rm.Scope, c.Pass.Rm.Name, c.Pass.Rm.Yes)
	case "pass copy <name>", "pass copy <name> <field>":
		clearAfter, err := resolveClipboardClear(c.Pass.Copy.ClearAfter)
		if err != nil {
			return err
		}
		return cli.RunPassCopy(ctx, c.Pass.Copy.Scope, c.Pass.Copy.Name, c.Pass.Copy.Field, clearAfter)
	case "pass generate":
		return cli.RunPassGenerate(c.Pass.Generate.Length, c.Pass.Generate.Raw)
	case "pass field set <name> <path>", "pass field set <name> <path> <value>":
		return cli.RunPassFieldSet(ctx, cli.PassFieldSetOpts{
			Item:     c.Pass.Field.Set.Name,
			Path:     c.Pass.Field.Set.Path,
			Value:    c.Pass.Field.Set.Value,
			Kind:     c.Pass.Field.Set.Type,
			Secret:   c.Pass.Field.Set.Secret,
			Generate: c.Pass.Field.Set.Generate,
			Length:   c.Pass.Field.Set.Length,
			Scope:    c.Pass.Field.Set.Scope,
		})
	case "pass field get <name> <path>":
		return cli.RunPassFieldGet(ctx, c.Pass.Field.Get.Scope, c.Pass.Field.Get.Name, c.Pass.Field.Get.Path, c.Pass.Field.Get.Raw)
	case "pass field rm <name> <path>":
		return cli.RunPassFieldRemove(ctx, c.Pass.Field.Rm.Scope, c.Pass.Field.Rm.Name, c.Pass.Field.Rm.Path, c.Pass.Field.Rm.Yes)
	case "pass notes <name>", "pass notes show <name>":
		return cli.RunPassNotes(ctx, c.Pass.Notes.Show.Scope, c.Pass.Notes.Show.Name)
	case "pass notes set <name>", "pass notes set <name> <text>":
		return cli.RunPassNotesSet(ctx, cli.PassNotesSetOpts{
			Item:  c.Pass.Notes.Set.Name,
			Scope: c.Pass.Notes.Set.Scope,
			Text:  c.Pass.Notes.Set.Text,
			// The <text> form means a positional was supplied — including an
			// explicit "", which clears the note instead of opening $EDITOR.
			HasText: kctx.Command() == "pass notes set <name> <text>",
		})
	case "pass notes rm <name>":
		return cli.RunPassNotesRemove(ctx, c.Pass.Notes.Rm.Scope, c.Pass.Notes.Rm.Name, c.Pass.Notes.Rm.Yes)
	case "pass section add <name> <path>":
		return cli.RunPassSectionAdd(ctx, c.Pass.Section.Add.Scope, c.Pass.Section.Add.Name, c.Pass.Section.Add.Path)
	case "pass totp add <name> <uri>":
		return cli.RunPassTOTPAdd(ctx, c.Pass.TOTP.Add.Scope, c.Pass.TOTP.Add.Name, c.Pass.TOTP.Add.Path, c.Pass.TOTP.Add.URI)
	case "pass totp", "pass totp <name>", "pass totp <name> <path>",
		"pass totp code <name>", "pass totp code <name> <path>":
		return cli.RunPassTOTP(ctx, c.Pass.TOTP.Code.Scope, c.Pass.TOTP.Code.Name, c.Pass.TOTP.Code.Path, c.Pass.TOTP.Code.Raw)
	case "pass file add <name> <file>", "pass file add <name> <file> <path>":
		return cli.RunPassFileAdd(ctx, cli.PassFileAddOpts{
			Item:  c.Pass.File.Add.Name,
			File:  c.Pass.File.Add.File,
			Path:  c.Pass.File.Add.Path,
			MIME:  c.Pass.File.Add.MIME,
			Scope: c.Pass.File.Add.Scope,
		})
	case "pass file export <name> <path>":
		return cli.RunPassFileExport(ctx, c.Pass.File.Export.Scope, c.Pass.File.Export.Name, c.Pass.File.Export.Path, c.Pass.File.Export.Out, c.Pass.File.Export.Force)

	// ── talos ─────────────────────────────────────────────────
	case "talos enable":
		return cli.RunTalosEnable(ctx, c.Talos.Enable.Merge)
	case "talos disable":
		return cli.RunTalosDisable(ctx)
	case "talos add", "talos add <name>":
		return cli.RunTalosAdd(ctx, cli.TalosAddOpts{
			Name:          c.Talos.Add.Name,
			Endpoints:     c.Talos.Add.Endpoint,
			Nodes:         c.Talos.Add.Node,
			CA:            c.Talos.Add.CA,
			CAFile:        c.Talos.Add.CAFile,
			Crt:           c.Talos.Add.Crt,
			CrtFile:       c.Talos.Add.CrtFile,
			Key:           c.Talos.Add.Key,
			KeyFile:       c.Talos.Add.KeyFile,
			FromConfig:    c.Talos.Add.FromConfig,
			ImportContext: c.Talos.Add.ImportContext,
			Role:          c.Talos.Add.Role,
			Description:   c.Talos.Add.Description,
			Tags:          c.Talos.Add.Tag,
			Scope:         c.Talos.Add.Scope,
			Force:         c.Talos.Add.Force,
		})
	case "talos new <name>":
		return cli.RunTalosNew(ctx, cli.TalosNewOpts{
			Name:        c.Talos.New.Name,
			Endpoint:    c.Talos.New.Endpoint,
			OutputDir:   c.Talos.New.OutputDir,
			Scope:       c.Talos.New.Scope,
			VaultScope:  c.Talos.New.VaultScope,
			Description: c.Talos.New.Description,
			Tags:        c.Talos.New.Tag,
			Force:       c.Talos.New.Force,
		})
	case "talos edit <name>":
		return cli.RunTalosEdit(ctx, cli.TalosEditOpts{
			Name:        c.Talos.Edit.Name,
			Scope:       c.Talos.Edit.Scope,
			Endpoints:   c.Talos.Edit.Endpoint.Ptr(),
			Nodes:       c.Talos.Edit.Node.Ptr(),
			Role:        c.Talos.Edit.Role,
			Description: c.Talos.Edit.Description,
			Tags:        c.Talos.Edit.Tag.Ptr(),
		})
	case "talos list", "talos ls":
		return cli.RunTalosList(ctx, c.Talos.List.Scope, c.Talos.List.Tag, c.Talos.List.NoTag, c.Talos.List.JSON)
	case "talos show <name>":
		return cli.RunTalosShow(ctx, c.Talos.Show.Scope, c.Talos.Show.Name)
	case "talos rename <name> <new-name>":
		return cli.RunTalosRename(ctx, c.Talos.Rename.Scope, c.Talos.Rename.Name, c.Talos.Rename.New, c.Talos.Rename.Force)
	case "talos rm <name>":
		return cli.RunTalosRemove(ctx, c.Talos.Rm.Scope, c.Talos.Rm.Name, c.Talos.Rm.Yes)
	case "talos move <name>":
		return cli.RunTalosMove(ctx, c.Talos.Move.Name, c.Talos.Move.From, c.Talos.Move.ToScope, c.Talos.Move.Force)
	case "talos sync":
		return cli.RunTalosSync(ctx, c.Talos.Sync.Merge, c.Talos.Sync.ReplaceActive)
	case "talos role-add":
		return cli.RunTalosRoleAdd(ctx, cli.TalosRoleAddOpts{
			SourceContext: c.Talos.RoleAdd.From,
			NewName:       c.Talos.RoleAdd.NewName,
			Role:          c.Talos.RoleAdd.Role,
			TTL:           c.Talos.RoleAdd.TTL,
			Scope:         c.Talos.RoleAdd.Scope,
			Description:   c.Talos.RoleAdd.Description,
			Tags:          c.Talos.RoleAdd.Tag,
		})
	case "talos kubeconfig <name>":
		return cli.RunTalosKubeconfig(ctx, c.Talos.Kubeconfig.Name, c.Talos.Kubeconfig.Scope)
	case "talos secrets export <name>":
		return cli.RunTalosSecretsExport(ctx,
			c.Talos.Secrets.Export.Scope,
			c.Talos.Secrets.Export.Name,
			c.Talos.Secrets.Export.Out,
			c.Talos.Secrets.Export.Force)
	case "talos secrets import <name>":
		return cli.RunTalosSecretsImport(ctx,
			c.Talos.Secrets.Import.Scope,
			c.Talos.Secrets.Import.Name,
			c.Talos.Secrets.Import.In)
	case "talos secrets list", "talos secrets ls":
		return cli.RunTalosSecretsList(ctx, c.Talos.Secrets.List.Scope)

	// ── kube ──────────────────────────────────────────────────
	case "kube enable":
		return cli.RunKubeEnable(ctx, c.Kube.Enable.Merge)
	case "kube disable":
		return cli.RunKubeDisable(ctx)
	case "kube add", "kube add <name>":
		return cli.RunKubeAdd(ctx, cli.KubeAddOpts{
			Name:                  c.Kube.Add.Name,
			Server:                c.Kube.Add.Server,
			CA:                    c.Kube.Add.CA,
			CAFile:                c.Kube.Add.CAFile,
			ClientCert:            c.Kube.Add.ClientCert,
			ClientCertFile:        c.Kube.Add.ClientCertFile,
			ClientKey:             c.Kube.Add.ClientKey,
			ClientKeyFile:         c.Kube.Add.ClientKeyFile,
			Token:                 c.Kube.Add.Token,
			Namespace:             c.Kube.Add.Namespace,
			InsecureSkipTLSVerify: c.Kube.Add.InsecureSkipTLSVerify,
			FromConfig:            c.Kube.Add.FromConfig,
			ImportContext:         c.Kube.Add.ImportContext,
			Description:           c.Kube.Add.Description,
			Tags:                  c.Kube.Add.Tag,
			Scope:                 c.Kube.Add.Scope,
			Force:                 c.Kube.Add.Force,
		})
	case "kube edit <name>":
		return cli.RunKubeEdit(ctx, cli.KubeEditOpts{
			Name:        c.Kube.Edit.Name,
			Scope:       c.Kube.Edit.Scope,
			Server:      c.Kube.Edit.Server,
			Namespace:   c.Kube.Edit.Namespace,
			Description: c.Kube.Edit.Description,
			Tags:        c.Kube.Edit.Tag.Ptr(),
		})
	case "kube list", "kube ls":
		return cli.RunKubeList(ctx, c.Kube.List.Scope, c.Kube.List.Tag, c.Kube.List.NoTag, c.Kube.List.JSON)
	case "kube show <name>":
		return cli.RunKubeShow(ctx, c.Kube.Show.Scope, c.Kube.Show.Name)
	case "kube rename <name> <new-name>":
		return cli.RunKubeRename(ctx, c.Kube.Rename.Scope, c.Kube.Rename.Name, c.Kube.Rename.New, c.Kube.Rename.Force)
	case "kube rm <name>":
		return cli.RunKubeRemove(ctx, c.Kube.Rm.Scope, c.Kube.Rm.Name, c.Kube.Rm.Yes)
	case "kube move <name>":
		return cli.RunKubeMove(ctx, c.Kube.Move.Name, c.Kube.Move.From, c.Kube.Move.ToScope, c.Kube.Move.Force)
	case "kube sync":
		return cli.RunKubeSync(ctx, c.Kube.Sync.Merge, c.Kube.Sync.ReplaceActive)
	}
	return fmt.Errorf("unknown command %q", kctx.Command())
}

// resolveClipboardClear returns the effective clear-after duration. Order:
//
//  1. CLI flag (--clear-after=...) when non-empty
//  2. [clipboard].clear_after_seconds from ~/.fd0/config.toml
//  3. 30s default
func resolveClipboardClear(flag string) (time.Duration, error) {
	if flag != "" {
		d, err := time.ParseDuration(flag)
		if err != nil {
			return 0, fmt.Errorf("--clear-after %q: %w", flag, err)
		}
		return d, nil
	}
	paths, err := fdhome.Resolve()
	if err == nil {
		cfg, err := fdhome.LoadConfig(paths.Config)
		if err == nil && cfg.Clipboard.ClearAfterSeconds > 0 {
			return time.Duration(cfg.Clipboard.ClearAfterSeconds) * time.Second, nil
		}
	}
	return 30 * time.Second, nil
}
