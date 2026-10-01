package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/sftpclient"
)

const (
	remotePathPrefix = "remote:"
	maxSFTPTreeDepth = 32
	maxSFTPTreeItems = 10_000
)

type SFTPListOpts struct {
	Host  string
	Path  string
	Scope string
	JSON  bool
}

type SFTPTreeOpts struct {
	SFTPListOpts
	Depth int
}

type SFTPCopyOpts struct {
	Host      string
	Source    string
	Dest      string
	Scope     string
	Recursive bool
	Force     bool
}

type SFTPMkdirOpts struct {
	Host    string
	Path    string
	Scope   string
	Parents bool
}

type SFTPMoveOpts struct {
	Host  string
	Old   string
	New   string
	Scope string
	Force bool
}

type SFTPRemoveOpts struct {
	Host      string
	Path      string
	Scope     string
	Recursive bool
	Yes       bool
}

type sftpTreeEntry struct {
	sftpclient.Entry
	Depth int `json:"depth"`
}

func RunSFTPInteractive(ctx context.Context, host, scope string) error {
	connection, err := PrepareOpenSSHConnection(ctx, scope, host)
	if err != nil {
		return err
	}
	binary, err := exec.LookPath("sftp")
	if err != nil {
		return fmt.Errorf("sftp client not on PATH: %w", err)
	}
	args := []string{"sftp"}
	if connection.ConfigPath != "" {
		args = append(args, "-F", connection.ConfigPath)
	}
	args = append(args, connection.Alias)
	if err := syscall.Exec(binary, args, os.Environ()); err != nil {
		command := exec.CommandContext(ctx, binary, args[1:]...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		return command.Run()
	}
	return nil
}

func RunSFTPList(ctx context.Context, opts SFTPListOpts) error {
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	remotePath, err := resolveRemotePath(client, opts.Path)
	if err != nil {
		return err
	}
	entries, err := client.ReadDir(ctx, remotePath)
	if err != nil {
		return err
	}
	sortSFTPEntries(entries)
	if opts.JSON {
		return json.NewEncoder(os.Stdout).Encode(entries)
	}
	for _, entry := range entries {
		fmt.Fprintf(os.Stdout, "%-10s %10s  %s  %s\n",
			entry.Mode, formatByteSize(entry.Size), entry.ModifiedAt.Local().Format("2006-01-02 15:04"), entry.Name)
	}
	return nil
}

func RunSFTPTree(ctx context.Context, opts SFTPTreeOpts) error {
	if opts.Depth == 0 {
		opts.Depth = 3
	}
	if opts.Depth < 1 || opts.Depth > maxSFTPTreeDepth {
		return fmt.Errorf("tree depth must be between 1 and %d", maxSFTPTreeDepth)
	}
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	root, err := resolveRemotePath(client, opts.Path)
	if err != nil {
		return err
	}
	var rows []sftpTreeEntry
	if err := collectSFTPTree(ctx, client, root, 0, opts.Depth, &rows); err != nil {
		return err
	}
	if opts.JSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}
	fmt.Fprintln(os.Stdout, root)
	for _, row := range rows {
		branch := "├── "
		fmt.Fprintf(os.Stdout, "%s%s%s\n", strings.Repeat("    ", row.Depth), branch, row.Name)
	}
	return nil
}

func RunSFTPStat(ctx context.Context, opts SFTPListOpts) error {
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	remotePath, err := resolveRemotePath(client, opts.Path)
	if err != nil {
		return err
	}
	entry, err := client.Stat(remotePath, false)
	if err != nil {
		return err
	}
	if opts.JSON {
		return json.NewEncoder(os.Stdout).Encode(entry)
	}
	fmt.Fprintf(os.Stdout, "path:     %s\n", entry.Path)
	fmt.Fprintf(os.Stdout, "type:     %s\n", entry.Type)
	fmt.Fprintf(os.Stdout, "size:     %d\n", entry.Size)
	fmt.Fprintf(os.Stdout, "mode:     %s\n", entry.Mode)
	fmt.Fprintf(os.Stdout, "modified: %s\n", entry.ModifiedAt.Local().Format(time.RFC3339))
	if entry.LinkTarget != "" {
		fmt.Fprintf(os.Stdout, "target:   %s\n", entry.LinkTarget)
	}
	return nil
}

func RunSFTPCopy(ctx context.Context, opts SFTPCopyOpts) error {
	defer trackCleanup()()
	sourceRemote, err := validateSFTPCopyOperands(opts.Source, opts.Dest)
	if err != nil {
		return err
	}
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	progress := cliTransferProgress()
	if sourceRemote {
		remoteSource, err := nonEmptyRemoteOperand(opts.Source)
		if err != nil {
			return err
		}
		result, err := client.DownloadPath(ctx, remoteSource, opts.Dest, sftpclient.TransferOptions{
			Recursive: opts.Recursive,
			Force:     opts.Force,
		}, progress)
		if err == nil {
			stderrln("✓ downloaded %s (%s)", result.Path, formatByteSize(result.Bytes))
		}
		return err
	}
	remoteDest, err := nonEmptyRemoteOperand(opts.Dest)
	if err != nil {
		return err
	}
	result, err := client.UploadPath(ctx, opts.Source, remoteDest, sftpclient.TransferOptions{
		Recursive: opts.Recursive,
		Force:     opts.Force,
	}, progress)
	if err == nil {
		stderrln("✓ uploaded %s (%s)", result.Path, formatByteSize(result.Bytes))
	}
	return err
}

func validateSFTPCopyOperands(source, destination string) (bool, error) {
	sourceRemote := strings.HasPrefix(source, remotePathPrefix)
	destRemote := strings.HasPrefix(destination, remotePathPrefix)
	if sourceRemote == destRemote {
		return false, errors.New("exactly one cp operand must start with remote:")
	}
	return sourceRemote, nil
}

func RunSFTPMkdir(ctx context.Context, opts SFTPMkdirOpts) error {
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	remotePath, err := requiredRemotePath(opts.Path)
	if err != nil {
		return err
	}
	return client.Mkdir(remotePath, opts.Parents)
}

func RunSFTPMove(ctx context.Context, opts SFTPMoveOpts) error {
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	oldPath, err := requiredRemotePath(opts.Old)
	if err != nil {
		return err
	}
	newPath, err := requiredRemotePath(opts.New)
	if err != nil {
		return err
	}
	if _, err := client.Stat(newPath, false); err == nil && !opts.Force {
		return fmt.Errorf("remote destination %q already exists; use --force to replace it", newPath)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return client.Rename(oldPath, newPath, opts.Force)
}

func RunSFTPRemove(ctx context.Context, opts SFTPRemoveOpts) error {
	remotePath, err := requiredRemotePath(opts.Path)
	if err != nil {
		return err
	}
	if !opts.Yes {
		if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
			return errors.New("refusing to remove a remote path without --yes in a non-interactive terminal")
		}
		if err := confirmDanger(false, fmt.Sprintf("Remove remote path %q?", remotePath)); err != nil {
			return err
		}
	}
	client, err := openSFTP(ctx, opts.Host, opts.Scope)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return client.Remove(ctx, remotePath, opts.Recursive)
}

func openSFTP(ctx context.Context, host, scope string) (*sftpclient.Client, error) {
	connection, err := PrepareOpenSSHConnection(ctx, scope, host)
	if err != nil {
		return nil, err
	}
	return sftpclient.Dial(ctx, sftpclient.Command{
		Binary: connection.SSHBinary,
		Args:   connection.SFTPSubsystemArgs(),
		Env:    os.Environ(),
	})
}

func resolveRemotePath(client *sftpclient.Client, value string) (string, error) {
	if value != "" {
		return requiredRemotePath(value)
	}
	return client.WorkingDirectory()
}

func requiredRemotePath(value string) (string, error) {
	value = strings.TrimPrefix(value, remotePathPrefix)
	if value == "" || strings.ContainsRune(value, '\x00') || len(value) > 4096 {
		return "", errors.New("remote path is invalid")
	}
	return value, nil
}

func nonEmptyRemoteOperand(value string) (string, error) {
	if !strings.HasPrefix(value, remotePathPrefix) {
		return "", errors.New("remote operand must start with remote:")
	}
	return requiredRemotePath(strings.TrimPrefix(value, remotePathPrefix))
}

func collectSFTPTree(
	ctx context.Context,
	client *sftpclient.Client,
	root string,
	depth, maximum int,
	rows *[]sftpTreeEntry,
) error {
	if depth >= maximum {
		return nil
	}
	entries, err := client.ReadDir(ctx, root)
	if err != nil {
		return err
	}
	sortSFTPEntries(entries)
	for _, entry := range entries {
		if len(*rows) >= maxSFTPTreeItems {
			return fmt.Errorf("remote tree exceeds %d entries", maxSFTPTreeItems)
		}
		*rows = append(*rows, sftpTreeEntry{Entry: entry, Depth: depth})
		if entry.Type == "directory" {
			if err := collectSFTPTree(ctx, client, entry.Path, depth+1, maximum, rows); err != nil {
				return err
			}
		}
	}
	return nil
}

func sortSFTPEntries(entries []sftpclient.Entry) {
	sort.Slice(entries, func(i, j int) bool {
		leftDir := entries[i].Type == "directory"
		rightDir := entries[j].Type == "directory"
		if leftDir != rightDir {
			return leftDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
}

func cliTransferProgress() sftpclient.Progress {
	if !IsTTY(os.Stderr) {
		return nil
	}
	var last time.Time
	return func(transferred, total int64) {
		now := time.Now()
		if transferred != total && now.Sub(last) < 100*time.Millisecond {
			return
		}
		last = now
		if total > 0 {
			fmt.Fprintf(os.Stderr, "\r  %s / %s (%3.0f%%)", formatByteSize(transferred), formatByteSize(total), float64(transferred)*100/float64(total))
		} else {
			fmt.Fprintf(os.Stderr, "\r  %s", formatByteSize(transferred))
		}
		if transferred == total {
			fmt.Fprintln(os.Stderr)
		}
	}
}

func formatByteSize(value int64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	divisor, exponent := int64(unit), 0
	for quotient := value / unit; quotient >= unit && exponent < 4; quotient /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(divisor), "KMGTPE"[exponent])
}
