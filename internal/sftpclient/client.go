package sftpclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
)

const (
	maxStderrBytes = 32 * 1024
	closeTimeout   = 2 * time.Second
)

type Command struct {
	Binary string
	Args   []string
	Env    []string
}

type Entry struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	ModifiedAt time.Time `json:"modifiedAt"`
	LinkTarget string    `json:"linkTarget,omitempty"`
}

type Progress func(transferred, total int64)

type Preview struct {
	Data      []byte `json:"data"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
}

type Client struct {
	client    *sftp.Client
	command   *exec.Cmd
	cancel    context.CancelFunc
	stderr    *boundedBuffer
	closeOnce sync.Once
	closeErr  error
}

func Dial(ctx context.Context, command Command) (*Client, error) {
	if command.Binary == "" || strings.ContainsRune(command.Binary, '\x00') {
		return nil, errors.New("sftp: invalid SSH executable")
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, '\x00') {
			return nil, errors.New("sftp: invalid SSH argument")
		}
	}

	processContext, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(processContext, command.Binary, command.Args...)
	if command.Env != nil {
		cmd.Env = append([]string(nil), command.Env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sftp: open SSH stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("sftp: open SSH stdout: %w", err)
	}
	stderr := &boundedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("sftp: start SSH: %w", err)
	}

	client, err := sftp.NewClientPipe(stdout, stdin)
	if err != nil {
		cancel()
		_ = cmd.Wait()
		return nil, connectError(err, stderr.String())
	}
	return &Client{
		client:  client,
		command: cmd,
		cancel:  cancel,
		stderr:  stderr,
	}, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		clientErr := c.client.Close()
		done := make(chan error, 1)
		go func() { done <- c.command.Wait() }()
		select {
		case processErr := <-done:
			if clientErr != nil {
				c.closeErr = clientErr
			} else if processErr != nil {
				c.closeErr = connectError(processErr, c.stderr.String())
			}
		case <-time.After(closeTimeout):
			c.cancel()
			_ = c.command.Process.Kill()
			<-done
			c.closeErr = errors.New("sftp: SSH did not close cleanly")
		}
		c.cancel()
	})
	return c.closeErr
}

func (c *Client) WorkingDirectory() (string, error) {
	value, err := c.client.Getwd()
	if err != nil {
		return "", operationError("resolve the remote home directory", err)
	}
	return value, nil
}

func (c *Client) ReadDir(ctx context.Context, remotePath string) ([]Entry, error) {
	infos, err := c.client.ReadDirContext(ctx, remotePath)
	if err != nil {
		return nil, operationError("list "+remotePath, err)
	}
	entries := make([]Entry, 0, len(infos))
	for _, info := range infos {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry := entryFromInfo(path.Join(remotePath, info.Name()), info)
		if info.Mode()&os.ModeSymlink != 0 {
			if target, readErr := c.client.ReadLink(entry.Path); readErr == nil {
				entry.LinkTarget = target
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (c *Client) Stat(remotePath string, followSymlink bool) (Entry, error) {
	var (
		info os.FileInfo
		err  error
	)
	if followSymlink {
		info, err = c.client.Stat(remotePath)
	} else {
		info, err = c.client.Lstat(remotePath)
	}
	if err != nil {
		return Entry{}, operationError("stat "+remotePath, err)
	}
	entry := entryFromInfo(remotePath, info)
	if info.Mode()&os.ModeSymlink != 0 {
		if target, readErr := c.client.ReadLink(remotePath); readErr == nil {
			entry.LinkTarget = target
		}
	}
	return entry, nil
}

func (c *Client) ReadPreview(remotePath string, limit int64) (Preview, error) {
	file, err := c.client.Open(remotePath)
	if err != nil {
		return Preview{}, operationError("open "+remotePath, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return Preview{}, operationError("stat "+remotePath, err)
	}
	if !info.Mode().IsRegular() {
		return Preview{}, fmt.Errorf("sftp: %s is not a regular file", remotePath)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return Preview{}, operationError("preview "+remotePath, err)
	}
	truncated := int64(len(data)) > limit
	if truncated {
		data = data[:limit]
	}
	return Preview{Data: data, Size: info.Size(), Truncated: truncated}, nil
}

func (c *Client) Download(
	ctx context.Context,
	remotePath string,
	destination io.Writer,
	progress Progress,
) (int64, error) {
	file, err := c.client.Open(remotePath)
	if err != nil {
		return 0, operationError("open "+remotePath, err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return 0, operationError("stat "+remotePath, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("sftp: %s is not a regular file", remotePath)
	}
	written, err := copyWithProgress(ctx, destination, file, info.Size(), progress)
	if err != nil {
		return written, operationError("download "+remotePath, err)
	}
	return written, nil
}

func (c *Client) Upload(
	ctx context.Context,
	source io.Reader,
	remotePath string,
	mode os.FileMode,
	total int64,
	progress Progress,
) (int64, error) {
	file, err := c.client.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return 0, operationError("create "+remotePath, err)
	}
	// The server creates the file with its default mode. Restrict it while
	// it is still empty so other remote users never read partial content.
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return 0, operationError("restrict permissions on "+remotePath, err)
	}
	written, copyErr := copyWithProgress(ctx, file, source, total, progress)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil {
		return written, operationError("upload "+remotePath, copyErr)
	}
	if syncErr != nil && !sftpStatusIs(syncErr, sftp.ErrSSHFxOpUnsupported) {
		return written, operationError("sync "+remotePath, syncErr)
	}
	if closeErr != nil {
		return written, operationError("close "+remotePath, closeErr)
	}
	if mode.Perm() != 0 {
		if err := c.client.Chmod(remotePath, mode.Perm()); err != nil {
			return written, operationError("set permissions on "+remotePath, err)
		}
	}
	return written, nil
}

func (c *Client) Mkdir(remotePath string, parents bool) error {
	var err error
	if parents {
		err = c.client.MkdirAll(remotePath)
	} else {
		err = c.client.Mkdir(remotePath)
	}
	if err != nil {
		return operationError("create directory "+remotePath, err)
	}
	return nil
}

// Chmod sets the permission bits of a remote path.
func (c *Client) Chmod(remotePath string, mode os.FileMode) error {
	if err := c.client.Chmod(remotePath, mode.Perm()); err != nil {
		return operationError("set permissions on "+remotePath, err)
	}
	return nil
}

func (c *Client) Rename(oldPath, newPath string, replace bool) error {
	if replace {
		if err := c.client.PosixRename(oldPath, newPath); err == nil {
			return nil
		}
	}
	if err := c.client.Rename(oldPath, newPath); err != nil {
		return operationError("rename "+oldPath, err)
	}
	return nil
}

func (c *Client) Remove(ctx context.Context, remotePath string, recursive bool) error {
	info, err := c.client.Lstat(remotePath)
	if err != nil {
		return operationError("stat "+remotePath, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err := c.client.Remove(remotePath); err != nil {
			return operationError("remove "+remotePath, err)
		}
		return nil
	}
	if !recursive {
		if err := c.client.RemoveDirectory(remotePath); err != nil {
			return operationError("remove directory "+remotePath, err)
		}
		return nil
	}
	entries, err := c.client.ReadDirContext(ctx, remotePath)
	if err != nil {
		return operationError("list "+remotePath, err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.Remove(ctx, path.Join(remotePath, entry.Name()), true); err != nil {
			return err
		}
	}
	if err := c.client.RemoveDirectory(remotePath); err != nil {
		return operationError("remove directory "+remotePath, err)
	}
	return nil
}

func entryFromInfo(remotePath string, info os.FileInfo) Entry {
	entryType := "file"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		entryType = "symlink"
	case info.IsDir():
		entryType = "directory"
	case !info.Mode().IsRegular():
		entryType = "other"
	}
	return Entry{
		Name:       info.Name(),
		Path:       remotePath,
		Type:       entryType,
		Size:       info.Size(),
		Mode:       info.Mode().String(),
		ModifiedAt: info.ModTime().UTC(),
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

type progressWriter struct {
	writer      io.Writer
	progress    Progress
	total       int64
	transferred int64
}

func (w *progressWriter) Write(buffer []byte) (int, error) {
	n, err := w.writer.Write(buffer)
	w.transferred += int64(n)
	if w.progress != nil {
		w.progress(w.transferred, w.total)
	}
	return n, err
}

func copyWithProgress(
	ctx context.Context,
	destination io.Writer,
	source io.Reader,
	total int64,
	progress Progress,
) (int64, error) {
	writer := &progressWriter{writer: destination, progress: progress, total: total}
	if progress != nil {
		progress(0, total)
	}
	written, err := io.Copy(writer, contextReader{ctx: ctx, reader: source})
	if err == nil {
		err = ctx.Err()
	}
	return written, err
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	return original, nil
}

func (b *boundedBuffer) String() string {
	return strings.TrimSpace(b.buffer.String())
}

func connectError(cause error, stderr string) error {
	switch {
	case strings.Contains(stderr, "Host key verification failed"):
		return errors.New("sftp: host key verification failed; connect in the terminal once to verify this host")
	case strings.Contains(stderr, "Permission denied"):
		return errors.New("sftp: authentication was denied; unlock fd0 and verify the host key binding")
	case strings.Contains(stderr, "subsystem request failed"):
		return errors.New("sftp: this server does not provide the SFTP subsystem")
	case stderr != "":
		return fmt.Errorf("sftp: SSH connection failed: %s", stderr)
	default:
		return fmt.Errorf("sftp: SSH connection failed: %w", cause)
	}
}

func operationError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("sftp: could not %s: %w", operation, err)
}

func sftpStatusIs(err error, code interface{ Error() string }) bool {
	var status *sftp.StatusError
	return errors.As(err, &status) && status.FxCode().Error() == code.Error()
}
