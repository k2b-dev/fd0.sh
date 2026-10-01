package sftpclient

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type TransferOptions struct {
	Recursive bool
	Force     bool
}

type TransferResult struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

func (c *Client) DownloadPath(
	ctx context.Context,
	remoteSource, localDestination string,
	options TransferOptions,
	progress Progress,
) (TransferResult, error) {
	source, err := c.Stat(remoteSource, false)
	if err != nil {
		return TransferResult{}, err
	}
	if source.Type == "symlink" {
		return TransferResult{}, errors.New("sftp: refusing to download a symlink; choose its target explicitly")
	}
	if source.Type == "directory" && !options.Recursive {
		return TransferResult{}, errors.New("sftp: remote source is a directory; enable recursive transfer")
	}
	localDestination, err = resolveLocalDestination(localDestination, source.Name)
	if err != nil {
		return TransferResult{}, err
	}
	if _, err := os.Lstat(localDestination); err == nil && !options.Force {
		return TransferResult{}, fmt.Errorf("local destination %q already exists", localDestination)
	} else if err != nil && !os.IsNotExist(err) {
		return TransferResult{}, err
	}
	parent := filepath.Dir(localDestination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return TransferResult{}, err
	}
	if source.Type == "directory" {
		temp, err := os.MkdirTemp(parent, ".fd0-sftp-")
		if err != nil {
			return TransferResult{}, err
		}
		defer func() { _ = os.RemoveAll(temp) }()
		total, err := c.downloadDirectory(ctx, remoteSource, temp, progress)
		if err != nil {
			return TransferResult{}, err
		}
		if _, err := os.Lstat(localDestination); err == nil {
			return TransferResult{}, fmt.Errorf("cannot atomically replace existing directory %q", localDestination)
		}
		if err := os.Rename(temp, localDestination); err != nil {
			return TransferResult{}, err
		}
		return TransferResult{Path: localDestination, Bytes: total}, nil
	}

	file, err := os.CreateTemp(parent, ".fd0-sftp-")
	if err != nil {
		return TransferResult{}, err
	}
	temp := file.Name()
	defer os.Remove(temp)
	written, copyErr := c.Download(ctx, remoteSource, file, progress)
	syncErr := file.Sync()
	chmodErr := file.Chmod(privateMode(source.Mode))
	closeErr := file.Close()
	if copyErr != nil {
		return TransferResult{}, copyErr
	}
	if syncErr != nil {
		return TransferResult{}, syncErr
	}
	if chmodErr != nil {
		return TransferResult{}, chmodErr
	}
	if closeErr != nil {
		return TransferResult{}, closeErr
	}
	if err := os.Rename(temp, localDestination); err != nil {
		return TransferResult{}, err
	}
	return TransferResult{Path: localDestination, Bytes: written}, nil
}

func (c *Client) UploadPath(
	ctx context.Context,
	localSource, remoteDestination string,
	options TransferOptions,
	progress Progress,
) (TransferResult, error) {
	source, err := os.Lstat(localSource)
	if err != nil {
		return TransferResult{}, err
	}
	if source.Mode()&os.ModeSymlink != 0 {
		return TransferResult{}, errors.New("sftp: refusing to upload a symlink; choose its target explicitly")
	}
	if source.IsDir() && !options.Recursive {
		return TransferResult{}, errors.New("sftp: local source is a directory; enable recursive transfer")
	}
	if destination, statErr := c.Stat(remoteDestination, true); statErr == nil && destination.Type == "directory" {
		remoteDestination = path.Join(remoteDestination, source.Name())
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return TransferResult{}, statErr
	}
	if _, err := c.Stat(remoteDestination, false); err == nil && !options.Force {
		return TransferResult{}, fmt.Errorf("remote destination %q already exists", remoteDestination)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return TransferResult{}, err
	}
	temp := path.Join(path.Dir(remoteDestination), "."+path.Base(remoteDestination)+".fd0-part-"+transferSuffix())
	defer func() { _ = c.Remove(context.Background(), temp, true) }()
	if source.IsDir() {
		if err := c.mkdirPrivate(temp); err != nil {
			return TransferResult{}, err
		}
		total, err := c.uploadDirectory(ctx, localSource, temp, progress)
		if err != nil {
			return TransferResult{}, err
		}
		if err := c.Chmod(temp, source.Mode()); err != nil {
			return TransferResult{}, err
		}
		if _, err := c.Stat(remoteDestination, false); err == nil {
			return TransferResult{}, fmt.Errorf("cannot atomically replace existing remote directory %q", remoteDestination)
		}
		if err := c.Rename(temp, remoteDestination, false); err != nil {
			return TransferResult{}, err
		}
		return TransferResult{Path: remoteDestination, Bytes: total}, nil
	}

	file, err := os.Open(localSource)
	if err != nil {
		return TransferResult{}, err
	}
	defer func() { _ = file.Close() }()
	written, err := c.Upload(ctx, file, temp, source.Mode(), source.Size(), progress)
	if err != nil {
		return TransferResult{}, err
	}
	if err := c.Rename(temp, remoteDestination, options.Force); err != nil {
		return TransferResult{}, err
	}
	return TransferResult{Path: remoteDestination, Bytes: written}, nil
}

func (c *Client) downloadDirectory(
	ctx context.Context,
	remoteRoot, localRoot string,
	progress Progress,
) (int64, error) {
	entries, err := c.ReadDir(ctx, remoteRoot)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if entry.Type == "symlink" {
			return total, fmt.Errorf("sftp: refusing to recursively download symlink %q", entry.Path)
		}
		localPath := filepath.Join(localRoot, entry.Name)
		switch entry.Type {
		case "directory":
			if err := os.Mkdir(localPath, privateMode(entry.Mode)); err != nil {
				return total, err
			}
			written, err := c.downloadDirectory(ctx, entry.Path, localPath, progress)
			total += written
			if err != nil {
				return total, err
			}
		case "file":
			file, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateMode(entry.Mode))
			if err != nil {
				return total, err
			}
			written, copyErr := c.Download(ctx, entry.Path, file, progress)
			closeErr := file.Close()
			total += written
			if copyErr != nil {
				return total, copyErr
			}
			if closeErr != nil {
				return total, closeErr
			}
		default:
			return total, fmt.Errorf("sftp: unsupported remote file type at %q", entry.Path)
		}
	}
	return total, nil
}

func (c *Client) uploadDirectory(
	ctx context.Context,
	localRoot, remoteRoot string,
	progress Progress,
) (int64, error) {
	entries, err := os.ReadDir(localRoot)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		info, err := entry.Info()
		if err != nil {
			return total, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return total, fmt.Errorf("sftp: refusing to recursively upload symlink %q", filepath.Join(localRoot, entry.Name()))
		}
		localPath := filepath.Join(localRoot, entry.Name())
		remotePath := path.Join(remoteRoot, entry.Name())
		if info.IsDir() {
			if err := c.mkdirPrivate(remotePath); err != nil {
				return total, err
			}
			written, err := c.uploadDirectory(ctx, localPath, remotePath, progress)
			total += written
			if err != nil {
				return total, err
			}
			if err := c.Chmod(remotePath, info.Mode()); err != nil {
				return total, err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return total, fmt.Errorf("sftp: unsupported local file type at %q", localPath)
		}
		file, err := os.Open(localPath)
		if err != nil {
			return total, err
		}
		written, copyErr := c.Upload(ctx, file, remotePath, info.Mode(), info.Size(), progress)
		closeErr := file.Close()
		total += written
		if copyErr != nil {
			return total, copyErr
		}
		if closeErr != nil {
			return total, closeErr
		}
	}
	return total, nil
}

// mkdirPrivate creates a staging directory and restricts it to the owner
// before anything is written into it; the source mode is applied once the
// directory is complete.
func (c *Client) mkdirPrivate(remotePath string) error {
	if err := c.Mkdir(remotePath, false); err != nil {
		return err
	}
	return c.Chmod(remotePath, 0o700)
}

func resolveLocalDestination(value, sourceName string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("sftp: local destination is invalid")
	}
	if info, err := os.Stat(value); err == nil && info.IsDir() {
		return filepath.Join(value, sourceName), nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return value, nil
}

func privateMode(value string) os.FileMode {
	mode := os.FileMode(0o600)
	if strings.Contains(value, "x") || strings.HasPrefix(value, "d") {
		mode = 0o700
	}
	return mode
}

func transferSuffix() string {
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}
