package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/crypto"
)

// Key files hold the passphrase of an unattended (machine) identity
// (docs/MACHINE_IDENTITIES_PLAN.md). They are provisioned outside fd0.
const (
	keyFileMaxBytes = 4096
	keyFileMinChars = 32
)

// ReadKeyFile reads an unattended identity's passphrase from path, or from
// stdin when path is "-". A file must be a regular file owned by the current
// user or root (for systemd credentials) and must not be readable by group or
// others; symlinks and FIFOs are refused. One trailing newline is removed.
// The content must be at least 32 bytes. The caller wipes the result.
func ReadKeyFile(path string) ([]byte, error) {
	var src io.Reader = os.Stdin
	if path != "-" {
		f, err := openPrivateRegularFile(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		src = f
	}
	buf := make([]byte, keyFileMaxBytes+1)
	n, err := io.ReadFull(src, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		crypto.Wipe(buf)
		return nil, fmt.Errorf("key file: read: %w", err)
	}
	if n > keyFileMaxBytes {
		crypto.Wipe(buf)
		return nil, fmt.Errorf("key file: larger than %d bytes", keyFileMaxBytes)
	}
	data := buf[:n]
	if n > 0 && data[n-1] == '\n' {
		data = data[:n-1]
		if m := len(data); m > 0 && data[m-1] == '\r' {
			data = data[:m-1]
		}
	}
	if len(data) < keyFileMinChars {
		crypto.Wipe(buf)
		return nil, fmt.Errorf("key file: content must be at least %d bytes of random data", keyFileMinChars)
	}
	key := append([]byte(nil), data...)
	crypto.Wipe(buf)
	return key, nil
}

// openPrivateRegularFile opens without following a final symlink and without
// blocking on a FIFO, then validates the opened descriptor.
func openPrivateRegularFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("key file %s: refusing to follow a symlink", path)
		}
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("key file %s: not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("key file %s: mode %04o is readable by group or others; use 0600 or 0400", path, info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() && st.Uid != 0 {
			f.Close()
			return nil, fmt.Errorf("key file %s: owned by uid %d, not by the current user or root", path, st.Uid)
		}
	}
	if info.Size() > keyFileMaxBytes {
		f.Close()
		return nil, fmt.Errorf("key file %s: larger than %d bytes", path, keyFileMaxBytes)
	}
	return f, nil
}
