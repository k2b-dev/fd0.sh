// Package chain reads and writes the client's CBOR-log chain files and
// implements replay (STORAGE.md §3, §4). One file per chain:
//
//	~/.fd0/chains/user.cbor
//	~/.fd0/chains/<scope_id>.cbor
//
// Each file is a concatenation of deterministic-CBOR events with no framing.
// Decoders consume one CBOR top-level item at a time. On partial decode at
// the tail, callers truncate the file to the last good offset (safe under the
// single-writer flock).
package chain

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/proto"
)

// AppendUser appends one UserEvent to path, creating it if missing. The write
// is fsynced before returning.
func AppendUser(path string, ev *proto.UserEvent) error {
	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	return appendBytes(path, b)
}

// AppendScope appends one ScopeEvent to path.
func AppendScope(path string, ev *proto.ScopeEvent) error {
	b, err := proto.Marshal(ev)
	if err != nil {
		return err
	}
	return appendBytes(path, b)
}

// AppendRaw writes already-encoded CBOR bytes (one event). Used by /sync pull
// which receives canonical bytes from the server and MUST persist them
// byte-identically.
func AppendRaw(path string, raw []byte) error { return appendBytes(path, raw) }

// THREAT: T18 (symlink-redirect attack on chain file).
func appendBytes(path string, raw []byte) error {
	// SECURITY (codex security audit 🟠): O_NOFOLLOW prevents a
	// same-UID attacker who plants a symlink at `path` (or who
	// owns the chains directory in some unusual deployment) from
	// redirecting our append into an attacker-chosen file. fd0's
	// security boundary is "trusted home dir, mode 0700", but
	// defense in depth costs nothing here.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

// ReadUserEvents decodes every UserEvent in file. On partial-tail decode it
// truncates the file at the last good offset and returns the events decoded
// before the partial. STORAGE.md §3.1.
func ReadUserEvents(path string) ([]*proto.UserEvent, error) {
	raws, err := readRawEvents(path)
	if err != nil {
		return nil, err
	}
	out := make([]*proto.UserEvent, 0, len(raws))
	for _, r := range raws {
		var ev proto.UserEvent
		if err := proto.Unmarshal(r, &ev); err != nil {
			return nil, fmt.Errorf("chain: decode user event: %w", err)
		}
		out = append(out, &ev)
	}
	return out, nil
}

// ReadScopeEvents decodes every ScopeEvent in file with tail-truncate.
func ReadScopeEvents(path string) ([]*proto.ScopeEvent, error) {
	return readScopeEvents(path, true)
}

// ReadScopeEventsReadOnly rejects partial tails without repairing the file.
// Agent-side grant activation may run without the CLI's writer lock.
func ReadScopeEventsReadOnly(path string) ([]*proto.ScopeEvent, error) {
	return readScopeEvents(path, false)
}

func readScopeEvents(path string, repair bool) ([]*proto.ScopeEvent, error) {
	raws, err := readRawEventsMode(path, repair)
	if err != nil {
		return nil, err
	}
	out := make([]*proto.ScopeEvent, 0, len(raws))
	for _, r := range raws {
		var ev proto.ScopeEvent
		if err := proto.Unmarshal(r, &ev); err != nil {
			return nil, fmt.Errorf("chain: decode scope event: %w", err)
		}
		out = append(out, &ev)
	}
	return out, nil
}

// readRawEvents returns every full top-level CBOR item from path, splitting
// on item boundaries via Decoder.NumBytesRead. A partial tail (decoder error
// after at least one good event) is truncated.
func readRawEvents(path string) ([][]byte, error) {
	return readRawEventsMode(path, true)
}

func readRawEventsMode(path string, repair bool) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	dec := proto.NewStreamDecoderBytes(data)
	var out [][]byte
	prev := 0
	for {
		var raw any
		err := dec.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Truncate ONLY on partial-tail (unexpected EOF inside the last
			// item). Any other error indicates mid-file corruption — bubble
			// up so the caller can investigate without silent data loss.
			//
			// SECURITY (adversarial test): tail-truncate ONLY fires after at
			// least one event decoded successfully. Without this guard, a
			// chain file corrupted from byte 0 (e.g. an attacker overwriting
			// the file with a single garbage byte) would parse as zero events
			// + tail truncated, leading callers to treat the scope as
			// "fresh" and silently re-fetch from the server — losing local-
			// only events that were never pushed. Require prev > 0 OR raise.
			if repair && errors.Is(err, io.ErrUnexpectedEOF) && prev > 0 {
				if prev < len(data) {
					if terr := os.Truncate(path, int64(prev)); terr != nil {
						return nil, fmt.Errorf("chain: truncate partial tail: %w", terr)
					}
				}
				break
			}
			return nil, fmt.Errorf("chain: decode at offset %d: %w", prev, err)
		}
		end := dec.NumBytesRead()
		out = append(out, data[prev:end])
		prev = end
	}
	return out, nil
}

// WriteAll atomically rewrites path with the concatenation of raws. Used by
// verified sync repair and transaction rollback.
func WriteAll(path string, raws [][]byte) error {
	tmp := path + ".tmp"
	// O_NOFOLLOW on the tmp path: defense in depth against
	// same-UID symlink-plant attacks. The .tmp suffix is
	// predictable, so an attacker who knows the chain path can
	// pre-create a symlink there and redirect our write.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	for _, r := range raws {
		if _, err := f.Write(r); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncDir(path)
}

func fsyncDir(p string) error {
	dir, err := os.Open(parentDir(p))
	if err != nil {
		return nil // best-effort on platforms that disallow this
	}
	defer dir.Close()
	_ = dir.Sync()
	return nil
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}
