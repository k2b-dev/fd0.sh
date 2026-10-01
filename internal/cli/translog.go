package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/canon"
	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/httpguard"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/translog"
)

// Translog client-side verification + first-contact pinning lives in
// this file (TRANSLOG.md §6). The split from sync.go is deliberate:
// the sync flow remains the network state machine, while everything
// related to "trust this server's pubkey" and "verify this STH/proof"
// is grouped here so a future audit can read the verification logic
// in one place without spelunking sync.

// Sentinel errors for client-side translog enforcement.
var (
	// ErrPinnedKeyMismatch fires when /v1/server-info returns a
	// pubkey for a server URL that doesn't match the previously-
	// pinned bytes. Per TRANSLOG.md §6.4, the client MUST refuse
	// any further interaction with this URL until the user
	// re-pins (typically via a `fd0 server pin --reset` ceremony,
	// not implemented in v1.0).
	ErrPinnedKeyMismatch = errors.New("translog: pinned server pubkey mismatch — refusing all interaction (TRANSLOG.md §6.4)")

	// ErrServerInfoUnsigned fires when /v1/server-info is missing
	// or its self-signature does not verify. Strongly indicates the
	// server is not running an fd0-server build with translog
	// support, or the response was tampered in transit (TLS broken).
	ErrServerInfoUnsigned = errors.New("translog: /v1/server-info self-signature failed")

	// ErrSTHMissing fires when a server response that should carry
	// an STH (per TRANSLOG.md §5.4 "MANDATORY") omits it. Treated as
	// a hard fail — accepting events without STH would defeat the
	// equivocation-detection guarantee.
	ErrSTHMissing = errors.New("translog: server response missing mandatory STH")

	// ErrInclusionMismatch / ErrConsistencyMismatch promote the
	// pure-layer ErrInclusionProofInvalid / ErrConsistencyProofInvalid
	// to client-facing errors that doctor / sync surface as red
	// banners.
	ErrInclusionMismatch   = errors.New("translog: inclusion proof failed")
	ErrConsistencyMismatch = errors.New("translog: consistency proof failed — possible server equivocation or rewrite")

	// ErrServerIdentityChanged is returned by the structured desktop pinning
	// flow when the server key observed during confirmation no longer matches
	// the key returned when the pin is committed. The caller must start the
	// confirmation ceremony again; silently accepting the new key would create
	// a preview/commit race at the trust boundary.
	ErrServerIdentityChanged = errors.New("translog: server identity changed during pin confirmation")
)

// ServerPinPreview is the verified, non-secret result of inspecting a server
// before a first-contact pin is committed. ServerPub is copied and owned by the
// result. Callers must pass it back to PinServer exactly as received.
type ServerPinPreview struct {
	URL         string
	ServerPub   ed25519.PublicKey
	Fingerprint string
	Label       string
}

// FD0AutoPinEnv, when set to "1", auto-confirms first-contact pinning
// without an interactive prompt. Used by integration tests and by
// non-interactive operator workflows. Production interactive use
// SHOULD always go through the prompt — auto-pin disables the safety-
// number ceremony entirely.
const FD0AutoPinEnv = "FD0_AUTO_PIN"

// NormalizeServerURL canonicalises a server URL string. Wave C-2:
// kept as a thin shim around canon.ParseURL so existing callers
// (witness, server fingerprint helpers, downstream serializers that
// store the URL as a plain string) work unchanged. New code should
// take canon.URL by type and avoid this function.
func NormalizeServerURL(s string) (string, error) {
	u, err := canon.ParseURL(s)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ErrServerPinMismatch means the server's safety number differs from --pin.
var ErrServerPinMismatch = errors.New("server safety number does not match --pin; refusing to sync")

type serverPinKey struct{}

// WithServerPin returns a context that requires the server's safety number to
// equal fp (`fd0 sync --pin`): it pins on first contact without a prompt and
// must also match an existing pin. Only digits and whitespace are accepted.
func WithServerPin(ctx context.Context, fp string) (context.Context, error) {
	var b strings.Builder
	for _, r := range fp {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
		default:
			return nil, errors.New("--pin accepts only the digits and spaces of the server's safety number")
		}
	}
	if b.Len() != 60 {
		return nil, errors.New("--pin must be the server's 12-group safety number (60 digits)")
	}
	return context.WithValue(ctx, serverPinKey{}, b.String()), nil
}

func serverPinFrom(ctx context.Context) string {
	fp, _ := ctx.Value(serverPinKey{}).(string)
	return fp
}

func fingerprintDigits(fp string) string {
	var b strings.Builder
	for _, r := range fp {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func checkExpectedFingerprint(expected, canonical string, pub []byte) error {
	fp, err := ServerFingerprint(canonical, pub)
	if err != nil {
		return err
	}
	if fingerprintDigits(fp) != expected {
		return ErrServerPinMismatch
	}
	return nil
}

// ServerFingerprint is the user-facing display string for a server
// pubkey, formatted exactly like SafetyNumber for identity cards so
// the operator's eyes don't have to learn a second visual idiom.
//
//	digest = SHA-256("fd0-server-fingerprint-v1" || cbor({url, pub}))
//	first 24 bytes → 12 groups of 5 decimal digits → 3 lines × 4 groups
//
// Binding the digest to the URL prevents a swapped-server-with-same-pub
// attack from being indistinguishable from a legitimate re-pin.
func ServerFingerprint(serverURL string, pub []byte) (string, error) {
	body, err := proto.Marshal(struct {
		URL string `cbor:"url"`
		Pub []byte `cbor:"pub"`
	}{serverURL, pub})
	if err != nil {
		return "", err
	}
	in := append([]byte(proto.DomainServerFingerprint), body...)
	sum := sha256.Sum256(in)
	groups := make([]string, 12)
	for i := 0; i < 12; i++ {
		v := uint16(sum[i*2])<<8 | uint16(sum[i*2+1])
		groups[i] = fmt.Sprintf("%05d", v)
	}
	var lines []string
	for i := 0; i < 12; i += 4 {
		lines = append(lines, strings.Join(groups[i:i+4], " "))
	}
	return strings.Join(lines, "\n"), nil
}

// InspectServer fetches and verifies a server's self-signed identity without
// mutating the vault. It is the structured equivalent of the informational
// half of the CLI pinning prompt and is safe for native GUI confirmation.
func InspectServer(ctx context.Context, server string) (*ServerPinPreview, error) {
	serverURL, err := canon.ParseURL(server)
	if err != nil {
		return nil, fmt.Errorf("server URL: %w", err)
	}
	info, err := fetchVerifiedServerInfo(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	fingerprint, err := ServerFingerprint(serverURL.String(), info.ServerPub)
	if err != nil {
		return nil, err
	}
	return &ServerPinPreview{
		URL:         serverURL.String(),
		ServerPub:   append(ed25519.PublicKey(nil), info.ServerPub...),
		Fingerprint: fingerprint,
		Label:       info.Label,
	}, nil
}

// EnsurePinnedServer reads the current pin for serverURL from the
// vault. If absent, fetches /v1/server-info, verifies the
// self-signature, runs the safety-number ceremony (or auto-confirms
// when FD0_AUTO_PIN=1), and persists the pin. If present, refetches
// /v1/server-info and refuses on mismatch.
//
// Returns the pinned pubkey on success. Persists the vault on first
// pin AND on no-op refetch (to update PinnedAt timestamp would be
// wasteful — we don't bother, persistence only happens on first pin).
//
// The session is mutated in place (s.Body.PinnedServers gets a new
// entry on first pin); caller is responsible for s.ReSeal afterwards.
//
// Wave C-2: takes canon.URL — caller is responsible for parsing the
// operator-supplied string via canon.ParseURL. Eliminates the
// "trailing-slash drift between sync and witness" class because both
// layers consume the same byte-stable canonical form.
//
// THREAT: T46 (server-info pubkey forgery — mitigated by server self-
//
//	signature verify + first-contact pinning).
func (s *Session) EnsurePinnedServer(ctx context.Context, serverURL canon.URL) (ed25519.PublicKey, error) {
	canonical := serverURL.String()
	info, err := fetchVerifiedServerInfo(ctx, serverURL)
	if err != nil {
		return nil, err
	}
	expected := serverPinFrom(ctx)
	if expected != "" {
		if err := checkExpectedFingerprint(expected, canonical, info.ServerPub); err != nil {
			return nil, err
		}
	}
	if s.Body.PinnedServers == nil {
		s.Body.PinnedServers = map[string]proto.PinnedServer{}
	}
	if existing, ok := s.Body.PinnedServers[canonical]; ok {
		// Re-pin gate: the cached pub MUST match what the server
		// just published. Any divergence is either rotation
		// (legitimate, but requires manual ceremony — out of v1.0
		// scope) or attack (illegitimate). Either way: refuse.
		if !bytes.Equal(existing.ServerPub, info.ServerPub) {
			return nil, ErrPinnedKeyMismatch
		}
		return ed25519.PublicKey(existing.ServerPub), nil
	}
	// First contact: TOFU.
	if err := pinningPrompt(canonical, info.ServerPub, expected != ""); err != nil {
		return nil, err
	}
	s.Body.PinnedServers[canonical] = proto.PinnedServer{
		ServerPub: append([]byte(nil), info.ServerPub...),
		PinnedAt:  uint64(nowUnix()),
	}
	if err := s.ReSeal(); err != nil {
		return nil, fmt.Errorf("persist pinned server: %w", err)
	}
	return ed25519.PublicKey(info.ServerPub), nil
}

// PinServer commits a server key that was previously returned by
// InspectServer. It refetches and re-verifies /v1/server-info before writing,
// which binds the confirmation to the exact canonical URL and public key.
func PinServer(ctx context.Context, server string, expectedPub []byte) error {
	if len(expectedPub) != ed25519.PublicKeySize {
		return errors.New("translog: expected server pubkey must be 32 bytes")
	}
	serverURL, err := canon.ParseURL(server)
	if err != nil {
		return fmt.Errorf("server URL: %w", err)
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.pinServer(ctx, serverURL, expectedPub)
}

func (s *Session) pinServer(ctx context.Context, serverURL canon.URL, expectedPub []byte) error {
	info, err := fetchVerifiedServerInfo(ctx, serverURL)
	if err != nil {
		return err
	}
	if !bytes.Equal(info.ServerPub, expectedPub) {
		return ErrServerIdentityChanged
	}
	canonical := serverURL.String()
	if s.Body.PinnedServers == nil {
		s.Body.PinnedServers = map[string]proto.PinnedServer{}
	}
	if existing, ok := s.Body.PinnedServers[canonical]; ok {
		if !bytes.Equal(existing.ServerPub, info.ServerPub) {
			return ErrPinnedKeyMismatch
		}
		return nil
	}
	s.Body.PinnedServers[canonical] = proto.PinnedServer{
		ServerPub: append([]byte(nil), info.ServerPub...),
		PinnedAt:  uint64(nowUnix()),
	}
	if err := s.ReSeal(); err != nil {
		delete(s.Body.PinnedServers, canonical)
		return fmt.Errorf("persist pinned server: %w", err)
	}
	return nil
}

// pinningPrompt displays the safety number for (url, pub) and gates
// the pin on user confirmation.
//
// Policy:
//   - Interactive (stdin is TTY): prompt y/N. User confirms after
//     verifying the fingerprint out of band.
//   - Non-interactive (no TTY) AND FD0_AUTO_PIN=1: auto-confirm. The
//     opt-in env var is required so an operator must consciously
//     enable scripted pinning. Otherwise a MITM during the very first
//     agent-spawned sync could pin its own pubkey and the user would
//     never see the prompt.
//   - Non-interactive WITHOUT FD0_AUTO_PIN=1: refuse with an error
//     pointing at the env var. Codex C4 review #3.
//
// The fingerprint is ALWAYS printed; the only thing the auto-confirm
// path skips is blocking on stdin.
//
// THREAT: T47 (auto-pin bypass without operator awareness).
func pinningPrompt(canonical string, pub []byte, matchedPin bool) error {
	fp, err := ServerFingerprint(canonical, pub)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nFirst contact with server %s\n", canonical)
	fmt.Fprintf(os.Stderr, "Server fingerprint (verify out-of-band):\n%s\n\n", indent(fp, "  "))
	autoPin := os.Getenv(FD0AutoPinEnv) == "1"
	tty := IsTTY(os.Stdin)
	switch {
	case matchedPin:
		// EnsurePinnedServer already checked --pin against this key.
		fmt.Fprintln(os.Stderr, "✓ pinned (matches --pin)")
		return nil
	case os.Getenv("FD0_BACKGROUND_SYNC") == "1":
		return errors.New("first contact with a server needs an explicit `fd0 sync` (or `fd0 sync --pin`); background sync never pins")
	case autoPin:
		fmt.Fprintln(os.Stderr, "✓ auto-pinned (FD0_AUTO_PIN=1; verify the fingerprint above out of band)")
		return nil
	case !tty:
		return fmt.Errorf("first-contact pinning required but stdin is not a TTY; set %s=1 to opt into unattended pinning (and verify the printed fingerprint out of band)", FD0AutoPinEnv)
	}
	fmt.Fprint(os.Stderr, "Pin this server? [y/N] ")
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read confirmation: %w", err)
	}
	line = strings.TrimSpace(strings.ToLower(line))
	if line != "y" && line != "yes" {
		return errors.New("server pinning refused by user")
	}
	return nil
}

// EnsureUserRegistered ensures the local user_super_pub is known to
// `serverURL` (codex audit 🔴 auth.go:87 + cli/sync.go:131). After
// the genesis user.cbor event, this POSTs it to /users — the server
// records (super_pub, short_id) and accepts subsequent /sync calls
// from this key.
//
// Idempotent: if the server already has us (HTTP 409 super_pub_taken)
// we treat that as success. Persists `Registered=true` on the
// PinnedServer entry so subsequent syncs skip the round-trip.
//
// NOTE: this is the bare-minimum fix for v1. Full user-chain sync
// (propagating subsequent auth.set events from `auth add`/`auth rm`
// to the server) is a v1.x follow-up tracked in TODO.md.
func (s *Session) EnsureUserRegistered(ctx context.Context, serverURL canon.URL) error {
	canonical := serverURL.String()
	pinned, ok := s.Body.PinnedServers[canonical]
	if ok && pinned.Registered {
		return nil
	}
	// Read the genesis user event from the local user chain.
	events, err := chain.ReadUserEvents(s.Paths.UserChain)
	if err != nil {
		return fmt.Errorf("registration: read user chain: %w", err)
	}
	if len(events) == 0 {
		return errors.New("registration: user chain empty (run `fd0 init` first)")
	}
	body, err := proto.Marshal(map[string]any{"event": events[0]})
	if err != nil {
		return fmt.Errorf("registration: marshal: %w", err)
	}
	// Bounded 429 retry. The register endpoint is rate-limited per-IP, so
	// a first sync behind a busy NAT can hit 429 before reaching the
	// signed sync path's own backoff. Honour Retry-After here too; the
	// body is fixed (no nonce) so each attempt re-sends it verbatim.
	const maxRegAttempts = 4
	const maxRegWait = 30 * time.Second
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, canonical+"/v1/users", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/cbor")
		resp, err = syncHTTPClient.Do(req)
		if err != nil {
			return fmt.Errorf("registration: POST /users: %w", err)
		}
		if resp.StatusCode != http.StatusTooManyRequests || attempt >= maxRegAttempts-1 {
			break
		}
		wait := retryAfterDelay(resp.Header.Get("Retry-After"), maxRegWait)
		resp.Body.Close()
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated:
		// Fresh registration — server accepted the genesis.
	case http.StatusConflict:
		// Could be `super_pub_taken` (already registered, fine) or
		// `dup` (event_id collision — also already registered). Either
		// way we're idempotently registered.
		respBody, err := httpguard.ReadBody(resp.Body, 4096)
		if err != nil {
			return fmt.Errorf("registration: POST /users: %w", err)
		}
		if !strings.Contains(string(respBody), "super_pub_taken") &&
			!strings.Contains(string(respBody), "dup") {
			return fmt.Errorf("registration: 409 with unexpected reason: %s", respBody)
		}
	default:
		respBody, err := httpguard.ReadBody(resp.Body, 4096)
		if err != nil {
			return fmt.Errorf("registration: POST /users: %w", err)
		}
		return fmt.Errorf("registration: POST /users: %s: %s", resp.Status, respBody)
	}
	// Persist Registered=true so future syncs skip the round-trip.
	if s.Body.PinnedServers == nil {
		s.Body.PinnedServers = map[string]proto.PinnedServer{}
	}
	pinned = s.Body.PinnedServers[canonical]
	pinned.Registered = true
	s.Body.PinnedServers[canonical] = pinned
	return s.ReSeal()
}

// fetchServerInfo issues an unauthenticated GET /v1/server-info to
// canonicalURL and decodes the response. Used by EnsurePinnedServer
// (boot-time first contact) and by future repin commands.
func fetchServerInfo(ctx context.Context, canonicalURL string) (translog.ServerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", canonicalURL+"/v1/server-info", nil)
	if err != nil {
		return translog.ServerInfo{}, err
	}
	resp, err := syncHTTPClient.Do(req)
	if err != nil {
		return translog.ServerInfo{}, fmt.Errorf("fetch /v1/server-info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return translog.ServerInfo{}, fmt.Errorf("/v1/server-info: %s", resp.Status)
	}
	body, err := httpguard.ReadBody(resp.Body, 1<<20)
	if err != nil {
		return translog.ServerInfo{}, err
	}
	var info translog.ServerInfo
	if err := proto.Unmarshal(body, &info); err != nil {
		return translog.ServerInfo{}, fmt.Errorf("decode /v1/server-info: %w", err)
	}
	return info, nil
}

func fetchVerifiedServerInfo(ctx context.Context, serverURL canon.URL) (translog.ServerInfo, error) {
	info, err := fetchServerInfo(ctx, serverURL.String())
	if err != nil {
		return translog.ServerInfo{}, err
	}
	if err := translog.VerifyServerInfo(info); err != nil {
		return translog.ServerInfo{}, ErrServerInfoUnsigned
	}
	return info, nil
}

// ErrSTHTreeSizeRegression fires when the server publishes a smaller
// tree_size than the client's persisted LastSTH. Per TRANSLOG.md §6.4
// this is a hard refuse — server invariant break (tree only grows).
var ErrSTHTreeSizeRegression = errors.New("translog: STH tree_size went backwards — refusing")

// VerifyTranslogResponse checks the STH signature + chain_id binding,
// every inclusion proof (with leaf_index and tree_size matching), and
// the optional consistency proof for one chain's response payload.
//
// Parameters:
//   - pinnedPub: the previously-pinned server pubkey (binds STH origin).
//   - expectedChainID: the chain we asked about ("user:..." or
//     "scope:..."). The server's STH MUST embed this exact id, else
//     it could swap chains across requests undetectably.
//   - sth: the response's STH (mandatory when chain has events).
//   - priorSTH: client's persisted LastSTH (nil = fresh subscription).
//   - inclusionProofs / expectedLeafIndices / eventLeafHashes: each
//     slice must be the same length; index i lines up across all
//     three. expectedLeafIndices MUST match what the server returned
//     in proof.LeafIndex — otherwise a malicious server could prove
//     leaf 5 is in the tree while the client thinks it proved leaf 7.
//   - consistency: present iff caller supplied last_sth_size > 0.
//
// Empty-events shortcut: if `sth == nil` AND no events, this is a
// no-op (per TRANSLOG.md §6.2 "MAY include" for empty pulls). Caller
// should NOT update LastSTH in that case.
//
// All verification errors are surfaced as ErrInclusionMismatch /
// ErrConsistencyMismatch / ErrSTHMissing / ErrSTHTreeSizeRegression
// so the caller can react uniformly.
//
// THREAT: T36 (server returns wrong consistency proof),
//
//	T42 (STH for a different chain_id).
func VerifyTranslogResponse(
	pinnedPub ed25519.PublicKey,
	expectedChainID string,
	sth *translog.STH,
	priorSTH *translog.STH,
	inclusionProofs []translog.InclusionProof,
	expectedLeafIndices []uint64,
	eventLeafHashes [][]byte,
	consistency *translog.ConsistencyProof,
) error {
	if sth == nil {
		if len(eventLeafHashes) == 0 && priorSTH == nil {
			// No data, no anchor — nothing to verify.
			return nil
		}
		return ErrSTHMissing
	}
	if sth.Head.ChainID != expectedChainID {
		return fmt.Errorf("translog: STH chain_id %q != expected %q",
			sth.Head.ChainID, expectedChainID)
	}
	if priorSTH != nil && sth.Head.TreeSize < priorSTH.Head.TreeSize {
		return fmt.Errorf("%w: %d < %d", ErrSTHTreeSizeRegression,
			sth.Head.TreeSize, priorSTH.Head.TreeSize)
	}
	if err := translog.VerifySTH(pinnedPub, *sth); err != nil {
		return fmt.Errorf("STH signature: %w", err)
	}
	if len(inclusionProofs) != len(eventLeafHashes) || len(inclusionProofs) != len(expectedLeafIndices) {
		return fmt.Errorf("translog: inclusion-proof / leaf-index / leaf-hash slice lengths %d/%d/%d disagree",
			len(inclusionProofs), len(expectedLeafIndices), len(eventLeafHashes))
	}
	for i, p := range inclusionProofs {
		if p.TreeSize != sth.Head.TreeSize {
			return fmt.Errorf("translog: inclusion proof[%d] tree_size=%d, want %d",
				i, p.TreeSize, sth.Head.TreeSize)
		}
		if p.LeafIndex != expectedLeafIndices[i] {
			return fmt.Errorf("translog: inclusion proof[%d] leaf_index=%d, want %d",
				i, p.LeafIndex, expectedLeafIndices[i])
		}
		if err := translog.VerifyInclusion(eventLeafHashes[i], p.LeafIndex, p.TreeSize, p.AuditPath, sth.Head.RootHash); err != nil {
			return fmt.Errorf("%w: leaf %d: %v", ErrInclusionMismatch, p.LeafIndex, err)
		}
	}
	if priorSTH != nil && priorSTH.Head.TreeSize > 0 {
		if consistency == nil {
			return fmt.Errorf("%w: server omitted consistency proof from %d to %d",
				ErrConsistencyMismatch, priorSTH.Head.TreeSize, sth.Head.TreeSize)
		}
		if consistency.FromSize != priorSTH.Head.TreeSize {
			return fmt.Errorf("%w: from_size=%d, want %d", ErrConsistencyMismatch,
				consistency.FromSize, priorSTH.Head.TreeSize)
		}
		if consistency.ToSize != sth.Head.TreeSize {
			return fmt.Errorf("%w: to_size=%d, want %d", ErrConsistencyMismatch,
				consistency.ToSize, sth.Head.TreeSize)
		}
		if err := translog.VerifyConsistency(consistency.FromSize, consistency.ToSize, consistency.Nodes, priorSTH.Head.RootHash, sth.Head.RootHash); err != nil {
			return fmt.Errorf("%w: %v", ErrConsistencyMismatch, err)
		}
	}
	return nil
}

// PinnedServerPub returns the previously-pinned pubkey for serverURL,
// or an error if no pin exists. Used by reconcile-side push helpers
// that operate after the outer RunSync has already done first-contact
// pinning — they should not redo the ceremony, only trust what's in
// the vault.
func (s *Session) PinnedServerPub(serverURL canon.URL) (ed25519.PublicKey, error) {
	canonical := serverURL.String()
	if entry, ok := s.Body.PinnedServers[canonical]; ok {
		return ed25519.PublicKey(entry.ServerPub), nil
	}
	return nil, fmt.Errorf("translog: no pinned pubkey for %s — outer sync must run first-contact pinning", canonical)
}

// EncodeSTH marshals a VerifiedSTH for storage in the vault's
// LastSTH / LastSTHUser fields. Wave D: signature now requires
// the type-state wrapper so an unverified STH cannot be
// persisted. The only path to a VerifiedSTH is via
// VerifyAndCrossCheck (or decodeVerifiedSTH for vault-loaded
// values, which are themselves trusted by induction).
//
// Codex Wave-D review fix: also runtime-check the seal sentinel
// so a forged `cli.VerifiedSTH{}` composite literal from a
// foreign package fails closed. The seal is set only by the two
// package-internal constructors (newVerifiedSTH from the verifier,
// decodeVerifiedSTH from the sealed vault).
func EncodeSTH(v VerifiedSTH) ([]byte, error) {
	if !v.seal.ok {
		return nil, errUnsealedVerifiedSTH
	}
	return proto.Marshal(v.sth)
}

// VerifyAndCrossCheck wraps VerifyTranslogResponse with a witness
// cross-check call when wcc is non-nil. Centralised here so every
// sync code path that trusts a server STH gets the same protection
// without duplicating the witness wiring.
//
// wcc may be nil — callers pass nil when the client config has no
// [[witness]] entries OR min_cosigns=0. Both checks happen before
// any state is committed, so a witness rejection reaches the
// caller before vault writes.
//
// Wave D: returns *VerifiedSTH on success — callers feed this into
// EncodeSTH for vault persistence. The type-state ensures encode
// can never run against an unverified value. Returns (nil, nil)
// when sth is nil and the verify path treats that as a legitimate
// "no STH this round" outcome.
//
// THREAT: T35 (server equivocation between clients — witness cosign),
//
//	T36 (wrong consistency proof — verify before commit),
//	T25 (verify result discarded — type-state enforced).
func VerifyAndCrossCheck(
	ctx context.Context,
	wcc *WitnessCheckClient,
	serverURL canon.URL,
	pinnedPub ed25519.PublicKey,
	expectedChainID string,
	sth *translog.STH,
	priorSTH *VerifiedSTH,
	inclusionProofs []translog.InclusionProof,
	expectedLeafIndices []uint64,
	eventLeafHashes [][]byte,
	consistency *translog.ConsistencyProof,
) (*VerifiedSTH, error) {
	// VerifyTranslogResponse takes the underlying STH; unwrap the
	// trusted prior anchor (or pass nil for fresh verifies).
	var priorRaw *translog.STH
	if priorSTH != nil {
		s := priorSTH.STH()
		priorRaw = &s
	}
	if err := VerifyTranslogResponse(pinnedPub, expectedChainID, sth, priorRaw, inclusionProofs, expectedLeafIndices, eventLeafHashes, consistency); err != nil {
		return nil, err
	}
	if sth == nil {
		// Verify accepted "no STH this round" (e.g. denied or
		// empty pull); no value to wrap.
		return nil, nil
	}
	if wcc != nil {
		// Codex fix #5: normalise the server URL once before the
		// cross-check. Pinning canonicalises (lowercase host, no
		// trailing slash); the witness archive uses whatever it
		// was configured with, which is also expected to be the
		// canonical form. Wave C-2: serverURL is already a
		// canon.URL (parsed at RunSync entry), so no second
		// normalisation pass is needed — the type carries the
		// invariant.
		if err := wcc.CrossCheckSTH(ctx, serverURL, pinnedPub, *sth); err != nil {
			return nil, err
		}
	}
	return newVerifiedSTH(*sth), nil
}

// DecodeSTH parses a CBOR-encoded STH from the vault. Returns nil on
// empty input (no anchor yet — fresh chain or legacy vault) so the
// caller can treat "no proof" and "missing field" identically.
func DecodeSTH(b []byte) (*translog.STH, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var sth translog.STH
	if err := proto.Unmarshal(b, &sth); err != nil {
		return nil, fmt.Errorf("decode LastSTH: %w", err)
	}
	return &sth, nil
}

// nowUnix is wrapped so tests can stub. v1 just calls time.Now().Unix().
var nowUnix = func() int64 { return time.Now().Unix() }
