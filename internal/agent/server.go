package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/chain"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/proto"
	"github.com/valentinkolb/fd0.sh/internal/vault"
)

// Config tunes the agent.
type Config struct {
	IdleTimeout    time.Duration // default 5m
	MaxLifetime    time.Duration // default 8h
	Logger         *slog.Logger
	Version        string
	Flavor         string
	YubikeyEnabled bool
	// StartedBy is reported verbatim in StatusResp so clients can tell an
	// agent they supervise from one somebody else started. Use
	// StartedByFromEnv to fill it.
	StartedBy string
	// Scheduler is optional. When set, the agent runs auto-sync per its
	// configuration and triggers an immediate sync after every unlock.
	Scheduler *Scheduler
	// NewYubikeyResolver, when set, lets the agent unlock vaults whose
	// active method is a YubiKey. The factory receives the PIN (empty
	// for touch-only slots) and returns a vault.MethodResolver that
	// will run the on-card sealed-box open. Build-tag split lives in
	// cmd/fd0-agent: the yubikey-tagged build injects a real factory;
	// the pure-Go build leaves it nil and the agent rejects yubikey
	// unlocks with a clean error.
	NewYubikeyResolver func(pin []byte) vault.MethodResolver
}

// ErrAlreadyServing reports that another fd0-agent already owns this home's
// socket, so this process did not start and did not touch anything. It is a
// classification of the refusal below, never a licence to override it: a
// supervisor that only wants *an* agent for the home (the desktop service, a
// systemd unit) can treat it as "nothing to do" instead of a failure, and so
// stop respawning itself into the same conflict.
var ErrAlreadyServing = errors.New("agent: another agent is already serving this home")

// Server is the running agent. Construct with Listen.
type Server struct {
	cfg       Config
	paths     fdhome.Paths
	listener  net.Listener
	scheduler *Scheduler
	log       *slog.Logger

	mu            sync.Mutex
	superPriv     *crypto.Secret // 64 B Ed25519
	x25519Priv    *crypto.Secret // 32 B
	unlockKey     *crypto.Secret // 32 B K_unlock for the active wrap (used to derive payloadKey + AddWrap source)
	payloadKey    *crypto.Secret // 32 B stable across re-seals; needed by SaveBody/AddWrap/RemoveWrap
	unlockMID     string         // method_id of the active wrap
	unlockMType   string         // method_type of the active wrap
	unlockPP      []byte         // public_params of the active wrap
	userSuperPub  []byte
	redactedBody  []byte // cached cbor(VaultBody) with super_priv zeroed
	unlockedAt    time.Time
	unlockSession string
	lastActivity  time.Time
	lifecycleWake chan struct{}
}

// Listen creates ~/.fd0/agent.sock and accepts connections. The directory
// must already exist with mode 0700; we additionally chmod the socket to 0600.
func Listen(paths fdhome.Paths, cfg Config) (*Server, error) {
	if cfg.IdleTimeout < 0 {
		return nil, errors.New("agent: idle timeout must not be negative")
	}
	if cfg.MaxLifetime < 0 {
		return nil, errors.New("agent: max lifetime must not be negative")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.MaxLifetime == 0 {
		cfg.MaxLifetime = 8 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := paths.VerifyTight(); err != nil {
		return nil, err
	}
	// Refuse to start if another agent is already serving this home: the
	// previous behaviour silently rebound the socket, leaving the original
	// agent running but unreachable (orphan process holding super_priv
	// mlocked, plus duplicate-state confusion). Detect via PID file +
	// liveness check; only proceed if the prior agent is truly gone.
	if alive, oldPID := isPriorAgentAlive(paths.AgentPID); alive {
		return nil, fmt.Errorf("%w (pid %d; delete %s if you're sure it's dead)", ErrAlreadyServing, oldPID, paths.AgentPID)
	}
	// SECURITY (codex audit 🔴 server.go:82): if the PID file is
	// missing/corrupt/stale BUT an old agent is still listening
	// on the socket, the previous code would silently unlink the
	// socket and bind a new listener — orphaning the old agent
	// (still holding super_priv mlocked) AND starting a duplicate.
	// Probe the socket; fail if anything answers.
	if probeAgentSocket(paths.AgentSock) {
		return nil, fmt.Errorf("%w: a process is listening on %s but %s is missing/stale; remove the socket only if you're sure no agent is running",
			ErrAlreadyServing, paths.AgentSock, paths.AgentPID)
	}
	// Stale socket from a crashed agent: safe to unlink (no listener).
	_ = os.Remove(paths.AgentSock)
	l, err := net.Listen("unix", paths.AgentSock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(paths.AgentSock, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	// SECURITY (codex audit 🟡 server.go:92): treat PID file write
	// failure as fatal. Without it, future agent invocations
	// can't detect we're running and may start duplicates (which
	// hits the orphan-agent bug above). Cleanup listener+socket
	// on failure so we don't leave them dangling.
	if err := os.WriteFile(paths.AgentPID, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		l.Close()
		_ = os.Remove(paths.AgentSock)
		return nil, fmt.Errorf("agent: write PID file %s: %w", paths.AgentPID, err)
	}
	s := &Server{
		cfg:           cfg,
		paths:         paths,
		listener:      l,
		scheduler:     cfg.Scheduler,
		log:           cfg.Logger,
		lifecycleWake: make(chan struct{}, 1),
	}
	return s, nil
}

// Serve runs the accept loop. Returns when ctx is done or the listener fails.
func (s *Server) Serve(ctx context.Context) error {
	go s.lifecycleTimer(ctx)
	if s.scheduler != nil {
		go s.scheduler.Run(ctx)
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

// Close stops accepting and zeroizes secrets.
func (s *Server) Close() {
	_ = s.listener.Close()
	_ = os.Remove(s.paths.AgentSock)
	_ = os.Remove(s.paths.AgentPID)
	s.lock()
}

// lifecycleTimer expires the unlocked state at the earliest configured
// deadline. Activity wakes the loop so a pushed-out idle deadline is observed
// without polling, while max-lifetime always remains absolute.
func (s *Server) lifecycleTimer(ctx context.Context) {
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer == nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	resetTimer := func() {
		deadline, ok := s.nextLifecycleDeadline()
		if !ok {
			stopTimer()
			timerC = nil
			return
		}
		delay := time.Until(deadline)
		if delay < 0 {
			delay = 0
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			stopTimer()
			timer.Reset(delay)
		}
		timerC = timer.C
	}
	resetTimer()
	defer stopTimer()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.lifecycleWake:
			resetTimer()
		case now := <-timerC:
			s.enforceLifetime(now)
			resetTimer()
		}
	}
}

func (s *Server) nextLifecycleDeadline() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.unlockedAt.IsZero() || s.lastActivity.IsZero() {
		return time.Time{}, false
	}
	idleDeadline := s.lastActivity.Add(s.cfg.IdleTimeout)
	maxDeadline := s.unlockedAt.Add(s.cfg.MaxLifetime)
	if maxDeadline.Before(idleDeadline) {
		return maxDeadline, true
	}
	return idleDeadline, true
}

func (s *Server) enforceLifetime(now time.Time) bool {
	reason := s.expireUnlocked(now)
	if reason == "" {
		return false
	}
	s.log.Info("agent: " + reason + ", locking")
	s.signalLifecycle()
	return true
}

func (s *Server) expireUnlocked(now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return ""
	}
	if !now.Before(s.unlockedAt.Add(s.cfg.MaxLifetime)) {
		s.lockHeld()
		return "max lifetime"
	}
	if !now.Before(s.lastActivity.Add(s.cfg.IdleTimeout)) {
		s.lockHeld()
		return "idle timeout"
	}
	return ""
}

func (s *Server) signalLifecycle() {
	if s.lifecycleWake == nil {
		return
	}
	select {
	case s.lifecycleWake <- struct{}{}:
	default:
	}
}

func (s *Server) markActivity(now time.Time) {
	s.mu.Lock()
	updated := s.superPriv != nil
	if updated {
		s.lastActivity = now
	}
	s.mu.Unlock()
	if updated {
		s.signalLifecycle()
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(agentRPCTimeout))
	var req Request
	if err := ReadFrame(c, &req); err != nil {
		s.log.Debug("agent: read", "err", err)
		return
	}
	requestCtx := ctx
	cancel := func() {}
	responseTimeout := agentRPCTimeout
	if req.Op == OpUnlock {
		requestCtx, cancel = context.WithTimeout(ctx, agentUnlockTimeout)
		responseTimeout = agentUnlockTimeout + agentUnlockServerGrace
	}
	defer cancel()
	_ = c.SetDeadline(time.Now().Add(responseTimeout))
	resp := s.dispatch(requestCtx, &req)
	_ = WriteFrame(c, resp)
}

func (s *Server) dispatch(ctx context.Context, req *Request) (resp *Response) {
	// Check both deadlines before serving any operation. A request arriving
	// after expiration must not revive or use an expired session while waiting
	// for the lifecycle goroutine to run.
	s.enforceLifetime(time.Now())
	defer func() {
		if resp != nil && resp.Err == "" && refreshesIdleDeadline(req.Op) {
			s.markActivity(time.Now())
		}
	}()
	switch req.Op {
	case OpStatus:
		return s.handleStatus()
	case OpUnlock:
		if req.Unlock == nil {
			return errResp("missing unlock body")
		}
		return s.handleUnlockContext(ctx, req.Unlock)
	case OpLock:
		s.lock()
		return &Response{}
	case OpSign:
		if req.Sign == nil {
			return errResp("missing sign body")
		}
		return s.handleSign(req.Sign)
	case OpOpenSeal:
		if req.OpenSeal == nil {
			return errResp("missing open_seal body")
		}
		return s.handleOpenSeal(req.OpenSeal)
	case OpReSeal:
		if req.ReSeal == nil {
			return errResp("missing re_seal body")
		}
		return s.handleReSeal(req.ReSeal)
	case OpGetBody:
		return s.handleGetBody()
	case OpRecoveryExport:
		if req.RecoveryExport == nil {
			return errResp("missing recovery_export body")
		}
		return s.handleRecoveryExport(req.RecoveryExport)
	case OpEncryptSuperPriv:
		if req.EncryptSuperPriv == nil {
			return errResp("missing encrypt_super_priv body")
		}
		return s.handleEncryptSuperPriv(req.EncryptSuperPriv)
	case OpAddWrap:
		if req.AddWrap == nil {
			return errResp("missing add_wrap body")
		}
		return s.handleAddWrap(req.AddWrap)
	case OpRemoveWrap:
		if req.RemoveWrap == nil {
			return errResp("missing remove_wrap body")
		}
		return s.handleRemoveWrap(req.RemoveWrap)
	default:
		return errResp(fmt.Sprintf("bad op %d", req.Op))
	}
}

func refreshesIdleDeadline(op uint8) bool {
	switch op {
	case OpSign, OpOpenSeal, OpReSeal, OpGetBody, OpRecoveryExport,
		OpEncryptSuperPriv, OpAddWrap, OpRemoveWrap:
		return true
	default:
		return false
	}
}

func (s *Server) handleStatus() *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &StatusResp{
		Unlocked:          s.superPriv != nil,
		Protocol:          ProtocolVersion,
		StartedBy:         s.cfg.StartedBy,
		Version:           s.cfg.Version,
		Flavor:            s.cfg.Flavor,
		YubikeyEnabled:    s.cfg.YubikeyEnabled,
		IdleTimeoutMillis: s.cfg.IdleTimeout.Milliseconds(),
		MaxLifetimeMillis: s.cfg.MaxLifetime.Milliseconds(),
	}
	if st.Unlocked {
		st.SinceUnix = s.unlockedAt.Unix()
		st.UnlockSession = s.unlockSession
		st.UserSuperPub = append([]byte(nil), s.userSuperPub...)
		st.ActiveMethodID = s.unlockMID
	}
	return &Response{Status: st}
}

const unlockTimeoutMessage = "unlock timed out before completion"

func (s *Server) handleUnlock(u *UnlockReq) *Response {
	return s.handleUnlockContext(context.Background(), u)
}

func (s *Server) handleUnlockContext(ctx context.Context, u *UnlockReq) *Response {
	// Sensitive credentials decoded from the wire frame: wipe before
	// returning, regardless of which path runs. We register the
	// wipes BEFORE any fallible call so a vault.Read / parse / RPC
	// error can't leave PIN or passphrase bytes on the heap.
	// (The wire-frame buffer itself was already wiped in ReadFrame.)
	defer crypto.Wipe(u.Passphrase)
	defer crypto.Wipe(u.YubikeyPIN)
	if ctx.Err() != nil {
		return errResp(unlockTimeoutMessage)
	}

	// Refuse ambiguous credential bundles. The wire schema permits
	// both Passphrase and YubikeyPIN to be set, but exactly one
	// must be populated for the chosen method_type. Accepting a
	// request with both lets a buggy / malicious client smuggle
	// extra material into a session in case the agent ever changes
	// which credential it consumes; fail closed instead.
	if len(u.Passphrase) > 0 && len(u.YubikeyPIN) > 0 {
		return errResp("agent: UnlockReq carries both Passphrase and YubikeyPIN; exactly one must be set for the chosen method_type")
	}

	// Validate the method type BEFORE doing any I/O. A misconfigured
	// client (or a deliberately-bad request) shouldn't make us read
	// the vault file just to discover we can't unlock it. The early
	// check also keeps the error message scoped to the actual
	// problem.
	var resolver vault.MethodResolver
	switch u.MethodType {
	case proto.AuthPassphrase:
		if len(u.YubikeyPIN) > 0 {
			return errResp("agent: method_type=passphrase but YubikeyPIN is set; reject ambiguous credential")
		}
		resolver = vault.PassphraseResolver{Passphrase: u.Passphrase}
	case proto.AuthYubikey:
		if len(u.Passphrase) > 0 {
			return errResp("agent: method_type=yubikey but Passphrase is set; reject ambiguous credential")
		}
		if s.cfg.NewYubikeyResolver == nil {
			return errResp(vault.ErrYubikeyNotConfigured.Error())
		}
		resolver = s.cfg.NewYubikeyResolver(u.YubikeyPIN)
		if resolver == nil {
			return errResp(vault.ErrYubikeyNotConfigured.Error())
		}
	default:
		return errResp(fmt.Sprintf("unsupported method_type %q", u.MethodType))
	}

	if err := s.validateCanonicalPaths(u.VaultPath, u.UserChainPath); err != nil {
		return errResp(err.Error())
	}
	v, err := vault.Read(s.paths.Vault)
	if err != nil {
		return errResp(err.Error())
	}
	res, err := vault.Open(v, []vault.MethodResolver{resolver})
	if err != nil {
		return errResp(err.Error())
	}
	defer wipeOpenResult(&res)
	body := res.Body
	if len(body.SuperPriv) != ed25519.PrivateKeySize {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault body super_priv: bad length")
	}
	derivedPub := ed25519.PrivateKey(body.SuperPriv).Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPub, v.UserSuperPub) {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault: super_priv pub != user_super_pub")
	}

	// The canonical signed user chain is authoritative for every unlock, not
	// only when its tip is ahead of the vault. This rejects revoked methods
	// and orphan wraps even when a stale vault has an internally consistent
	// AuthTip.
	st, rerr := chain.ReplayUser(s.paths.UserChain)
	if rerr != nil {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(fmt.Sprintf("vault: replay canonical user chain: %v", rerr))
	}
	if st == nil || st.LatestAuthSet == nil {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault: canonical user chain is missing; refusing to unlock")
	}
	if !bytes.Equal(st.UserSuperPub, v.UserSuperPub) {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp("vault: canonical user chain belongs to a different identity")
	}
	if len(body.AuthTip.Hash) != 32 {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(fmt.Sprintf(
			"vault: AuthTip.Hash is %d bytes (want 32) — possible legacy/rolled-back vault; refusing to unlock",
			len(body.AuthTip.Hash),
		))
	}
	if st.TipSeq < body.AuthTip.Seq ||
		(st.TipSeq == body.AuthTip.Seq && !bytes.Equal(st.TipHash, body.AuthTip.Hash)) {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(fmt.Sprintf(
			"vault: ROLLBACK DETECTED — vault auth_tip (seq=%d) does not match canonical user chain tip (seq=%d)",
			body.AuthTip.Seq, st.TipSeq,
		))
	}
	if err := verifyLiveAuthMethod(st, v.UserSuperPub, body.SuperPriv, res.UsedWrap, res.UnlockKey); err != nil {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(fmt.Sprintf("vault: used auth method is not active in the canonical user chain: %v", err))
	}

	x, err := crypto.EdPrivToX25519(body.SuperPriv)
	if err != nil {
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		return errResp(err.Error())
	}
	// Finish all fallible preparation before replacing the live session. A
	// failed unlock response must never leave newly-installed keys behind.
	redacted := *body
	redacted.SuperPriv = bytes.Repeat([]byte{0}, ed25519.PrivateKeySize)
	rb, err := proto.Marshal(redacted)
	if err != nil {
		crypto.Wipe(x)
		crypto.Wipe(res.UnlockKey)
		crypto.Wipe(res.PayloadKey)
		crypto.Wipe(body.SuperPriv)
		return errResp(err.Error())
	}
	s.mu.Lock()
	if ctx.Err() != nil {
		s.mu.Unlock()
		crypto.Wipe(x)
		crypto.Wipe(rb)
		return errResp(unlockTimeoutMessage)
	}
	if s.superPriv != nil {
		s.superPriv.Destroy()
	}
	if s.x25519Priv != nil {
		s.x25519Priv.Destroy()
	}
	if s.unlockKey != nil {
		s.unlockKey.Destroy()
	}
	if s.payloadKey != nil {
		s.payloadKey.Destroy()
	}
	s.superPriv = crypto.NewSecretCopy(body.SuperPriv)
	s.x25519Priv = crypto.NewSecret(x)
	s.unlockKey = crypto.NewSecret(res.UnlockKey) // takes ownership; wipes uk
	s.payloadKey = crypto.NewSecret(res.PayloadKey)
	s.unlockMID = res.UsedWrap.MethodID
	s.unlockMType = res.UsedWrap.MethodType
	s.unlockPP = append([]byte(nil), res.UsedWrap.PublicParams...)
	s.userSuperPub = append([]byte(nil), v.UserSuperPub...)
	now := time.Now()
	s.unlockedAt = now
	s.unlockSession = rand.Text()
	s.lastActivity = now
	// SECURITY (codex audit 🟡 server.go:305): wipe any prior
	// redactedBody before overwriting. The "redacted" body still
	// contains OEKs and other sensitive scope data; repeated
	// unlocks would leave old buffers in heap memory until GC.
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
	}
	s.redactedBody = rb
	s.mu.Unlock()
	s.signalLifecycle()
	// Zero the original body (best-effort; CBOR decode allocated copies).
	crypto.Wipe(body.SuperPriv)
	if s.scheduler != nil && s.scheduler.cfg.OnUnlock {
		go s.scheduler.TriggerSync("unlock")
	}
	return &Response{Unlock: &UnlockResp{
		RedactedBody: rb,
		UserSuperPub: append([]byte(nil), v.UserSuperPub...),
	}}
}

func wipeOpenResult(res *vault.OpenResult) {
	if res == nil {
		return
	}
	crypto.Wipe(res.UnlockKey)
	crypto.Wipe(res.PayloadKey)
	if res.Body != nil {
		crypto.Wipe(res.Body.SuperPriv)
	}
}

func (s *Server) handleSign(sr *SignReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	// Go's ed25519 internally caches expanded scalars via weak pointers,
	// which require GC-managed memory. memguard buffers are mlocked outside
	// the heap. Copy briefly, sign, wipe.
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	// Wave C-3': SignBytes is the byte-slice boundary helper —
	// the agent's mlocked source is the trust anchor; the typed
	// Ed25519Priv path is for callers who hold the value across
	// multiple operations. SignBytes runs the length-gate then
	// hands to ed25519.Sign on a guaranteed-correct-length input.
	sig, err := crypto.SignBytes(priv, sr.Payload)
	if err != nil {
		return errResp("sign failed")
	}
	return &Response{Sign: &SignResp{Signature: sig}}
}

func (s *Server) handleOpenSeal(or *OpenSealReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.x25519Priv == nil {
		return errResp("locked")
	}
	// Same heap-vs-mlock concern as Sign: copy briefly.
	xPriv := make([]byte, 32)
	copy(xPriv, s.x25519Priv.Bytes())
	defer crypto.Wipe(xPriv)
	xPub, err := crypto.X25519Pub(xPriv)
	if err != nil {
		return errResp(err.Error())
	}
	plain, ok := crypto.OpenAnonymous(or.Sealed, xPub, xPriv)
	if !ok {
		return errResp("open_anonymous failed")
	}
	return &Response{OpenSeal: &OpenSealResp{Plain: plain}}
}

func (s *Server) handleReSeal(r *ReSealReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	if err := s.validateCanonicalVaultPath(r.VaultPath); err != nil {
		return errResp(err.Error())
	}
	body, err := s.unredact(r.RedactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	if err := vault.SaveBody(s.paths.Vault, s.userSuperPub, body, pk); err != nil {
		return errResp(err.Error())
	}
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
	}
	s.redactedBody = append([]byte(nil), r.RedactedBody...)
	return &Response{ReSeal: &ReSealResp{}}
}

// unredact rebuilds a VaultBody from the redacted CBOR + cached super_priv.
// Returns a body with super_priv populated; caller wipes after use.
func (s *Server) unredact(redactedBody []byte) (*proto.VaultBody, error) {
	var body proto.VaultBody
	if err := proto.Unmarshal(redactedBody, &body); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	if !bytes.Equal(body.SuperPriv, bytes.Repeat([]byte{0}, ed25519.PrivateKeySize)) {
		return nil, errors.New("redacted_body: super_priv not zero-redacted")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	body.SuperPriv = priv
	return &body, nil
}

// handleGetBody returns the cached redacted body. Caller must already have
// unlocked the vault.
//
// SECURITY NOTE. The redacted body still contains every OEK the user holds
// (one per subscribed scope, per OEK version). Same-UID-Code-Execution
// attackers can read these. This is acceptable in v1 because:
//  1. Same-UID attackers can equally call Sign/OpenSeal to recover OEKs by
//     simulating member.change replay.
//  2. THREATS.md §2 lists same-UID compromise as an acknowledged limit.
//  3. The agent's value-add is keeping super_priv (the master key) sealed;
//     OEK lifecycle is shorter (rotates on every member.change) and recovery
//     after compromise of an OEK era is supported by the protocol.
func (s *Server) handleGetBody() *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.redactedBody == nil {
		return errResp("locked")
	}
	return &Response{GetBody: &GetBodyResp{
		RedactedBody: append([]byte(nil), s.redactedBody...),
		UserSuperPub: append([]byte(nil), s.userSuperPub...),
	}}
}

// handleRecoveryExport AEAD-encrypts super_priv under the caller-supplied
// K_recovery. super_priv never leaves the agent in plaintext, but a
// same-UID caller CAN exfiltrate the current identity by supplying their
// own K_recovery and decrypting the response. This is consistent with the
// agent's documented same-UID trust boundary (THREATS.md §2: same-UID
// code execution); the user_super_pub check below only prevents export
// under a foreign identity, not exfiltration of the current one.
func (s *Server) handleRecoveryExport(r *RecoveryExportReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	if len(r.UnlockKey) != 32 || len(r.Nonce) != 12 || len(r.UserSuperPub) != 32 {
		return errResp("recovery_export: bad params")
	}
	if !bytes.Equal(r.UserSuperPub, s.userSuperPub) {
		return errResp("recovery_export: user_super_pub mismatch")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	aad := append([]byte(proto.DomainRecoveryKey), r.UserSuperPub...)
	ct, err := crypto.AEADSeal(r.UnlockKey, r.Nonce, priv, aad)
	if err != nil {
		return errResp(err.Error())
	}
	return &Response{RecoveryExport: &RecoveryExportResp{Encrypted: ct}}
}

// handleEncryptSuperPriv produces an `encrypted_super_priv` blob (nonce ||
// AEAD-ciphertext) under K_unlock with the protocol AAD. Used by `fd0 auth
// add` to assemble the new AuthMethod for the next auth.set.
func (s *Server) handleEncryptSuperPriv(r *EncryptSuperPrivReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil {
		return errResp("locked")
	}
	if len(r.UnlockKey) != 32 {
		return errResp("encrypt_super_priv: bad K_unlock length")
	}
	if r.MethodID == "" {
		return errResp("encrypt_super_priv: empty method_id")
	}
	priv := make([]byte, ed25519.PrivateKeySize)
	copy(priv, s.superPriv.Bytes())
	defer crypto.Wipe(priv)
	enc, err := vault.EncryptSuperPriv(priv, s.userSuperPub, r.MethodID, r.UnlockKey)
	if err != nil {
		return errResp(err.Error())
	}
	return &Response{EncryptSuperPriv: &EncryptSuperPrivResp{EncryptedSuperPriv: enc}}
}

// handleAddWrap encrypts the cached payload_key under the supplied K_unlock
// and appends the wrap to the on-disk vault. Body is re-encrypted (AAD
// covers the wraps array).
func (s *Server) handleAddWrap(r *AddWrapReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	if err := s.validateCanonicalVaultPath(r.VaultPath); err != nil {
		return errResp(err.Error())
	}
	if r.MethodID == "" || r.MethodType == "" || len(r.UnlockKey) != 32 {
		return errResp("add_wrap: missing method_id/method_type/unlock_key")
	}
	body, err := s.unredact(s.redactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	wrap := vault.WrapInput{
		MethodID:     r.MethodID,
		MethodType:   r.MethodType,
		PublicParams: r.PublicParams,
		UnlockKey:    r.UnlockKey,
	}
	st, err := chain.ReplayUser(s.paths.UserChain)
	if err != nil {
		return errResp(fmt.Sprintf("add_wrap: replay canonical user chain: %v", err))
	}
	candidate := &proto.WrappedKey{
		MethodID:     r.MethodID,
		MethodType:   r.MethodType,
		PublicParams: r.PublicParams,
	}
	if err := verifyLiveAuthMethod(st, s.userSuperPub, body.SuperPriv, candidate, r.UnlockKey); err != nil {
		return errResp(fmt.Sprintf("add_wrap: method is not active in the canonical user chain: %v", err))
	}
	if err := vault.AddWrap(s.paths.Vault, s.userSuperPub, body, pk, wrap); err != nil {
		return errResp(err.Error())
	}
	return &Response{AddWrap: &AddWrapResp{}}
}

// handleRemoveWrap drops a wrap from the on-disk vault. Refuses to remove
// the currently-active wrap (would lock the agent out for future re-seals)
// and refuses to leave zero wraps.
func (s *Server) handleRemoveWrap(r *RemoveWrapReq) *Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.superPriv == nil || s.payloadKey == nil {
		return errResp("locked")
	}
	if err := s.validateCanonicalVaultPath(r.VaultPath); err != nil {
		return errResp(err.Error())
	}
	if r.MethodID == s.unlockMID {
		return errResp("remove_wrap: cannot remove the currently-active method (lock first, unlock with another method, then retry)")
	}
	body, err := s.unredact(s.redactedBody)
	if err != nil {
		return errResp(err.Error())
	}
	defer crypto.Wipe(body.SuperPriv)
	pk := make([]byte, 32)
	copy(pk, s.payloadKey.Bytes())
	defer crypto.Wipe(pk)
	if err := vault.RemoveWrap(s.paths.Vault, s.userSuperPub, body, pk, r.MethodID); err != nil {
		return errResp(err.Error())
	}
	return &Response{RemoveWrap: &RemoveWrapResp{}}
}

// lock zeroizes super_priv, x25519_priv, and the cached body.
func (s *Server) lock() {
	s.mu.Lock()
	s.lockHeld()
	s.mu.Unlock()
	s.signalLifecycle()
}

func (s *Server) lockHeld() {
	if s.superPriv != nil {
		s.superPriv.Destroy()
		s.superPriv = nil
	}
	if s.x25519Priv != nil {
		s.x25519Priv.Destroy()
		s.x25519Priv = nil
	}
	if s.unlockKey != nil {
		s.unlockKey.Destroy()
		s.unlockKey = nil
	}
	if s.payloadKey != nil {
		s.payloadKey.Destroy()
		s.payloadKey = nil
	}
	if s.redactedBody != nil {
		crypto.Wipe(s.redactedBody)
		s.redactedBody = nil
	}
	s.unlockMID = ""
	s.unlockMType = ""
	s.unlockPP = nil
	s.userSuperPub = nil
	s.unlockedAt = time.Time{}
	s.unlockSession = ""
	s.lastActivity = time.Time{}
}

func (s *Server) validateCanonicalPaths(vaultPath, userChainPath string) error {
	if err := s.validateCanonicalVaultPath(vaultPath); err != nil {
		return err
	}
	if s.paths.UserChain == "" {
		return errors.New("agent: canonical user chain path is unavailable")
	}
	if userChainPath != "" && userChainPath != s.paths.UserChain {
		return errors.New("agent: refusing caller-selected user chain path")
	}
	return nil
}

func (s *Server) validateCanonicalVaultPath(vaultPath string) error {
	if s.paths.Vault == "" {
		return errors.New("agent: canonical vault path is unavailable")
	}
	if vaultPath != "" && vaultPath != s.paths.Vault {
		return errors.New("agent: refusing caller-selected vault path")
	}
	return nil
}

func verifyLiveAuthMethod(st *chain.UserState, userSuperPub, superPriv []byte, used *proto.WrappedKey, unlockKey []byte) error {
	if st == nil || st.LatestAuthSet == nil {
		return errors.New("missing latest auth.set")
	}
	if !bytes.Equal(st.UserSuperPub, userSuperPub) {
		return errors.New("auth.set belongs to a different identity")
	}
	if used == nil {
		return errors.New("missing used wrap")
	}
	for _, m := range st.LatestAuthSet.Payload.Active {
		if m.MethodID != used.MethodID {
			continue
		}
		if m.MethodType != used.MethodType {
			return fmt.Errorf("method_type changed from %q to %q", used.MethodType, m.MethodType)
		}
		if !bytes.Equal(m.PublicParams, used.PublicParams) {
			return errors.New("public_params changed")
		}
		plain, err := vault.DecryptSuperPriv(m.EncryptedSuperPriv, userSuperPub, m.MethodID, unlockKey)
		if err != nil {
			return fmt.Errorf("encrypted_super_priv does not open under used K_unlock: %w", err)
		}
		defer crypto.Wipe(plain)
		if !bytes.Equal(plain, superPriv) {
			return errors.New("encrypted_super_priv opens to different super_priv")
		}
		return nil
	}
	return fmt.Errorf("method_id %q is no longer active", used.MethodID)
}

func errResp(msg string) *Response { return &Response{Err: msg} }

// SafeExit calls memguard.SafePanic on signals; the Stop helper calls Purge.
func SafeExit() { memguard.SafePanic(errors.New("agent SafeExit")) }

// isPriorAgentAlive reads the PID file (if any) and probes whether the
// recorded process is still around. We use signal 0 (no-op) to test
// liveness without disturbing the process. Returns (alive, pid).
//
// On any error (no file, bad content, foreign-owned PID) we conservatively
// return (false, 0) — the caller will then proceed and replace the socket.
// The worst-case behaviour is a brief duplicate-agent window during crash
// recovery, which is no worse than the previous unconditional behaviour.
func isPriorAgentAlive(pidPath string) (bool, int) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return false, 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return false, 0
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}
	// On Unix, FindProcess always succeeds; signal 0 is the liveness probe.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return false, 0
	}
	return true, pid
}

// probeAgentSocket returns true iff something is currently listening
// on `path`. Used in Listen() to detect the bug-class where the PID
// file is missing/stale but an old agent is still serving requests
// — unlinking the socket then would orphan the old agent (still
// holding super_priv mlocked) and start a duplicate.
func probeAgentSocket(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
