// Package simtest is a deterministic, in-process simulation harness for
// the fd0 multi-client / multi-server sync layer.
//
// Motivation: every sync bug we have found (foreign-event loss on
// reconcile, incomplete-history recovery, divergence handling)
// is an EMERGENT multi-actor state interaction that unit tests and even
// scripted integration tests miss. This harness drives the REAL stack —
// real fd0 client binary + real agent + the real server HTTP handler in
// process — through a SEEDED random schedule of operations with
// controllable network partitions, and asserts hard invariants after
// every quiescent point. A failing seed is a reproducible bug report.
//
// Fidelity vs. speed: servers run in-process (httptest + a fault gate)
// so the harness can both inject partitions and inspect authoritative
// server state directly for invariant checks; clients run as real
// subprocesses (one long-lived agent each, reused across ops) so the
// exact production client code — sync, reconcile, history repair — is
// exercised, with zero changes to production code.
//
// Determinism: the operation schedule and the fault schedule are derived
// from a single seed, so a failure reproduces. Wall-clock timing of the
// real binaries adds some nondeterminism, but the logical schedule does
// not, which is what matters for shrinking a failure to a minimal case.
package simtest

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/server"
)

// FaultMode is how the fault gate perturbs a server.
type FaultMode int32

const (
	FaultNone       FaultMode = iota // pass through
	FaultPartition                   // drop the connection pre-handler (unreachable)
	FaultPostCommit                  // run the handler (it COMMITS), then drop the response
	Fault429                         // reply 429 Too Many Requests (no handler)
	Fault503                         // reply 503 Service Unavailable (no handler)
)

// Server is one in-process fd0-server with a fault gate in front.
type Server struct {
	Label string
	URL   string
	srv   *server.Server
	http  *httptest.Server
	mode  atomic.Int32 // FaultMode
}

// SetFault sets the active fault mode.
func (s *Server) SetFault(m FaultMode) { s.mode.Store(int32(m)) }

// SetDown partitions (true) or heals (false) the server — a transport
// error, NOT an HTTP status. Kept for the partition-only callers.
func (s *Server) SetDown(down bool) {
	if down {
		s.mode.Store(int32(FaultPartition))
	} else {
		s.mode.Store(int32(FaultNone))
	}
}

// IsDown reports whether the server is partitioned.
func (s *Server) IsDown() bool { return FaultMode(s.mode.Load()) == FaultPartition }

func dropConn(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	w.WriteHeader(http.StatusServiceUnavailable) // fallback
}

// faultHandler wraps the real server handler with the fault gate.
func (s *Server) faultHandler(real http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch FaultMode(s.mode.Load()) {
		case FaultPartition:
			// Unreachable: client sees a transport error, as for a real
			// partition (distinct from an HTTP error status).
			dropConn(w)
		case FaultPostCommit:
			// The server PROCESSES the request (committing any write to its
			// store) but the response never reaches the client — the
			// "accepted but un-acked" case. The client must treat it as a
			// failure, re-push next round, and the server must dedup
			// idempotently. We run the handler against a throwaway recorder
			// (the DB commit happens inside it, independent of this writer),
			// then drop the real connection.
			real.ServeHTTP(httptest.NewRecorder(), r)
			dropConn(w)
		case Fault429:
			w.WriteHeader(http.StatusTooManyRequests)
		case Fault503:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			real.ServeHTTP(w, r)
		}
	})
}

// Harness owns the servers, the client homes, and the built binaries for
// one simulation run. Construct via New; always defer Close.
type Harness struct {
	t        *testing.T
	dir      string // root temp dir
	fd0Bin   string
	agentBin string
	Servers  []*Server
	Clients  []*Client
	mu       sync.Mutex // serialises client ops (the schedule is sequential)
}

// New builds the fd0 + fd0-agent binaries once, then starts nServers
// in-process servers. Clients are added separately (AddClient) so a test
// controls membership setup.
func New(t *testing.T, nServers int) *Harness {
	t.Helper()
	// IMPORTANT: root at a SHORT path, not t.TempDir(). The agent binds a
	// unix socket at <FD0_HOME>/agent.sock, and macOS caps sun_path at
	// ~104 bytes. A subtest's t.TempDir() ("…/TestSimSeedsseed=1…/001/")
	// plus "<client>/agent.sock" overflows that and the agent silently
	// fails to listen ("agent: not ready"). /tmp keeps the path tiny.
	dir, err := os.MkdirTemp(shortTmpRoot(), "fs")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	h := &Harness{t: t, dir: dir}
	h.fd0Bin = h.build("fd0", "./cmd/fd0")
	h.agentBin = h.build("fd0-agent", "./cmd/fd0-agent")
	for i := 0; i < nServers; i++ {
		h.Servers = append(h.Servers, h.startServer(fmt.Sprintf("srv%d", i)))
	}
	t.Cleanup(h.Close)
	return h
}

// build compiles a cmd into the harness bin dir and returns its path.
func (h *Harness) build(name, pkg string) string {
	h.t.Helper()
	out := filepath.Join(h.dir, "bin", name)
	// repoRoot: walk up from the test's working dir to the module root.
	// Simulated clients must never fall back to the hosted server.
	cmd := exec.Command("go", "build", "-ldflags", testDefaultServerLDFlag(), "-o", out, pkg)
	cmd.Dir = repoRoot(h.t)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		h.t.Fatalf("build %s: %v\n%s", name, err, stderr.String())
	}
	return out
}

// testDefaultServerLDFlag points fdhome.DefaultServer at an unresolvable
// .invalid host (RFC 2606) in every binary the harness builds.
func testDefaultServerLDFlag() string {
	pkg := reflect.TypeOf(fdhome.SyncConfig{}).PkgPath()
	return "-X " + pkg + ".DefaultServer=http://default-server.fd0-test.invalid"
}

// startServer brings up one in-process fd0-server behind a fault gate.
func (h *Harness) startServer(label string) *Server {
	h.t.Helper()
	dbPath := filepath.Join(h.dir, "server-"+label+".db")
	srv, err := server.New(server.Config{
		DBPath:  dbPath,
		Version: "simtest",
		Label:   label,
		// Each server MUST have its own translog identity. The default
		// key path is <db-dir>/server-translog.key — shared across
		// servers in the same dir, which would make them indistinguishable
		// (and break primary-per-scope anchor selection, which keys on the
		// translog pubkey). Give each its own key file.
		TranslogKeyPath:   filepath.Join(h.dir, "server-"+label+".key"),
		RateLimitDisabled: true,
	})
	if err != nil {
		h.t.Fatalf("server.New(%s): %v", label, err)
	}
	s := &Server{Label: label, srv: srv}
	s.http = httptest.NewServer(s.faultHandler(srv))
	s.URL = s.http.URL
	return s
}

// Close tears down servers (clients clean themselves up via t.Cleanup).
func (h *Harness) Close() {
	for _, c := range h.Clients {
		c.stopAgent()
	}
	for _, s := range h.Servers {
		if s.http != nil {
			s.http.Close()
		}
		if s.srv != nil {
			_ = s.srv.Close()
		}
	}
}

// ServerURLs returns the configured server URLs in order.
func (h *Harness) ServerURLs() []string {
	out := make([]string, len(h.Servers))
	for i, s := range h.Servers {
		out[i] = s.URL
	}
	return out
}

// shortTmpRoot returns a short base dir for unix sockets. macOS's
// $TMPDIR (/var/folders/…) is already ~50 chars before we add anything;
// /tmp is short and present on every unix CI runner. Falls back to ""
// (os default) on platforms without /tmp.
func shortTmpRoot() string {
	if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
		return "/tmp"
	}
	return ""
}

// repoRoot finds the module root by walking up until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repoRoot: go.mod not found above " + dir)
		}
		dir = parent
	}
}
