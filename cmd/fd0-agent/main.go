// fd0-agent is the local key-holding daemon. It listens on
// $FD0_HOME/agent.sock (default ~/.fd0/agent.sock) and serves five operations
// to same-UID clients: status, unlock, lock, sign, open_seal, re_seal.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/awnumar/memguard"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/buildinfo"
	fd0cli "github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/sshagent"
)

// version is overwritten by goreleaser via `-ldflags="-X main.version=..."`.
var version = "dev"

type cli struct {
	// No kong defaults: we can't otherwise distinguish "user passed 5m" from
	// "kong filled the default in". Resolution layered in main() so config
	// can take effect when neither flag nor env are set.
	IdleTimeout string `name:"idle-timeout" help:"Lock after idle (default 5m, or [agent].idle_timeout)." env:"FD0_AGENT_IDLE"`
	MaxLifetime string `name:"max-lifetime" help:"Lock after max lifetime (default 8h, or [agent].max_lifetime)." env:"FD0_AGENT_MAX_LIFETIME"`
	Verbose     bool   `name:"verbose" short:"v" help:"Verbose logging." env:"FD0_AGENT_VERBOSE"`
	Version     bool   `name:"version" help:"Print version and exit."`
}

func main() {
	// SECURITY (codex audit 🔴 cmd/fd0-agent/main.go:36): do NOT
	// call memguard.CatchInterrupt — it installs its own signal
	// handler that races our graceful-shutdown handler below. On
	// the race CatchInterrupt's os.Exit fires first, bypassing
	// `defer srv.Close()` and leaving stale agent.sock + agent.pid
	// behind (subsequent agent invocations then refuse to start).
	// We explicitly call memguard.Purge() inside our own shutdown
	// goroutine instead.
	defer memguard.Purge()
	var c cli
	kong.Parse(&c, kong.Name("fd0-agent"))
	if c.Version {
		fmt.Printf("fd0-agent %s %s\n", version, buildinfo.Flavor)
		return
	}
	level := slog.LevelInfo
	if c.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	paths, err := fdhome.Resolve()
	if err != nil {
		log.Error("resolve home", "err", err)
		os.Exit(1)
	}
	if err := paths.EnsureDirs(); err != nil {
		log.Error("ensure dirs", "err", err)
		os.Exit(1)
	}
	// Load ~/.fd0/config.toml so the agent can run periodic auto-sync.
	cfg, err := fdhome.LoadConfig(paths.Config)
	if err != nil {
		log.Warn("config: load failed, continuing with defaults", "err", err)
	}

	// Resolve idle / max-lifetime: flag > env > config > hardcoded default.
	// Kong already merges flag and env into c.IdleTimeout / c.MaxLifetime.
	idle, err := resolveDuration(c.IdleTimeout, cfg.Agent.IdleTimeout, 5*time.Minute, "idle-timeout")
	if err != nil {
		log.Error("bad idle-timeout", "err", err)
		os.Exit(2)
	}
	maxLife, err := resolveDuration(c.MaxLifetime, cfg.Agent.MaxLifetime, 8*time.Hour, "max-lifetime")
	if err != nil {
		log.Error("bad max-lifetime", "err", err)
		os.Exit(2)
	}
	// Single-primary resolution. If FD0_SERVER is set in the agent's env
	// (override path), pass it through so the child `fd0 sync` uses it.
	// Otherwise leave it unset so the child resolves [sync].server from
	// config and ultimately falls back to fdhome.DefaultServer.
	serverOverride := os.Getenv("FD0_SERVER")
	var sched *agent.Scheduler
	onUnlock := cfg.Sync.OnUnlockEnabled()
	interval := cfg.SyncIntervalDuration()
	if os.Getenv("FD0_AGENT_SYNC_DISABLED") == "1" {
		onUnlock = false
		interval = 0
		log.Info("agent: automatic sync disabled by environment")
	}
	if interval > 0 || onUnlock {
		sched = agent.NewScheduler(agent.SchedulerConfig{
			Interval: interval,
			OnUnlock: onUnlock,
			FD0Bin:   os.Getenv("FD0_BIN"),
			Server:   serverOverride,
			Home:     paths.Home,
		}, log)
		// Log what the child will pick up. Empty override means config
		// resolution wins — surface the resolved primary so the user sees
		// what the agent will hit.
		if interval > 0 {
			server := serverOverride
			if server == "" {
				server, _ = cfg.Sync.ResolvedServer()
			}
			log.Info("agent: auto-sync enabled", "interval", interval, "server", server)
		}
		if onUnlock {
			log.Info("agent: on-unlock sync enabled")
		}
	}
	srv, err := agent.Listen(paths, agent.Config{
		IdleTimeout:        idle,
		MaxLifetime:        maxLife,
		Logger:             log,
		Scheduler:          sched,
		NewYubikeyResolver: newYubikeyResolverFactory(),
		Version:            version,
		Flavor:             buildinfo.Flavor,
		YubikeyEnabled:     buildinfo.YubikeyEnabled,
		StartedBy:          agent.StartedByFromEnv(),
	})
	if err != nil {
		// The home is already served — by the user's shell session, or by a
		// service that won the race. One agent per home is the rule and it
		// still holds; we simply have nothing left to do. Exiting 0 says that
		// to launchd (KeepAlive/SuccessfulExit) and systemd (Restart=on-failure)
		// so neither respawns us into the same conflict every few seconds.
		if errors.Is(err, agent.ErrAlreadyServing) {
			log.Info("fd0-agent: nothing to do", "reason", err)
			return
		}
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("agent: shutdown")
		cancel()
		srv.Close()
		memguard.Purge() // explicit; was a no-op before (`_ = memguard.Purge`).
	}()

	log.Info("fd0-agent listening", "sock", paths.AgentSock)

	// Start the optional SSH-agent socket. Default behaviour: enable
	// when an SSH socket path is reachable (we always create one; it
	// just returns empty when the vault is locked, which is the
	// industry-standard "no identities" degradation). Operators can
	// disable via FD0_SSH_SOCK="" (empty string).
	sshSock, sshSockSet := os.LookupEnv("FD0_SSH_SOCK")
	if !sshSockSet {
		sshSock = sshagent.DefaultSocketPath()
	}
	if sshSock == "" {
		log.Info("ssh-agent socket disabled", "reason", "FD0_SSH_SOCK is empty")
	} else {
		stopSSH, err := srv.StartSSHSocket(ctx, log, sshSock, func(fetchCtx context.Context) ([]sshagent.KeyEntry, error) {
			// We open a CLI session per fetch — see ssh_socket.go for
			// the concurrency notes. The flock is released by the
			// session's Close before we return.
			s, err := fd0cli.OpenSSHSession(fetchCtx)
			if err != nil {
				return nil, err
			}
			defer s.Close()
			raw, err := fd0cli.CollectKeyEntries(s)
			if err != nil {
				return nil, err
			}
			out := make([]sshagent.KeyEntry, len(raw))
			for i, e := range raw {
				out[i] = sshagent.KeyEntry{Key: e.Key, Comment: e.Comment}
			}
			return out, nil
		})
		if err != nil {
			log.Warn("ssh-agent socket disabled", "err", err)
		} else {
			defer stopSSH()
		}
	}

	if err := srv.Serve(ctx); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

// resolveDuration picks a duration from the layered config: a non-empty
// flagOrEnv (Kong fills this from --flag and matching env) wins, else a
// non-empty configValue, else the hardcoded fallback. Empty inputs are
// skipped silently so the user can leave fields out without warnings.
func resolveDuration(flagOrEnv, configValue string, fallback time.Duration, name string) (time.Duration, error) {
	pick := flagOrEnv
	if pick == "" {
		pick = configValue
	}
	if pick == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(pick)
	if err != nil {
		return 0, fmt.Errorf("%s %q: %w", name, pick, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s %q: duration must be greater than zero", name, pick)
	}
	return d, nil
}
