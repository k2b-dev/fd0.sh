package cli

// `fd0 ssh [NAME] [cmd...]` — the connect / picker entry point. When
// invoked with no alias, opens a fuzzy picker over the known hosts
// (uses internal/tui/picker) and execs ssh on the choice. When
// invoked with an unambiguous alias, execs directly. When invoked
// with a prefix that matches multiple hosts, opens the picker
// pre-filtered.
//
// Importantly we exec ssh, not net.Dial — every native flag (-J, -L,
// -A, etc.) just works because the user's ssh client is in charge of
// the connection.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/valentinkolb/fd0.sh/internal/sshhost"
	"github.com/valentinkolb/fd0.sh/internal/tui"
)

type OpenSSHConnection struct {
	Alias      string
	ConfigPath string
	SSHBinary  string
}

func (c OpenSSHConnection) SFTPSubsystemArgs() []string {
	args := make([]string, 0, 8)
	if c.ConfigPath != "" {
		args = append(args, "-F", c.ConfigPath)
	}
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-s", c.Alias, "sftp",
	)
	return args
}

// PrepareOpenSSHConnection resolves one fd0 host and refreshes the local
// OpenSSH projection without starting a shell. File-transfer clients use the
// returned argv to request the SFTP subsystem while retaining native
// ProxyJump, Known Hosts, and fd0-agent behavior.
func PrepareOpenSSHConnection(ctx context.Context, scopeID, name string) (OpenSSHConnection, error) {
	if name == "" {
		return OpenSSHConnection{}, errors.New("host alias is required")
	}
	s, err := Open(ctx)
	if errors.Is(err, ErrAgentLocked) {
		return prepareGrantedSSHConnection(scopeID, name)
	}
	if err != nil {
		return OpenSSHConnection{}, err
	}
	defer s.Close()
	hosts, err := loadHosts(s, scopeID)
	if err != nil {
		return OpenSSHConnection{}, err
	}
	host := exactMatch(hosts, name)
	if host == nil {
		prefixed := prefixMatch(hosts, name)
		if len(prefixed) == 1 {
			host = prefixed[0]
		} else if len(prefixed) > 1 {
			return OpenSSHConnection{}, fmt.Errorf("host alias %q is ambiguous", name)
		} else {
			return OpenSSHConnection{}, fmt.Errorf("no fd0 host matches %q", name)
		}
	}
	if err := renderSSHForConnect(s); err != nil {
		return OpenSSHConnection{}, err
	}
	if sshAgentSocketDisabledByEnv() {
		return OpenSSHConnection{}, errors.New("fd0 SSH agent socket is disabled by FD0_SSH_SOCK")
	}
	sshSock := SSHSocketPathForRender()
	if err := checkSSHAgentSocket(sshSock); err != nil {
		return OpenSSHConnection{}, sshAgentSocketUnavailable(sshSock, err)
	}
	configPath, err := sshConnectConfigPath()
	if err != nil {
		return OpenSSHConnection{}, err
	}
	binary, err := exec.LookPath("ssh")
	if err != nil {
		return OpenSSHConnection{}, fmt.Errorf("ssh client not on PATH: %w", err)
	}
	return OpenSSHConnection{
		Alias:      host.Alias,
		ConfigPath: configPath,
		SSHBinary:  binary,
	}, nil
}

// RunSSHConnect dispatches according to the name:
//   - empty            → picker over all hosts
//   - unique match     → exec ssh NAME [cmd...]
//   - prefix collision → picker pre-filtered to the prefix
//
// `extra` is the trailing argv after NAME — passed verbatim to ssh
// (e.g. `fd0 ssh prod-db "uname -a"`).
func RunSSHConnect(ctx context.Context, scopeID, name string, extra []string, anyTags []string) error {
	s, err := Open(ctx)
	if errors.Is(err, ErrAgentLocked) {
		if len(anyTags) > 0 {
			return errors.New("unlock to filter hosts by tags")
		}
		conn, e := prepareGrantedSSHConnection(scopeID, name)
		if e != nil {
			return e
		}
		return execSSH(conn.Alias, extra, conn.ConfigPath)
	}
	if err != nil {
		return err
	}
	hosts, err := loadHosts(s, scopeID)
	if err != nil {
		s.Close()
		return err
	}
	hosts = filterHosts(hosts, anyTags, nil)
	if len(hosts) == 0 {
		s.Close()
		return errors.New("no fd0-managed hosts; create one with `fd0 ssh add`")
	}

	// Fast paths.
	if name != "" {
		exact := exactMatch(hosts, name)
		if exact != nil {
			return renderAndExecSSH(s, exact, extra)
		}
		prefixed := prefixMatch(hosts, name)
		if len(prefixed) == 1 {
			return renderAndExecSSH(s, prefixed[0], extra)
		}
		if len(prefixed) > 1 {
			h, err := pickHost(prefixed)
			if err != nil {
				s.Close()
				return err
			}
			return renderAndExecSSH(s, h, extra)
		}
		// Nothing matched — fall through to picker over the full list
		// so the user sees what IS available.
		stderrln("no host matches %q; opening picker over all hosts", name)
	}

	h, err := pickHost(hosts)
	if err != nil {
		s.Close()
		return err
	}
	return renderAndExecSSH(s, h, extra)
}

// exactMatch looks for a host whose alias equals name (case-sensitive
// — SSH config aliases are case-sensitive).
func exactMatch(hosts []*sshhost.Host, name string) *sshhost.Host {
	for _, h := range hosts {
		if h.Alias == name {
			return h
		}
	}
	return nil
}

// prefixMatch returns every host whose alias starts with name. Used
// for "fd0 ssh prod" → matches prod-db, prod-web → picker.
func prefixMatch(hosts []*sshhost.Host, name string) []*sshhost.Host {
	var out []*sshhost.Host
	for _, h := range hosts {
		if strings.HasPrefix(h.Alias, name) {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// pickHost runs the TUI picker over the given hosts. Re-uses the same
// inline picker the secret-get command uses, with an SSH-shaped row.
func pickHost(hosts []*sshhost.Host) (*sshhost.Host, error) {
	items := make([]tui.PickerItem, len(hosts))
	for i, h := range hosts {
		conn := h.Hostname
		if h.User != "" {
			conn = h.User + "@" + conn
		}
		if h.Port != 0 && h.Port != 22 {
			conn = fmt.Sprintf("%s:%d", conn, h.Port)
		}
		extras := []string{conn}
		if h.ProxyJump != "" {
			extras = append(extras, "jump="+h.ProxyJump)
		}
		if len(h.Tags) > 0 {
			extras = append(extras, "#"+strings.Join(h.Tags, " #"))
		}
		items[i] = tui.PickerItem{
			ID:    h.Alias,
			Label: fmt.Sprintf("%-20s  %s", h.Alias, h.Scope),
			Hint:  strings.Join(extras, " · "),
		}
	}
	res, err := tui.RunPicker("select host", items)
	if err != nil {
		return nil, err
	}
	if res.ID == "" {
		return nil, errors.New("cancelled")
	}
	for _, h := range hosts {
		if h.Alias == res.ID {
			return h, nil
		}
	}
	return nil, errors.New("picker returned unknown alias")
}

func renderAndExecSSH(s *Session, host *sshhost.Host, extra []string) error {
	if err := renderSSHForConnect(s); err != nil {
		s.Close()
		return err
	}
	s.Close()
	if sshAgentSocketDisabledByEnv() {
		return fmt.Errorf("fd0 SSH agent socket is disabled by FD0_SSH_SOCK; unset FD0_SSH_SOCK or set it to a socket path")
	}
	sshSock := SSHSocketPathForRender()
	if err := checkSSHAgentSocket(sshSock); err != nil {
		return sshAgentSocketUnavailable(sshSock, err)
	}
	configPath, err := sshConnectConfigPath()
	if err != nil {
		return err
	}
	return execSSH(host.Alias, extra, configPath)
}

func sshConnectConfigPath() (string, error) {
	fd0Conf := SSHConfPath()
	userCfg := sshhost.DefaultUserConfigPath()
	included, err := sshhost.HasInclude(userCfg, fd0Conf)
	if err != nil {
		return "", err
	}
	if included {
		return "", nil
	}
	path := SSHConnectConfigPath()
	var b strings.Builder
	fmt.Fprintf(&b, "Include %s\n", sshConfigPathLiteral(fd0Conf))
	if _, err := os.Stat(userCfg); err == nil {
		fmt.Fprintf(&b, "Include %s\n", sshConfigPathLiteral(userCfg))
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := writeFileAtomic(path, []byte(b.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func sshConfigPathLiteral(path string) string {
	return `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
}

// execSSH wraps ssh with the host alias and any extra argv. We use
// exec (syscall.Exec) to REPLACE this fd0 process with ssh so signals
// (SIGINT, SIGWINCH) reach ssh directly and the user's terminal
// experience is indistinguishable from `ssh <alias>` typed directly.
//
// Fallback: if syscall.Exec isn't available (unlikely on Unix), fall
// back to running ssh as a subprocess and forwarding its exit code.
func execSSH(alias string, extra []string, configPath string) error {
	args := []string{"ssh"}
	if configPath != "" {
		args = append(args, "-F", configPath)
	}
	args = append(args, alias)
	args = append(args, extra...)
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("ssh client not on PATH: %w", err)
	}
	if err := syscall.Exec(bin, args, os.Environ()); err != nil {
		// Fallback: run as a subprocess and propagate the exit code.
		cmd := exec.Command(bin, args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		runErr := cmd.Run()
		if runErr == nil {
			return nil
		}
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		return runErr
	}
	return nil // unreachable after successful syscall.Exec
}
