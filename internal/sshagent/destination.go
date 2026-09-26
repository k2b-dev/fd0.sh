package sshagent

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Destination is used only for keys retained across vault lock. Unrestricted
// keys have a nil Destinations slice; an empty non-nil slice permits nothing.
type Destination struct {
	User     string
	HostKeys [][]byte
}

type sessionBinding struct {
	hostKey   []byte
	sessionID []byte
}

// Extension implements OpenSSH session binding for direct, local clients.
// Forwarded-agent access is deliberately unavailable for retained grants.
func (a *fd0Agent) Extension(name string, contents []byte) ([]byte, error) {
	if name != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Never recover a poisoned/rebound connection by sending another extension.
	if a.bindingAttempted {
		a.binding = nil
		return nil, errors.New("SSH session already bound")
	}
	a.bindingAttempted = true
	var req struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if len(contents) > 64*1024 || ssh.Unmarshal(contents, &req) != nil || req.Forwarding || len(req.SessionID) == 0 || len(req.SessionID) > 128 {
		return nil, errors.New("unsupported SSH session binding")
	}
	pub, err := ssh.ParsePublicKey(req.HostKey)
	if err != nil {
		return nil, errors.New("invalid SSH host key")
	}
	var sig ssh.Signature
	if ssh.Unmarshal(req.Signature, &sig) != nil || pub.Verify(req.SessionID, &sig) != nil {
		return nil, errors.New("invalid SSH session proof")
	}
	a.binding = &sessionBinding{hostKey: append([]byte(nil), req.HostKey...), sessionID: append([]byte(nil), req.SessionID...)}
	return []byte{6}, nil // SSH_AGENT_SUCCESS
}

func (a *fd0Agent) allows(destinations []Destination, public ssh.PublicKey, data []byte) bool {
	if destinations == nil {
		return true
	}
	if a.binding == nil {
		return false
	}
	// Host-bound authentication prevents a malicious server from borrowing a
	// session proof for another host. Generic signing and old clients fail closed.
	var req struct {
		SessionID    []byte
		Message      byte
		User         string
		Service      string
		Method       string
		HasSignature bool
		Algorithm    string
		PublicKey    []byte
		HostKey      []byte
	}
	if ssh.Unmarshal(data, &req) != nil || req.Message != 50 || req.Service != "ssh-connection" || req.Method != "publickey-hostbound-v00@openssh.com" || !req.HasSignature || !bytes.Equal(req.SessionID, a.binding.sessionID) || !bytes.Equal(req.HostKey, a.binding.hostKey) || !bytes.Equal(req.PublicKey, public.Marshal()) {
		return false
	}
	for _, d := range destinations {
		if d.User == req.User {
			for _, k := range d.HostKeys {
				if bytes.Equal(k, req.HostKey) {
					return true
				}
			}
		}
	}
	return false
}
