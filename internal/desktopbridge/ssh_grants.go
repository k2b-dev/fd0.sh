package desktopbridge

import (
	"context"
	"strings"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
)

type SSHGrantParams struct {
	Action     string `json:"action"`
	ScopeID    string `json:"scopeId"`
	Name       string `json:"name"`
	ID         string `json:"id"`
	Digest     string `json:"digest"`
	Method     string `json:"method"`
	Passphrase []byte `json:"passphrase"`
	PIN        []byte `json:"pin"`
}

func (s *Service) sshGrant(ctx context.Context, p SSHGrantParams) (*agent.SSHGrantResp, error) {
	defer crypto.Wipe(p.Passphrase)
	defer crypto.Wipe(p.PIN)
	r := agent.SSHGrantReq{Action: p.Action, ScopeID: p.ScopeID, Name: strings.TrimPrefix(p.Name, "host:"), ID: p.ID, Digest: p.Digest}
	if p.Action == "create" {
		paths, err := fdhome.Resolve()
		if err != nil {
			return nil, err
		}
		methods, err := cli.LoadGrantAuthMethods(paths)
		if err != nil {
			return nil, mapDomainError(err)
		}
		method, err := selectAuthMethod(paths, methods, p.Method)
		if err != nil {
			return nil, err
		}
		credential, err := authenticationCredential(*method, p.Passphrase, p.PIN)
		if err != nil {
			return nil, err
		}
		r.Authentication = &agent.UnlockReq{MethodType: method.MethodType, Passphrase: credential.Passphrase, YubikeyPIN: credential.YubikeyPIN}
	}
	result, err := cli.ManageSSHGrant(ctx, r)
	if err != nil {
		return nil, mapDomainError(err)
	}
	return result, nil
}
