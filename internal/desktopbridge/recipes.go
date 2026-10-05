package desktopbridge

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/agent"
	"github.com/valentinkolb/fd0.sh/internal/cli"
	"github.com/valentinkolb/fd0.sh/internal/crypto"
	"github.com/valentinkolb/fd0.sh/internal/fdhome"
	"github.com/valentinkolb/fd0.sh/internal/recipe"
)

// Deploy recipes in Desktop (docs/SERVICES_PLAN.md, phase 3): Desktop shows a
// service's recipes, approves them with fresh authentication and runs them.
// Creating and editing recipes stays in the CLI.

type RecipeListParams struct {
	ScopeID string `json:"scopeId"`
	Service string `json:"service"`
}

type RecipeListResult struct {
	Recipes []cli.RecipeView `json:"recipes"`
}

type RecipeApproveParams struct {
	ScopeID    string `json:"scopeId"`
	Name       string `json:"name"`
	Digest     string `json:"digest"`
	Method     string `json:"method"`
	Passphrase []byte `json:"passphrase"`
	PIN        []byte `json:"pin"`
}

type RecipeDeployParams struct {
	ScopeID string `json:"scopeId"`
	Name    string `json:"name"` // SERVICE or SERVICE/NAME
	Target  string `json:"target"`
}

type RecipeDeployResult struct {
	Results []recipe.Result `json:"results"`
	Error   string          `json:"error,omitempty"`
}

func (s *Service) recipeList(ctx context.Context, p RecipeListParams) (RecipeListResult, error) {
	if p.ScopeID == "" || p.Service == "" {
		return RecipeListResult{}, fail("validation", "Choose a service.", "", false)
	}
	views, err := cli.ServiceRecipes(ctx, p.ScopeID, p.Service)
	if err != nil {
		return RecipeListResult{}, mapDomainError(err)
	}
	return RecipeListResult{Recipes: views}, nil
}

func (s *Service) recipeApprove(ctx context.Context, p RecipeApproveParams) (RecipeListResult, error) {
	defer crypto.Wipe(p.Passphrase)
	defer crypto.Wipe(p.PIN)
	serviceName, _, err := recipe.SplitName(p.Name)
	if err != nil || p.ScopeID == "" || p.Digest == "" {
		return RecipeListResult{}, fail("validation", "Review the recipe again before approving it.", "", false)
	}
	paths, err := fdhome.Resolve()
	if err != nil {
		return RecipeListResult{}, err
	}
	methods, err := cli.LoadGrantAuthMethods(paths)
	if err != nil {
		return RecipeListResult{}, mapDomainError(err)
	}
	method, err := selectAuthMethod(paths, methods, p.Method)
	if err != nil {
		return RecipeListResult{}, err
	}
	credential, err := authenticationCredential(*method, p.Passphrase, p.PIN)
	if err != nil {
		return RecipeListResult{}, err
	}
	auth := &agent.UnlockReq{MethodType: method.MethodType, Passphrase: credential.Passphrase, YubikeyPIN: credential.YubikeyPIN}
	if err := cli.ApproveRecipe(ctx, p.ScopeID, p.Name, p.Digest, auth); err != nil {
		return RecipeListResult{}, mapDomainError(err)
	}
	return s.recipeList(ctx, RecipeListParams{ScopeID: p.ScopeID, Service: serviceName})
}

// recipeDeploy runs a deploy and returns each target's result. A failed
// command is a result, not a bridge error, so Desktop can show it in place.
func (s *Service) recipeDeploy(ctx context.Context, p RecipeDeployParams) (RecipeDeployResult, error) {
	if s.Mode == "isolated" {
		return RecipeDeployResult{}, fail("sync_disabled", "Deploys sync first, which is disabled for the isolated development vault.", "Use a dedicated test server to try deploys.", false)
	}
	if p.ScopeID == "" || p.Name == "" {
		return RecipeDeployResult{}, fail("validation", "Choose a recipe to deploy.", "", false)
	}
	var mu sync.Mutex
	out := RecipeDeployResult{Results: []recipe.Result{}}
	err := cli.RunServiceDeploy(ctx, cli.DeployOpts{
		Scope: p.ScopeID, Name: p.Name, Target: p.Target,
		Env: []string{"PATH=" + userShellPath()},
		OnResult: func(r recipe.Result) {
			mu.Lock()
			out.Results = append(out.Results, r)
			mu.Unlock()
		},
	})
	if err != nil {
		if len(out.Results) == 0 {
			return RecipeDeployResult{}, mapDomainError(err)
		}
		out.Error = err.Error()
	}
	return out, nil
}

var (
	shellPathOnce sync.Once
	shellPath     string
)

// userShellPath is the PATH of the user's login shell. Desktop apps started
// from the Dock or a launcher get a minimal PATH, so tools a recipe calls
// (kubectl, fd0, a tunnel helper) would otherwise not be found.
func userShellPath() string {
	shellPathOnce.Do(func() {
		shellPath = os.Getenv("PATH")
		shell := os.Getenv("SHELL")
		if shell == "" || !filepath.IsAbs(shell) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		const marker = "__FD0_PATH__="
		cmd := exec.CommandContext(ctx, shell, "-l", "-c", `printf '\n`+marker+`%s\n' "$PATH"`)
		cmd.Stdin = nil
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		if cmd.Run() != nil {
			return
		}
		for _, line := range strings.Split(stdout.String(), "\n") {
			if value, ok := strings.CutPrefix(line, marker); ok && value != "" {
				shellPath = value
			}
		}
	})
	return shellPath
}
