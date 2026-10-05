package desktopbridge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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

// Deploys run as background jobs: the bridge serves one request at a time,
// so a deploy that takes minutes must not block status polling.
type deployJob struct {
	mu       sync.Mutex
	done     bool
	finished time.Time
	results  []recipe.Result
	err      string
}

type RecipeDeployStarted struct {
	JobID string `json:"jobId"`
}

type RecipeDeployStatus struct {
	Done    bool            `json:"done"`
	Results []recipe.Result `json:"results"`
	Error   string          `json:"error,omitempty"`
}

var (
	deployJobsMu sync.Mutex
	deployJobs   = map[string]*deployJob{}
	deployJobSeq int
	// deployCtx ends running deploys when the bridge shuts down, so recipe
	// commands do not outlive it and the device's deploy lock stays honest.
	deployCtx, cancelDeploys = context.WithCancel(context.Background())
	deployWG                 sync.WaitGroup
)

const maxDeployJobs = 32

// StopDeploys cancels running deploys and waits up to timeout for them to
// record the result of the target they were running.
func StopDeploys(timeout time.Duration) {
	cancelDeploys()
	done := make(chan struct{})
	go func() { deployWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// recipeDeploy starts a deploy and returns at once. A failed command is a
// result, not a bridge error, so Desktop can show it in place.
func (s *Service) recipeDeploy(_ context.Context, p RecipeDeployParams) (RecipeDeployStarted, error) {
	if s.Mode == "isolated" {
		return RecipeDeployStarted{}, fail("sync_disabled", "Deploys sync first, which is disabled for the isolated development vault.", "Use a dedicated test server to try deploys.", false)
	}
	if p.ScopeID == "" || p.Name == "" {
		return RecipeDeployStarted{}, fail("validation", "Choose a recipe to deploy.", "", false)
	}
	job := &deployJob{results: []recipe.Result{}}
	deployJobsMu.Lock()
	// Forget finished jobs nobody collected after ten minutes.
	for id, old := range deployJobs {
		old.mu.Lock()
		stale := old.done && time.Since(old.finished) > 10*time.Minute
		old.mu.Unlock()
		if stale {
			delete(deployJobs, id)
		}
	}
	if len(deployJobs) >= maxDeployJobs {
		deployJobsMu.Unlock()
		return RecipeDeployStarted{}, fail("busy", "Too many deploys are pending.", "Wait for running deploys to finish.", true)
	}
	deployJobSeq++
	id := "deploy-" + strconv.Itoa(deployJobSeq)
	deployJobs[id] = job
	deployJobsMu.Unlock()
	deployWG.Add(1)
	go func() {
		defer deployWG.Done()
		// Not the request context: the deploy outlives this request.
		err := cli.RunServiceDeploy(deployCtx, cli.DeployOpts{
			Scope: p.ScopeID, Name: p.Name, Target: p.Target,
			Env: []string{"PATH=" + userShellPath()},
			OnResult: func(r recipe.Result) {
				job.mu.Lock()
				job.results = append(job.results, r)
				job.mu.Unlock()
			},
		})
		job.mu.Lock()
		if err != nil {
			job.err = deployErrorText(err)
		}
		job.done, job.finished = true, time.Now()
		job.mu.Unlock()
	}()
	return RecipeDeployStarted{JobID: id}, nil
}

func (s *Service) recipeDeployStatus(p RecipeDeployStarted) (RecipeDeployStatus, error) {
	deployJobsMu.Lock()
	job, ok := deployJobs[p.JobID]
	deployJobsMu.Unlock()
	if !ok {
		return RecipeDeployStatus{}, fail("not_found", "That deploy is no longer known.", "", false)
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	out := RecipeDeployStatus{Done: job.done, Results: append([]recipe.Result(nil), job.results...), Error: job.err}
	if job.done {
		deployJobsMu.Lock()
		delete(deployJobs, p.JobID)
		deployJobsMu.Unlock()
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
		// A startup script may print a lot or leave a child holding stdout:
		// cap the capture and stop waiting shortly after the shell exits.
		stdout := &cappedBuffer{limit: 64 << 10}
		cmd.Stdout = stdout
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil {
			return
		}
		for _, line := range strings.Split(stdout.buf.String(), "\n") {
			if value, ok := strings.CutPrefix(line, marker); ok && value != "" {
				shellPath = value
			}
		}
	})
	return shellPath
}

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// deployErrorText keeps the mapped, user-facing message for operational
// failures (locked vault, busy device, sync errors).
func deployErrorText(err error) string {
	var me *methodError
	if errors.As(mapDomainError(err), &me) && me.bridge.Message != "" {
		if me.bridge.Action != "" {
			return me.bridge.Message + " " + me.bridge.Action
		}
		return me.bridge.Message
	}
	return err.Error()
}
