package orchestrate

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// preflightCheckExecutor is a recording executor that also implements the
// optional PreflightChecker with an injectable failure, so the orchestrator's
// executor-preflight integration can be tested end to end.
type preflightCheckExecutor struct {
	recordingExecutor
	checkErr   error
	checkCalls int
}

func (e *preflightCheckExecutor) PreflightCheck(a state.Action) error {
	e.checkCalls++
	return e.checkErr
}

// Scenario: the service configuration is invalid on the live machine (the
// real Saymer3 case: duplicate [sshd] section in jail.local). Prepare must
// surface the executor preflight failure and mark the plan not ready — the
// operator is never asked to confirm a doomed plan.
func TestPrepareBlocksOnExecutorPreflightFailure(t *testing.T) {
	px := &preflightCheckExecutor{checkErr: errors.New("fail2ban-client -t: duplicate section [sshd]")}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: px},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if p.Ready {
		t.Fatal("invalid service configuration must make the plan not ready")
	}
	if p.Preflight.Status != state.PreflightBlocked {
		t.Fatalf("preflight=%s", p.Preflight.Status)
	}
	found := false
	for _, b := range p.Blockers {
		if strings.Contains(b, "executor preflight") && strings.Contains(b, "duplicate section [sshd]") {
			found = true
		}
	}
	if !found {
		t.Fatalf("preflight blocker missing: %v", p.Blockers)
	}
	// The check itself is read-only: no mutating executor method ran.
	if len(px.calls) != 0 {
		t.Fatalf("mutation methods invoked: %v", px.calls)
	}
	if px.checkCalls != 1 {
		t.Fatalf("checkCalls=%d", px.checkCalls)
	}
}

// Scenario: the configuration breaks between Prepare and Execute. The
// executor preflight re-runs under the lock and blocks the mutation before
// the Engine is reached.
func TestExecuteBlocksOnExecutorPreflightFailureBeforeMutation(t *testing.T) {
	px := &preflightCheckExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: px},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}

	px.checkErr = errors.New("config broke after planning")
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	if len(px.recordingExecutor.calls) != 0 {
		t.Fatalf("mutation attempted despite executor preflight failure: %v", px.recordingExecutor.calls)
	}
	if px.checkCalls != 2 {
		t.Fatalf("checkCalls=%d, want 2 (prepare + execute)", px.checkCalls)
	}
}

// The happy path is unchanged when the executor preflight passes.
func TestExecuteProceedsWhenExecutorPreflightPasses(t *testing.T) {
	px := &preflightCheckExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: px},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers)
	}
	if px.checkCalls != 2 {
		t.Fatalf("checkCalls=%d, want 2 (prepare + execute)", px.checkCalls)
	}
}
