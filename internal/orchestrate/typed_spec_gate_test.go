package orchestrate

import (
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// A hand-built mutating action without a typed spec must be blocked by the
// Execute structural re-check, regardless of the caller's Ready claim — it
// must never reach the executor registry (TASK-31/43).
func TestExecuteBlocksHandBuiltSpeclessMutation(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, nil, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := Plan{
		Ready:     true,
		Preflight: readyPreflight(),
		Plan: state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
			// Deliberately specless: the exact defect the typed-spec
			// invariant exists to stop.
			{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned},
		}},
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("specless mutating plan must be blocked, got stage=%s", out.Stage)
	}
	joined := strings.Join(out.Blockers, "; ")
	if !strings.Contains(joined, "typed-spec invariant") || !strings.Contains(joined, "requires a service spec") {
		t.Fatalf("blockers must name the typed-spec violation: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("executor must not be reached: %v", svc.calls)
	}
}

// A valid prepared experiment-shape plan keeps satisfying the invariant
// (positive control: the gate does not reject sanctioned plans).
func TestPreparedExperimentPlanSatisfiesTypedSpecInvariant(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("plan not ready: %v", p.Blockers)
	}
	if err := state.ValidatePlanTypedSpecs(p.Plan); err != nil {
		t.Fatalf("prepared plan must satisfy the typed-spec invariant: %v", err)
	}
}
