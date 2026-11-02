package orchestrate

// Stage 4/B orchestration wiring tests (ZAI-132): the derived capability
// set is part of the plan identity, is folded in by Prepare, is re-checked
// exact-set before confirmation, and participates in the staleness gate.
// Synthetic fixtures only (the package's existing helpers).

import (
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

const stage4PinnedCapability = capability.CapabilityID("muvg.service.restart.v1;unit=fail2ban.service")

// The prepared plan carries the derived capability set, and the capability
// set is part of the plan identity: the fingerprint of a plan without the
// folded set differs from the fingerprint of the prepared plan, while a
// legacy orchestrator (nil deriver) produces exactly the pre-Stage-4
// fingerprint (compatibility pinned).
func TestStage4PrepareFoldsCapabilitiesIntoPlanIdentity(t *testing.T) {
	states := []discovery.Result{makeDiscovery(false)}
	o, _ := newOrchestrator(t, states, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	p := o.Prepare(fail2banConfig(), rootOn())

	if got, want := p.Plan.Capabilities, []string{string(stage4PinnedCapability)}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("prepared plan must carry the derived set, got %v", got)
	}
	withCapabilities := Fingerprint(p.Plan)
	stripped := p.Plan
	stripped.Capabilities = nil
	if Fingerprint(stripped) == withCapabilities {
		t.Fatal("the capability set must change the plan fingerprint (identity binding)")
	}

	// Compatibility: a legacy orchestrator (nil deriver) folds nothing and
	// fingerprints exactly like the pre-Stage-4 plan.
	legacy, _ := newOrchestrator(t, states, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	lp := legacy.Prepare(fail2banConfig(), rootOn())
	if len(lp.Plan.Capabilities) != 0 {
		t.Fatalf("nil deriver must leave capabilities empty, got %v", lp.Plan.Capabilities)
	}
	if Fingerprint(lp.Plan) != Fingerprint(stripped) {
		t.Fatal("nil-deriver fingerprints must be byte-identical to the pre-Stage-4 encoding")
	}
}

// NO_CHANGE: a converged input derives an empty set — the plan carries no
// capabilities and the fingerprint equals the pre-Stage-4 encoding.
func TestStage4NoChangeCarriesNoCapabilities(t *testing.T) {
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	p := o.Prepare(fail2banConfig(), rootOn())
	if len(p.Plan.Actions) != 0 {
		t.Fatalf("a converged input must produce no actions, got %d", len(p.Plan.Actions))
	}
	if len(p.Plan.Capabilities) != 0 {
		t.Fatalf("a NO_CHANGE plan must carry no capabilities, got %v", p.Plan.Capabilities)
	}
}

func stage4PreparedPlan(t *testing.T) (Orchestrator, Plan, *recordingExecutor) {
	t.Helper()
	svc := &recordingExecutor{}
	// Discovery sequence: inactive at prepare, inactive under the
	// staleness gate, active after the sanctioned restart (the same
	// pattern the existing end-to-end orchestration tests use).
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("fixture plan must be ready, blockers: %v", p.Blockers)
	}
	return o, p, svc
}

// Missing capability: a carried set WITHOUT the derived requirement is an
// authorization mismatch, blocked before confirmation and before any
// executor call (the deliberately wrong confirmation proves the ordering).
func TestStage4ExecuteBlocksMissingCapability(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	p.Plan.Capabilities = nil
	conf := Confirmation{ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	joined := strings.Join(out.Blockers, "; ")
	if !strings.Contains(joined, "do not match the derived requirements") || !strings.Contains(joined, string(stage4PinnedCapability)) {
		t.Fatalf("the missing-capability mismatch must be named: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("no executor call may happen on a refused plan: %v", svc.calls)
	}
}

// Extra capability: over-granting is itself an authorization mismatch
// (exact-set discipline) — an added capability blocks the mutation.
func TestStage4ExecuteBlocksExtraCapability(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	p.Plan.Capabilities = append(p.Plan.Capabilities, "muvg.projectfile.v1")
	conf := Confirmation{ApprovedBy: "operator", At: time.Now().UTC()}
	out, _ := o.Execute(p, conf, nil)
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	joined := strings.Join(out.Blockers, "; ")
	if !strings.Contains(joined, "unexpected") || !strings.Contains(joined, "muvg.projectfile.v1") {
		t.Fatalf("the over-grant must be named as unexpected authority: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("no executor call may happen on a refused plan: %v", svc.calls)
	}
}

// Replaced capability: swapping the pinned service authority for an
// unrelated capability class (even a structurally valid one) is a mismatch.
func TestStage4ExecuteBlocksReplacedCapability(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	p.Plan.Capabilities = []string{"muvg.sysctl.apply.v1;keys=net.ipv4.ip_forward"}
	conf := Confirmation{ApprovedBy: "operator", At: time.Now().UTC()}
	out, _ := o.Execute(p, conf, nil)
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("no executor call may happen on a refused plan: %v", svc.calls)
	}
}

// Malformed capability injection: a carried string that is not a canonical
// capability fails closed structurally, before the exact-set comparison.
func TestStage4ExecuteBlocksMalformedCapabilityInjection(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	p.Plan.Capabilities = []string{"not-a-capability"}
	conf := Confirmation{ApprovedBy: "operator", At: time.Now().UTC()}
	out, _ := o.Execute(p, conf, nil)
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	if !strings.Contains(strings.Join(out.Blockers, "; "), "malformed capability set") {
		t.Fatalf("the malformed injection must be named: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("no executor call may happen on a refused plan: %v", svc.calls)
	}
}

// Operation mismatch: an action whose typed spec was altered after
// preparation derives a DIFFERENT requirement than the carried set — the
// exact-set check refuses (the capability is bound to the concrete
// operation, not to the plan loosely).
func TestStage4ExecuteBlocksOperationMismatch(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	// Tamper the operation after derivation: the carried capability still
	// says restart-of-fail2ban, but the plan now asks for a different
	// operation — the derivation of the tampered plan fails closed (the
	// Stage-1 bound refuses stop) and the mutation blocks.
	p.Plan.Actions[0].Spec.Service.Operation = "stop"
	conf := Confirmation{ApprovedBy: "operator", At: time.Now().UTC()}
	out, _ := o.Execute(p, conf, nil)
	if out.Stage != StageBlocked {
		t.Fatalf("stage=%s", out.Stage)
	}
	if !strings.Contains(strings.Join(out.Blockers, "; "), "capability derivation") {
		t.Fatalf("the tampered operation must fail capability derivation: %v", out.Blockers)
	}
	if len(svc.calls) != 0 {
		t.Fatalf("no executor call may happen on a refused plan: %v", svc.calls)
	}
}

// Changed-plan invalidation: a confirmation issued for the derived plan is
// refused for ANY other plan identity — in particular for a plan whose
// capability set differs. The capability set is inside the fingerprint
// coverage, so "operator approved plan F" can never be reinterpreted as
// approval of a different authority set.
func TestStage4CapabilityChangeInvalidatesConfirmation(t *testing.T) {
	o, p, _ := stage4PreparedPlan(t)
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	if err := o.Confirm(p, conf); err != nil {
		t.Fatalf("the exact-plan confirmation must hold: %v", err)
	}
	// Same actions, different capability set → different plan identity.
	other := p
	other.Plan.Capabilities = []string{"muvg.projectfile.v1"}
	if err := o.Confirm(other, conf); err == nil {
		t.Fatal("a confirmation for one capability set must be refused for another")
	}
}

// Positive control: the pinned experiment flow works end to end with the
// deriver wired — the capability wiring adds the identity binding without
// false-blocking the sanctioned path.
func TestStage4PinnedExperimentFlowWorksWithDeriver(t *testing.T) {
	o, p, svc := stage4PreparedPlan(t)
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s error=%v blockers=%v", out.Stage, out.Transaction.Error, out.Blockers)
	}
	found := false
	for _, call := range svc.calls {
		if call == "apply:service.fail2ban.service" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the sanctioned restart must have been applied: %v", svc.calls)
	}
}

// Unknown action class: a plan carrying a mutating action kind with no
// compiled derivation BLOCKS at Prepare (fail-closed), instead of
// producing an unauthorized plan.
func TestStage4DerivationFailureBlocksPlanAtPrepare(t *testing.T) {
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	const fileResource = "file./etc/vps-gateway/experiment-file-test.conf"
	cfg := fail2banConfig()
	cfg.Desired.Files = []state.FileDesired{{Path: "/etc/vps-gateway/experiment-file-test.conf", Content: "x", Mode: 0600}}
	cfg.Ownership[fileResource] = state.Owned
	p := o.Prepare(cfg, rootOn())
	if !p.Plan.Blocked {
		t.Fatal("a plan whose requirements cannot be derived must be blocked")
	}
	joined := strings.Join(p.Plan.BlockReasons, "; ")
	if !strings.Contains(joined, "capability derivation") || !strings.Contains(joined, "no compiled capability derivation") {
		t.Fatalf("the derivation failure must be named: %v", joined)
	}
	// And the blocked plan carries no capabilities.
	if len(p.Plan.Capabilities) != 0 {
		t.Fatalf("a blocked plan must not carry capabilities: %v", p.Plan.Capabilities)
	}
}

// Capability injection through config/state is structurally impossible:
// the planner (BuildPlan, pipeline.Assemble) never sets Capabilities — the
// ONLY writer is the orchestrator's configured compiled deriver. Pinned at
// the state layer.
func TestStage4PlannerNeverSetsCapabilities(t *testing.T) {
	m := state.Model{}
	p := state.BuildPlan(m)
	if len(p.Capabilities) != 0 {
		t.Fatalf("BuildPlan must never set capabilities, got %v", p.Capabilities)
	}
}
