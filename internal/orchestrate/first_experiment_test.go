package orchestrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// The first production experiment, pinned: Saymer3 → repair fail2ban.service.
//
// This file proves that the first real Execute is physically restricted to
// exactly one expected action —
//
//	SERVICE → fail2ban.service → restart → expected_state=active → OWNED
//
// — and that nothing else can slip into the plan: the executor registry only
// contains SERVICE, the confirmation fingerprint is bound to the exact plan,
// the staleness gate stays mandatory, and every fail-closed check holds
// before the mutation. The experiment is planning-only here: Execute is
// never run against a real VPS from these tests.

// allActionKinds enumerates every action kind the project can produce, so a
// registry-exhaustion test cannot silently forget one.
var allActionKinds = []state.ActionKind{
	state.ActionCreateFile,
	state.ActionUpdateFile,
	state.ActionDeleteOwnedFile,
	state.ActionFirewall,
	state.ActionRouting,
	state.ActionService,
	state.ActionSSH,
	state.ActionInstaller,
	state.ActionValidate,
	state.ActionReboot,
	state.ActionSSHFinalize,
}

// forbiddenInFirstExperiment lists kinds that must never appear in the
// first production experiment plan: SSH migration, firewall, routing,
// package installation, reboots and file mutations are out of scope.
var forbiddenInFirstExperiment = map[state.ActionKind]bool{
	state.ActionSSH:            true,
	state.ActionSSHFinalize:    true,
	state.ActionFirewall:       true,
	state.ActionRouting:        true,
	state.ActionInstaller:      true,
	state.ActionReboot:         true,
	state.ActionCreateFile:     true,
	state.ActionUpdateFile:     true,
	state.ActionDeleteOwnedFile: true,
}

func loadFirstExperimentScenario(t *testing.T) (discovery.Result, *pipeline.Config) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "first-apply-saymer3.json"))
	if err != nil { t.Fatal(err) }
	var scenario struct {
		Discovery discovery.Result `json:"discovery"`
		ConfigRaw json.RawMessage  `json:"config"`
	}
	if err := json.Unmarshal(raw, &scenario); err != nil { t.Fatal(err) }
	cfg, err := pipeline.ParseConfig(scenario.ConfigRaw)
	if err != nil { t.Fatal(err) }
	return scenario.Discovery, cfg
}

// The experiment registry is deliberately minimal: only the SERVICE kind has
// an executor. Any other kind in the plan is a coverage failure and blocks
// before the first mutation.
func newFirstExperimentOrchestrator(t *testing.T, states []discovery.Result) (Orchestrator, *recordingExecutor, *int) {
	svc := &recordingExecutor{}
	o, calls := newOrchestrator(t, states, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	return o, svc, calls
}

func firstExperimentConfirmation(p Plan) Confirmation {
	return Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
}

// Invariants 1-8: the plan contains exactly one action and that action is
// the fail2ban restart, with the exact typed spec and ownership.
func TestFirstExperimentPlanIsExactlyOneServiceAction(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, _, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())

	if !p.Ready { t.Fatalf("experiment plan must be ready, blockers=%v", p.Blockers) }
	if len(p.Plan.Actions) != 1 { t.Fatalf("want exactly 1 action, got %d: %#v", len(p.Plan.Actions), p.Plan.Actions) }
	a := p.Plan.Actions[0]

	if a.Kind != state.ActionService { t.Fatalf("kind=%s, want SERVICE", a.Kind) }
	if a.Resource != "service.fail2ban.service" { t.Fatalf("resource=%q", a.Resource) }
	if a.Spec == nil || a.Spec.Service == nil { t.Fatalf("missing service spec: %#v", a.Spec) }
	if a.Spec.Service.Name != "fail2ban.service" { t.Fatalf("service name=%q", a.Spec.Service.Name) }
	if a.Spec.Service.Operation != "restart" { t.Fatalf("operation=%q", a.Spec.Service.Operation) }
	if a.Spec.Service.ExpectedState != "active" { t.Fatalf("expected state=%q", a.Spec.Service.ExpectedState) }
	if a.Ownership != state.Owned { t.Fatalf("ownership=%q, want OWNED", a.Ownership) }

	for _, kind := range allActionKinds {
		if forbiddenInFirstExperiment[kind] {
			for _, act := range p.Plan.Actions {
				if act.Kind == kind { t.Fatalf("forbidden action kind %s present in first experiment plan", kind) }
			}
		}
	}
}

// Invariant 9: the experiment registry makes any other action kind
// unexecutable. For every non-SERVICE kind a plan containing it fails the
// executor coverage check.
func TestFirstExperimentRegistryForbidsOtherKinds(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, _, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())

	registered := map[state.ActionKind]bool{state.ActionService: true}
	if missing := state.MissingExecutors(p.Plan, registered); len(missing) != 0 {
		t.Fatalf("the pinned plan must be fully covered by the experiment registry: %v", missing)
	}
	for _, kind := range allActionKinds {
		if kind == state.ActionService { continue }
		probePlan := state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
			{ID: "probe", Resource: "probe.resource", Kind: kind, Ownership: state.Owned},
		}}
		if missing := state.MissingExecutors(probePlan, registered); len(missing) == 0 {
			t.Fatalf("registry must not execute unexpected kind %s", kind)
		}
	}
}

// Invariant 10: the confirmation fingerprint refers to exactly this plan.
// Adding any second action — SSH, firewall or even another service — breaks
// the fingerprint and must be rejected.
func TestFirstExperimentConfirmationBindsExactPlan(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, _, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())
	conf := firstExperimentConfirmation(p)

	if err := o.Confirm(p, conf); err != nil {
		t.Fatalf("confirmation must validate for the exact plan: %v", err)
	}

	extra := []state.Action{
		{ID: "sneaky-ssh", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned},
		{ID: "sneaky-firewall", Resource: "firewall.rule", Kind: state.ActionFirewall, Ownership: state.Owned},
		{ID: "sneaky-service", Resource: "service.other.service", Kind: state.ActionService, Ownership: state.Owned},
	}
	for _, act := range extra {
		mutated := p
		mutated.Plan.Actions = append(append([]state.Action{}, p.Plan.Actions...), act)
		if err := o.Confirm(mutated, conf); err == nil {
			t.Fatalf("confirmation must be rejected for a plan with an extra %s action", act.Kind)
		}
	}
}

// Regression: an attempt to smuggle a second action (SSH or firewall) into
// the first experiment must be rejected before the first mutation — via the
// confirmation fingerprint and, for kinds without an executor, additionally
// via executor coverage.
func TestFirstExperimentSecondActionIsRejected(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, svc, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())
	conf := firstExperimentConfirmation(p)

	for _, tc := range []struct {
		name    string
		action  state.Action
	}{
		{"ssh", state.Action{ID: "sneaky-ssh", Resource: "ssh.port", Kind: state.ActionSSH, Ownership: state.Owned}},
		{"firewall", state.Action{ID: "sneaky-fw", Resource: "firewall.rule", Kind: state.ActionFirewall, Ownership: state.Owned}},
		{"extra-service", state.Action{ID: "sneaky-svc", Resource: "service.other.service", Kind: state.ActionService, Ownership: state.Owned}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := p
			mutated.Plan.Actions = append(append([]state.Action{}, p.Plan.Actions...), tc.action)
			out, err := o.Execute(mutated, conf, nil)
			if err != nil { t.Fatal(err) }
			if out.Stage != StageBlocked {
				t.Fatalf("second action must be rejected, stage=%s blockers=%v", out.Stage, out.Blockers)
			}
			if len(svc.calls) != 0 {
				t.Fatalf("mutation attempted with a smuggled action: %v", svc.calls)
			}
		})
	}
}

// Invariant 11: the staleness gate stays mandatory for the experiment. If
// the machine changes between Prepare and Execute (here: fail2ban already
// active), the plan is stale and the mutation is refused.
func TestFirstExperimentStalePlanStillBlocked(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, svc, calls := newFirstExperimentOrchestrator(t, []discovery.Result{disc, repairDiscoveryForStaleness(t, disc)})
	p := o.Prepare(cfg, rootOn())
	conf := firstExperimentConfirmation(p)

	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked {
		t.Fatalf("stale experiment plan must be blocked, stage=%s blockers=%v", out.Stage, out.Blockers)
	}
	if !strings.Contains(strings.Join(out.Blockers, "; "), "stale") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with stale plan: %v", svc.calls) }
	if *calls != 2 { t.Fatalf("discovery calls=%d, want 2 (prepare + staleness)", *calls) }
}

// repairDiscoveryForStaleness returns the same machine with fail2ban already
// repaired — the drift that must invalidate the prepared plan.
func repairDiscoveryForStaleness(t *testing.T, base discovery.Result) discovery.Result {
	t.Helper()
	drifting := base
	services := make([]discovery.Service, len(base.Services))
	copy(services, base.Services)
	for i := range services {
		if services[i].Name == "fail2ban.service" {
			services[i].Active = true
			services[i].SubState = "running"
		}
	}
	drifting.Services = services
	return drifting
}

// Invariant 12: the existing fail-closed checks remain in force for the
// experiment — a plan without confirmation or with an unknown-ownership
// variant is refused before any mutation.
func TestFirstExperimentFailClosedChain(t *testing.T) {
	disc, cfg := loadFirstExperimentScenario(t)
	o, svc, _ := newFirstExperimentOrchestrator(t, []discovery.Result{disc})
	p := o.Prepare(cfg, rootOn())

	// Without confirmation.
	out, err := o.Execute(p, Confirmation{}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked || len(svc.calls) != 0 {
		t.Fatalf("no-confirmation run must block: stage=%s calls=%v", out.Stage, svc.calls)
	}

	// With UNKNOWN ownership (config without the ownership declaration).
	noOwned := *cfg
	noOwned.Ownership = nil
	p2 := o.Prepare(&noOwned, rootOn())
	if p2.Ready || !p2.Plan.Blocked {
		t.Fatalf("UNKNOWN ownership must block the experiment plan: ready=%v blocked=%v", p2.Ready, p2.Plan.Blocked)
	}
	p2.Ready = true
	conf2 := Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "op", At: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)}
	out2, err := o.Execute(p2, conf2, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageBlocked || len(svc.calls) != 0 {
		t.Fatalf("UNKNOWN ownership run must block: stage=%s calls=%v", out2.Stage, svc.calls)
	}
}
