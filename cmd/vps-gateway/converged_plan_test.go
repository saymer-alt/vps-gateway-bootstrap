package main

// ZAI-124 addendum: the first-transaction cold start against the REAL
// experiment shape — both directions of the fail2ban state.
//
// Live finding (ZAI-123 on Saymer3): the pinned experiment is a
// CONVERGENCE plan — firstExperimentConfig desires fail2ban.service
// active, so a healthy service yields a plan with ZERO actions and the
// experiment guard refuses ("experiment allows exactly one action, plan
// has 0"). These tests pin both outcomes: the converged dry-run reports
// NO_CHANGE explicitly (an informational result, not a failed
// operation), while the mutation path keeps the guard refusal intact.
// Nothing here stops, disables or breaks the real service on any host —
// all fixtures are synthetic discovery states.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// convergedProbe counts executor and observer consultations (the
// observer cannot legitimately be consulted: observation lives inside
// Execute, which the guard refusal never reaches — the counters prove it).
type convergedProbe struct {
	executorCalls int
	observerCalls int
}

type convergedCountingExecutor struct {
	probe *convergedProbe
}

func (e *convergedCountingExecutor) Backup(id, resource string) error {
	e.probe.executorCalls++
	return nil
}
func (e *convergedCountingExecutor) Apply(id, resource, kind string) error {
	e.probe.executorCalls++
	return nil
}
func (e *convergedCountingExecutor) Validate(id, resource string) error {
	e.probe.executorCalls++
	return nil
}
func (e *convergedCountingExecutor) Rollback(id, resource string) error {
	e.probe.executorCalls++
	return nil
}

// healthyFail2banDiscovery is ZAI-123's live shape: the desired state
// already matches, so the planner produces ZERO actions.
func healthyFail2banDiscovery(t *testing.T) discovery.Result {
	return repairedSaymer3Discovery(t)
}

func convergedTestOrchestrator(t *testing.T) (*orchestrate.Orchestrator, *convergedProbe) {
	t.Helper()
	probe := &convergedProbe{}
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		healthyFail2banDiscovery(t), healthyFail2banDiscovery(t), healthyFail2banDiscovery(t),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &convergedCountingExecutor{probe: probe}},
	})
	o.ObserveService = func(ctx context.Context, unit string) (serviceobs.Observation, error) {
		probe.observerCalls++
		return serviceobs.Observation{}, nil
	}
	return o, probe
}

// The dry-run on a converged (zero-action) plan is an informational
// NO_CHANGE: exit 0, the converged outcome named explicitly, the guard
// refusal not presented as an operation failure, and zero executor or
// observer calls.
func TestApplyDryRunConvergedPlanReportsNoChange(t *testing.T) {
	o, probe := convergedTestOrchestrator(t)
	var out strings.Builder
	code := runApplyWith([]string{"--dry-run", "--observe-service-report", "--config", experimentConfig(t)}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("a converged dry-run must succeed as NO_CHANGE, code=%d output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "NO_CHANGE") || !strings.Contains(out.String(), "verifiably reached") {
		t.Fatalf("the converged outcome must be named explicitly:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no plan actions were produced") || !strings.Contains(out.String(), "explicitly desired active under OWNED ownership") || !strings.Contains(out.String(), "model diff is NO_CHANGE") {
		t.Fatalf("the zero-action and verification facts must be stated:\n%s", out.String())
	}
	if strings.Contains(out.String(), "apply restricted to the first production experiment") {
		t.Fatal("a converged dry-run must not be presented as a guard failure")
	}
	if !strings.Contains(out.String(), "service observation skipped") {
		t.Fatalf("the observation skip must be stated:\n%s", out.String())
	}
	if probe.executorCalls != 0 || probe.observerCalls != 0 {
		t.Fatalf("a converged plan must touch nothing: executor=%d observer=%d", probe.executorCalls, probe.observerCalls)
	}
}

// A zero-action plan from an EMPTY/unrelated configuration is NOT a
// converged NO_CHANGE: the experiment goal is not verifiably reached
// (fail2ban absent from discovery), so the guard refusal stands even on
// the dry-run path. Fails-first: the pre-review code reported NO_CHANGE
// for every zero-action plan.
func TestApplyDryRunZeroPlanWithoutGoalIsNotNoChange(t *testing.T) {
	empty := writeApplyConfig(t, map[string]any{"desired": map[string]any{}})
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}},
	})
	var out strings.Builder
	code := runApplyWith([]string{"--dry-run", "--config", empty}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 3 {
		t.Fatalf("a zero-action plan without the verified goal must not be NO_CHANGE, code=%d output:\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "NO_CHANGE") {
		t.Fatal("an unrelated zero-action plan must not be reported as NO_CHANGE")
	}
	if !strings.Contains(out.String(), "apply restricted to the first production experiment") {
		t.Fatalf("the guard refusal must stand:\n%s", out.String())
	}
}

// ZAI-127 correction, required case 2: a COMPLETELY EMPTY user config
// ({}) must not receive a false NO_CHANGE success — nothing is desired,
// so nothing is converged.
func TestApplyDryRunEmptyUserConfigIsNotNoChange(t *testing.T) {
	empty := writeApplyConfig(t, map[string]any{})
	o, probe := convergedTestOrchestrator(t)
	var out strings.Builder
	code := runApplyWith([]string{"--dry-run", "--observe-service-report", "--config", empty}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 3 {
		t.Fatalf("an empty configuration must not be a NO_CHANGE success, code=%d output:\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "NO_CHANGE") {
		t.Fatal("an empty configuration must not be reported as NO_CHANGE")
	}
	if probe.executorCalls != 0 || probe.observerCalls != 0 {
		t.Fatalf("nothing may execute for an empty config: executor=%d observer=%d", probe.executorCalls, probe.observerCalls)
	}
}

// ZAI-127 correction, required case 3: the REAL apply path (no
// --dry-run) keeps the pre-existing prohibition for a converged plan —
// the guard refusal with exit 3, no execution, no state written.
func TestApplyRealApplyConvergedPlanStillForbidden(t *testing.T) {
	o, probe := convergedTestOrchestrator(t)
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)
	var out strings.Builder
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix, "--observe-service-report"}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 3 {
		t.Fatalf("the real apply of a converged plan must stay forbidden, code=%d output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "apply restricted to the first production experiment") {
		t.Fatalf("the guard refusal must be the outcome:\n%s", out.String())
	}
	if probe.executorCalls != 0 || probe.observerCalls != 0 {
		t.Fatalf("a refused apply must touch nothing: executor=%d observer=%d", probe.executorCalls, probe.observerCalls)
	}
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) {
		t.Fatalf("no state may be written by a refused apply: %v", err)
	}
}

// The mutation path keeps the guard intact: without --dry-run a
// converged plan is still refused before confirmation can matter.
func TestApplyConvergedPlanStillRefusedWithoutDryRun(t *testing.T) {
	o, probe := convergedTestOrchestrator(t)
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)
	var out strings.Builder
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 3 {
		t.Fatalf("the non-dry-run path must keep the guard refusal, code=%d output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "apply restricted to the first production experiment") {
		t.Fatalf("the guard refusal must remain on the mutation path:\n%s", out.String())
	}
	if probe.executorCalls != 0 || probe.observerCalls != 0 {
		t.Fatalf("a refused run must touch nothing: executor=%d observer=%d", probe.executorCalls, probe.observerCalls)
	}
}
