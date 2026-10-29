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
	if !strings.Contains(out.String(), "NO_CHANGE") || !strings.Contains(out.String(), "already matches") {
		t.Fatalf("the converged outcome must be named explicitly:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "no plan actions were produced") {
		t.Fatalf("the zero-action fact must be stated:\n%s", out.String())
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
