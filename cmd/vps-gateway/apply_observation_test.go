package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// CLI-side report-only observation tests (ZAI-115): the observer is
// injected through the orchestrator; production wiring never configures
// it; --dry-run never observes; and the CLI experiment pin and the
// observation-eligible resource stay locked together.

// TestFirstExperimentResourceIsReportable pins the two resource constants
// equal — a drift on either side must fail here (the orchestrate-side twin
// pins the same equality from the eligible-plan direction).
func TestFirstExperimentResourceIsReportable(t *testing.T) {
	if firstExperimentResource != orchestrate.ReportableServiceResource {
		t.Fatalf("the CLI experiment pin %q and the reportable resource %q must be identical", firstExperimentResource, orchestrate.ReportableServiceResource)
	}
}

// TestDefaultApplyOrchestratorNoObserver pins the production default: the
// report-only observer is DISABLED on the real fail2ban path — no wiring,
// no flag, no environment switch.
func TestDefaultApplyOrchestratorNoObserver(t *testing.T) {
	o := defaultApplyOrchestrator(0)
	if o.ObserveService != nil {
		t.Fatal("the production wiring must leave the report-only observer DISABLED (nil)")
	}
	if o.ServiceObservationTimeout != 0 {
		t.Fatal("the production wiring must not configure an observation timeout")
	}
}

// observationCountingOrchestrator injects an observation dependency whose
// snapshots always fail (the strongest non-interference probe: observation
// errors must surface as notes and change nothing else).
func observationCountingOrchestrator(t *testing.T, states []discovery.Result) (*orchestrate.Orchestrator, *int) {
	t.Helper()
	o, _, _ := applyTestOrchestrator(t, states, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}},
	})
	calls := 0
	o.ObserveService = func(ctx context.Context, unit string) (serviceobs.Observation, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			return serviceobs.Observation{}, errors.New("observation context must be bounded")
		}
		return serviceobs.Observation{}, errors.New("injected observation failure")
	}
	return o, &calls
}

// --dry-run stops before confirmation and execution: the observer must
// never run, even when one is configured.
func TestApplyDryRunNeverObserves(t *testing.T) {
	o, calls := observationCountingOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)})
	var out strings.Builder
	code := runApplyWith([]string{"--dry-run", "--config", experimentConfig(t)}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("dry-run must succeed, code=%d output=%s", code, out.String())
	}
	if *calls != 0 {
		t.Fatalf("--dry-run must not observe, got %d observer calls", *calls)
	}
	if strings.Contains(out.String(), "Service observation") {
		t.Fatal("a dry-run must not carry an observation report")
	}
}

// A confirmed run with an injected observer surfaces the report-only
// diagnostic in the CLI output without changing the exit code — even when
// every observation call fails.
func TestApplySurfacesObservationReport(t *testing.T) {
	// Discovery calls: #1 test-side Prepare (fingerprint), #2 CLI Prepare,
	// #3 staleness re-check, #4 post-apply re-discovery.
	o, calls := observationCountingOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t), loadSaymer3Discovery(t), repairedSaymer3Discovery(t),
	})
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)

	var out strings.Builder
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("an observation failure must not fail the run, code=%d output=%s", code, out.String())
	}
	if *calls != 2 {
		t.Fatalf("the observer must run twice around the engine attempt, got %d", *calls)
	}
	if !strings.Contains(out.String(), "Service observation (report-only)") || !strings.Contains(out.String(), "before-snapshot unavailable") || !strings.Contains(out.String(), "after-snapshot unavailable") {
		t.Fatalf("the report and its failure notes must be surfaced: %s", out.String())
	}
	if !strings.Contains(out.String(), "Stage: COMPLETED") {
		t.Fatalf("the run must still complete: %s", out.String())
	}
}

// The observation failure path must keep the exit code identical to the
// unobserved run.
func TestApplyObservationFailureKeepsExitCode(t *testing.T) {
	// The plain orchestrator gets a test-side Prepare (fingerprint), so its
	// queue is 4 long; the observed orchestrator is used without one and
	// needs only 3 (CLI Prepare, staleness, post-apply).
	plain, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t), loadSaymer3Discovery(t), repairedSaymer3Discovery(t),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}},
	})
	prepared := plain.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)

	var outPlain strings.Builder
	codePlain := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, plain, rootOpts(), strings.NewReader(""), &outPlain, &outPlain)

	o, _ := observationCountingOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t), repairedSaymer3Discovery(t),
	})
	var outObs strings.Builder
	codeObs := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, o, rootOpts(), strings.NewReader(""), &outObs, &outObs)

	if codePlain != codeObs {
		t.Fatalf("the exit code must not change with an observer: %d vs %d", codePlain, codeObs)
	}
	if !strings.Contains(outObs.String(), "Service observation (report-only)") {
		t.Fatalf("the observed run must surface its report: %s", outObs.String())
	}
	if strings.Contains(outPlain.String(), "Service observation (report-only)") {
		t.Fatal("the unobserved run must not carry a report")
	}
}
