package orchestrate

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Regression tests for the TASK-09 operator decisions:
//   - every mutating Plan executed by Execute must originate from Prepare;
//   - convergence must use the exact planning context (p.Config + p.opts);
//   - post-apply CONFLICT/UNKNOWN/UNSUPPORTED must block persistence;
//   - read-only (VALIDATE-only) plans remain executable without Prepare.

// A prepared plan stripped of its provenance: identical plan content,
// correct fingerprint, valid legacy confirmation — only the missing Prepare
// provenance differs. Execute must refuse it before any mutation.
func TestExecuteRejectsUnpreparedMutatingPlan(t *testing.T) {
	rec := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec},
	}, nil)
	prepared := o.Prepare(fail2banConfig(), rootOn())
	if !prepared.Ready { t.Fatalf("plan not ready: %v", prepared.Blockers) }

	hand := Plan{
		Discovery: prepared.Discovery,
		Model:     prepared.Model,
		Plan:      prepared.Plan,
		Preflight: prepared.Preflight,
		Config:    prepared.Config,
		Ready:     true,
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(hand.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(hand, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("unprepared mutating plan was executed: %s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "unprepared plan") {
		t.Fatalf("blockers=%v", out.Blockers)
	}
	if len(rec.calls) != 0 { t.Fatalf("mutation attempted with unprepared plan: %v", rec.calls) }
}

// The sanctioned path is unchanged: a prepared mutating plan executes to
// completion (positive control for the provenance gate).
func TestPreparedMutatingPlanStillExecutes(t *testing.T) {
	rec := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !out.Persisted { t.Fatal("state must be persisted on success") }
}

// Read-only behavior is preserved: a VALIDATE-only plan carries no mutation
// and may still execute without Prepare (AGENTS.md §3).
func TestUnpreparedValidateOnlyPlanStillExecutes(t *testing.T) {
	rec := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionValidate: rec},
	}, nil)
	p := Plan{
		Ready:     true,
		Preflight: readyPreflight(),
		Plan: state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
			{ID: "v1", Resource: "service.ssh.service", Kind: state.ActionValidate, Ownership: state.External, Why: "observe external resource", Risk: state.RiskLow},
		}},
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("validate-only plan must still execute: %s blockers=%v", out.Stage, out.Blockers) }
}

// Convergence must consult the SAME injected planning options as Prepare and
// the staleness re-check. The injected file inspector is called once per
// Assemble: #1 Prepare, #2 staleness, #3 convergence. If convergence used
// default options it would read the real filesystem instead (call count 2,
// file observed absent → CREATE divergence → no persist).
func TestConvergenceUsesOriginalPlanningOptions(t *testing.T) {
	const path = "/etc/vps-gateway/convergence-probe.conf"
	const content = "convergence probe\n"
	sum := sha256.Sum256([]byte(content))
	yes := true
	cfg := &pipeline.Config{
		Desired:   &state.Desired{Files: []state.FileDesired{{Path: path, Content: content, Mode: 0600}}},
		Ownership: map[string]state.Ownership{"file." + path: state.Owned},
	}
	calls := 0
	inspect := func(p string) (state.FileActual, error) {
		calls++
		if calls < 3 { return state.FileActual{Path: p}, nil }
		return state.FileActual{Path: p, Exists: true, SHA256: hex.EncodeToString(sum[:]), Mode: 0600}, nil
	}
	rec := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionCreateFile:      rec,
			state.ActionUpdateFile:      rec,
			state.ActionDeleteOwnedFile: rec,
		},
	}, nil)
	p := o.Prepare(cfg, pipeline.Options{Root: &yes, InspectFile: inspect})
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }
	if len(p.Plan.Actions) != 1 || p.Plan.Actions[0].Kind != state.ActionCreateFile {
		t.Fatalf("want exactly one CREATE_FILE action, got %#v", p.Plan.Actions)
	}

	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !out.Persisted { t.Fatal("state must be persisted on success") }
	if calls != 3 { t.Fatalf("inspector calls=%d, want 3 (prepare + staleness + convergence) — convergence must use the planning options", calls) }
}

// End-to-end: the desired unit vanishes between Apply and the final
// re-discovery. The post-apply diff is CONFLICT, which must block
// persistence — state.json must never record it as last-known-good.
func TestConvergenceBlocksPostApplyConflict(t *testing.T) {
	rec := &recordingExecutor{}
	final := makeDiscovery(true)
	final.Services = final.Services[:1] // only ssh.service — fail2ban vanished
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), final}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }

	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedFinalValidation { t.Fatalf("stage=%s", out.Stage) }
	if out.Persisted { t.Fatal("CONFLICT post-apply diff must never be persisted") }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
	joined := strings.Join(out.Blockers, "; ")
	if !strings.Contains(joined, "service.fail2ban.service") || !strings.Contains(joined, "CONFLICT") {
		t.Fatalf("blockers=%v", out.Blockers)
	}
}

// Classification of the convergence gate itself: converged and report-only
// kinds pass; unfinished mutations and unclassifiable state block; unknown
// future kinds fail closed.
func TestConvergenceFailuresClassification(t *testing.T) {
	item := func(kind state.DiffKind) state.DiffItem { return state.DiffItem{Resource: "r", Kind: kind} }

	if got := convergenceFailures([]state.DiffItem{item(state.NoChange), item(state.Skip), item(state.ExternalDiff)}); len(got) != 0 {
		t.Fatalf("converged/report-only kinds must not block: %v", got)
	}
	for _, kind := range []state.DiffKind{state.Create, state.Update, state.Remove} {
		got := convergenceFailures([]state.DiffItem{item(kind)})
		if len(got) != 1 || !strings.Contains(got[0], "did not converge") { t.Fatalf("kind %s: %v", kind, got) }
	}
	for _, kind := range []state.DiffKind{state.Conflict, state.UnknownDiff, state.Unsupported} {
		got := convergenceFailures([]state.DiffItem{item(kind)})
		if len(got) != 1 || !strings.Contains(got[0], "not unambiguous") { t.Fatalf("kind %s: %v", kind, got) }
	}
	if got := convergenceFailures([]state.DiffItem{item(state.DiffKind("SOMETHING_NEW"))}); len(got) != 1 {
		t.Fatalf("unknown future kinds must fail closed: %v", got)
	}
}
