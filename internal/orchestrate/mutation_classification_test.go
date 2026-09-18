package orchestrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Regression tests for the TASK-15 F1/F2 hardening:
//   - mutation classification is registry-backed and fail-closed: a
//     mutation-capable executor registered under ActionValidate gains no
//     read-only exemption from provenance, journal or retry-classification
//     gates (F1);
//   - persistence requires journal evidence: a nil-Journal embedder can run
//     read-only validation but can never persist last-known-good state,
//     so a NO_CHANGE run cannot launder a failed transaction (F2).

// mutatingValidateExecutor is deliberately NOT a read-only executor: it
// simulates a future executor registered under ActionValidate whose Apply
// mutates the machine (writes a file). It implements no ReadOnly method,
// so the fail-closed classification must treat it as mutation-capable.
type mutatingValidateExecutor struct {
	calls []string
	path  string
}

func (e *mutatingValidateExecutor) Backup(id, resource string) error {
	e.calls = append(e.calls, "backup:"+resource)
	return nil
}
func (e *mutatingValidateExecutor) Apply(id, resource, kind string) error {
	e.calls = append(e.calls, "apply:"+resource)
	return os.WriteFile(e.path, []byte("mutated"), 0600)
}
func (e *mutatingValidateExecutor) Validate(id, resource string) error {
	e.calls = append(e.calls, "validate:"+resource)
	return nil
}
func (e *mutatingValidateExecutor) Rollback(id, resource string) error {
	e.calls = append(e.calls, "rollback:"+resource)
	return nil
}

// externalValidateConfig prepares a genuine VALIDATE-only plan: ssh.service
// is observed but externally owned and its desired state differs, so the
// diff is EXTERNAL and BuildPlan emits a read-only-looking VALIDATE action
// for it — exactly the shape a mutating executor under ActionValidate would
// inherit exemptions through.
func externalValidateConfig() *pipeline.Config {
	no := false
	return &pipeline.Config{
		Desired:   &state.Desired{Services: []state.ServiceDesired{{Name: "ssh.service", Active: &no}}},
		Ownership: map[string]state.Ownership{"service.ssh.service": state.External},
	}
}

// F1 negative: a mutation-capable executor under ActionValidate must not
// execute a hand-built (unprepared) plan — the provenance gate classifies
// the plan as mutating and blocks before any executor call.
func TestMutatingExecutorUnderValidateKindCannotBypassProvenance(t *testing.T) {
	mut := &mutatingValidateExecutor{path: filepath.Join(t.TempDir(), "bypass")}
	o, _ := newOrchestrator(t, nil, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionValidate: mut},
	}, nil)
	p := Plan{Ready: true, Preflight: readyPreflight(), Plan: state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
		{ID: "v1", Resource: "service.ssh.service", Kind: state.ActionValidate, Ownership: state.External, Why: "observe external resource", Risk: state.RiskLow},
	}}}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("mutating VALIDATE-kind plan executed unprepared: %s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "unprepared plan") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(mut.calls) != 0 { t.Fatalf("mutation attempted: %v", mut.calls) }
	if _, err := os.Stat(mut.path); !os.IsNotExist(err) { t.Fatalf("mutation happened: %v", err) }
}

// F1 negative, prepared: even a PREPARED plan whose only action rides on a
// mutation-capable executor under ActionValidate cannot skip the journal,
// and with a journal present the unclassifiable mutating kind is refused by
// retry classification — unknown classes are mutation-capable and fail
// closed, never silently journaled as retryable.
func TestMutatingExecutorUnderValidateKindRequiresJournalAndClassification(t *testing.T) {
	mut := &mutatingValidateExecutor{path: filepath.Join(t.TempDir(), "bypass")}

	// Prepared, no journal: the mutation gate refuses the run.
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionValidate: mut},
	}, nil)
	o.Journal = nil
	p := o.Prepare(externalValidateConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("mutating plan ran without journal: %s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "no transaction journal") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(mut.calls) != 0 { t.Fatalf("mutation attempted: %v", mut.calls) }

	// Prepared with a journal: the VALIDATE kind has no retry
	// classification, so the mutating run is refused there as well.
	o2, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionValidate: mut},
	}, nil)
	p2 := o2.Prepare(externalValidateConfig(), rootOn())
	if !p2.Ready { t.Fatalf("plan not ready: %v", p2.Blockers) }
	conf2 := Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out2, err := o2.Execute(p2, conf2, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageBlocked { t.Fatalf("unclassifiable mutating kind must be refused: %s", out2.Stage) }
	if !strings.Contains(strings.Join(out2.Blockers, "; "), "no retry classification") { t.Fatalf("blockers=%v", out2.Blockers) }
	if len(mut.calls) != 0 { t.Fatalf("mutation attempted: %v", mut.calls) }
}

// F2 negative (the laundering path itself): run 1 fails after possible
// mutation and its journal carries the FAILED record; run 2 is an
// autonomous NO_CHANGE run on an embedder with Journal == nil. Before the
// hardening it skipped the anti-laundering gate and persisted over the
// failed transaction; now persistence fails closed and the state file is
// never written.
func TestNilJournalCannotLaunderFailedPostMutationState(t *testing.T) {
	final := makeDiscovery(true)
	final.Services = final.Services[:1] // the unit vanished after apply
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), final,
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedFinalValidation { t.Fatalf("run1 stage=%s", out.Stage) }
	recs, err := o.Journal.Records()
	if err != nil { t.Fatal(err) }
	if len(recs) != 1 || recs[0].Outcome != journal.OutcomeFailed || !recs[0].MutationPossible {
		t.Fatalf("run1 must leave a failed post-mutation record: %+v", recs)
	}

	// Run 2: converged machine, NO_CHANGE plan, journal deliberately nil.
	o2, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(true), makeDiscovery(true), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	o2.Journal = nil
	o2.StatePath = o.StatePath
	p2 := o2.Prepare(fail2banConfig(), rootOn())
	if len(p2.Plan.Actions) != 0 { t.Fatalf("run2 should be NO_CHANGE, actions=%v", p2.Plan.Actions) }
	out2, err := o2.Execute(p2, Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageFailedFinalValidation { t.Fatalf("run2 stage=%s", out2.Stage) }
	if out2.Persisted { t.Fatal("nil-Journal run must not persist") }
	if !strings.Contains(strings.Join(out2.Blockers, "; "), "no transaction journal configured") {
		t.Fatalf("blockers=%v", out2.Blockers)
	}
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
}

// F2 boundary: a nil-Journal embedder can still run pure read-only
// validation to completion — the validation executor runs, re-discovery and
// convergence hold — but the run cannot persist last-known-good state.
func TestNilJournalRunsReadOnlyValidationWithoutPersistence(t *testing.T) {
	ro := &readOnlyValidateExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(true), makeDiscovery(true), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionValidate: ro},
	}, nil)
	o.Journal = nil
	p := o.Prepare(externalValidateConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }
	if len(p.Plan.Actions) != 1 || p.Plan.Actions[0].Kind != state.ActionValidate { t.Fatalf("actions=%v", p.Plan.Actions) }
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	sawValidation := false
	for _, c := range ro.calls {
		if strings.HasPrefix(c, "validate:") { sawValidation = true }
	}
	if !sawValidation { t.Fatalf("read-only validation must still run: %v", ro.calls) }
	if out.Persisted { t.Fatal("nil-Journal run must not persist") }
	if out.Stage != StageFailedFinalValidation || !strings.Contains(strings.Join(out.Blockers, "; "), "no transaction journal configured") {
		t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers)
	}
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
}
