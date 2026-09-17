package orchestrate

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// End-to-end tests for the durable transaction/recovery layer
// (docs/security-model.md §11): journal-before-mutation, outcome
// transitions, the recovery latch and the anti-laundering persistence gate.

// The journal record must exist durably BEFORE the first possibly mutating
// operation: the executor's Backup (the engine's first call) asserts the
// record is already on disk.
func TestJournalRecordExistsBeforeFirstMutation(t *testing.T) {
	var backupSawRecord, applySawRecord bool
	var journalDir string
	rec := &recordingExecutor{}
	spy := &assertingExecutor{
		inner: rec,
		onCall: func(stage string) {
			entries, err := os.ReadDir(journalDir)
			if err != nil { t.Errorf("journal dir unreadable at %s: %v", stage, err); return }
			if len(entries) == 0 { t.Errorf("no journal record at %s: journal must exist before first mutation", stage) }
			if stage == "backup" { backupSawRecord = true } else { applySawRecord = true }
		},
	}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: spy},
	}, nil)
	journalDir = o.Journal.Dir
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !backupSawRecord || !applySawRecord { t.Fatal("executor stages not observed") }

	// Successful transaction reaches COMPLETED, with recovery clear.
	recs, err := o.Journal.Records()
	if err != nil { t.Fatal(err) }
	if len(recs) != 1 { t.Fatalf("records=%+v", recs) }
	if recs[0].Outcome != journal.OutcomeCompleted || recs[0].RecoveryRequired {
		t.Fatalf("outcome=%q recovery=%v", recs[0].Outcome, recs[0].RecoveryRequired)
	}
	if !recs[0].MutationPossible { t.Fatal("mutating transaction must record mutation-possible") }
	if recs[0].Approval == nil || recs[0].Approval.Mode != "legacy" { t.Fatalf("approval evidence missing: %+v", recs[0].Approval) }
}

// assertingExecutor forwards to inner and calls onCall at Backup and Apply.
type assertingExecutor struct {
	inner  *recordingExecutor
	onCall func(stage string)
}

func (e *assertingExecutor) Backup(id, resource string) error {
	e.onCall("backup")
	return e.inner.Backup(id, resource)
}
func (e *assertingExecutor) Apply(id, resource, kind string) error {
	e.onCall("apply")
	return e.inner.Apply(id, resource, kind)
}
func (e *assertingExecutor) Validate(id, resource string) error { return e.inner.Validate(id, resource) }
func (e *assertingExecutor) Rollback(id, resource string) error { return e.inner.Rollback(id, resource) }

// A failure before the journal record exists (e.g. staleness rejection)
// must not create any record, let alone a recovery-required one.
func TestPreMutationFailureCreatesNoRecord(t *testing.T) {
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	recs, err := o.Journal.Records()
	if err != nil {
		if !os.IsNotExist(err) { t.Fatal(err) }
		recs = nil // no journal dir yet: nothing was recorded, as required
	}
	if len(recs) != 0 { t.Fatalf("stale-plan rejection must not journal: %+v", recs) }
}

// ROLLBACK_FAILED always latches RECOVERY_REQUIRED.
func TestRollbackFailureCreatesRecoveryRequired(t *testing.T) {
	svc := &recordingExecutor{failApply: true, failRollback: true}
	// Three degraded discoveries: run 1 consumes prepare+staleness, run 2
	// must still see a mutating (non-converged) plan so the recovery gate —
	// not just the persistence gate — is what blocks it.
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	recs, err := o.Journal.Records()
	if err != nil { t.Fatal(err) }
	if len(recs) != 1 { t.Fatalf("records=%+v", recs) }
	if recs[0].Outcome != journal.OutcomeRecoveryRequired || !recs[0].RecoveryRequired {
		t.Fatalf("ROLLBACK_FAILED must latch recovery: outcome=%q recovery=%v", recs[0].Outcome, recs[0].RecoveryRequired)
	}
	if recs[0].RollbackResult != "ROLLBACK_FAILED" { t.Fatalf("rollback result=%q", recs[0].RollbackResult) }

	// The latch blocks a newly approved mutation of the same plan.
	p2 := o.Prepare(fail2banConfig(), rootOn())
	out2, err := o.Execute(p2, Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageBlocked { t.Fatalf("recovery latch must block new mutations: %s", out2.Stage) }
	joined := strings.Join(out2.Blockers, "; ")
	if !strings.Contains(joined, "recovery") { t.Fatalf("blockers=%v", out2.Blockers) }
}

// A valid signed approval does NOT bypass the recovery gate.
func TestApprovalCannotBypassRecovery(t *testing.T) {
	svc := &recordingExecutor{failApply: true, failRollback: true}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.ApprovalVerifier = approvalTestVerifier()

	// Run 1 latches recovery (artifact-approved, rollback fails).
	p := o.Prepare(fail2banConfig(), rootOn())
	out, err := o.Execute(p, Confirmation{Approval: signApproval(t, Fingerprint(p.Plan))}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	recs, err := o.Journal.Records()
	if err != nil { t.Fatal(err) }
	if len(recs) != 1 { t.Fatalf("records=%+v", recs) }
	if recs[0].Outcome != journal.OutcomeRecoveryRequired { t.Fatalf("outcome=%q", recs[0].Outcome) }
	if recs[0].Approval == nil || recs[0].Approval.Mode != "artifact" || recs[0].Approval.Reference == "" {
		t.Fatalf("artifact evidence must be recorded: %+v", recs[0].Approval)
	}

	// Run 2: a fresh valid artifact for a fresh plan must still be refused.
	p2 := o.Prepare(fail2banConfig(), rootOn())
	out2, err := o.Execute(p2, Confirmation{Approval: signApproval(t, Fingerprint(p2.Plan))}, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageBlocked { t.Fatalf("approval bypassed recovery: %s", out2.Stage) }
}

// A crashed run (journal record without final outcome) fail-safes the next
// invocation: mutation is refused until an operator reviews the record.
func TestCrashedRecordBlocksNextMutation(t *testing.T) {
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	crashed := &journal.Record{
		TransactionID: "tx-crashed-1", PlanFingerprint: "fp-old",
		Stage: "MUTATING", MutationPossible: true, StartedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := o.Journal.Begin(crashed); err != nil { t.Fatal(err) }
	p := o.Prepare(fail2banConfig(), rootOn())
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("crashed record must block: %s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "incomplete") { t.Fatalf("blockers=%v", out.Blockers) }
}

// Anti-laundering: a failed post-mutation transaction must not be silently
// converted into last-known-good by a later autonomous NO_CHANGE run.
func TestNoChangeRunCannotLaunderFailedPostMutationState(t *testing.T) {
	svc := &recordingExecutor{}
	final := makeDiscovery(true)
	final.Services = final.Services[:1] // the unit vanished after apply
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), final, makeDiscovery(true), makeDiscovery(true),
	}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)

	// Run 1: applies, then the convergence gate fails on the vanished unit —
	// a post-mutation FAILED transaction, never persisted.
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedFinalValidation { t.Fatalf("run1 stage=%s", out.Stage) }
	if out.Persisted { t.Fatal("run1 must not persist") }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist after run1: %v", err) }

	// Run 2: the machine looks converged, so the plan is NO_CHANGE — but the
	// failed post-mutation history must block the autonomous persistence.
	p2 := o.Prepare(fail2banConfig(), rootOn())
	if len(p2.Plan.Actions) != 0 { t.Fatalf("run2 should be NO_CHANGE, actions=%v", p2.Plan.Actions) }
	out2, err := o.Execute(p2, Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageFailedFinalValidation { t.Fatalf("run2 stage=%s", out2.Stage) }
	if out2.Persisted { t.Fatal("NO_CHANGE run must not launder failed post-mutation state") }
	joined := strings.Join(out2.Blockers, "; ")
	if !strings.Contains(joined, "no-mutation run must not record last-known-good") { t.Fatalf("blockers=%v", out2.Blockers) }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist after run2: %v", err) }
}

// A mutating run that completes cleanly persists even though older FAILED
// (rolled-back) history exists — the hybrid retry model permits the retry,
// and this run re-mutated and re-verified everything itself.
func TestCleanRetryAfterFailedRolledBackRunPersists(t *testing.T) {
	svc := &recordingExecutor{}
	rec := &recordingExecutor{failApply: true}
	states := []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}
	// Run 1 uses a failing executor; run 2 the healthy one. Two orchestrator
	// field swaps share one journal to model two invocations on one host.
	o, _ := newOrchestrator(t, states[:3], apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	if _, err := o.Execute(p, conf, nil); err != nil { t.Fatal(err) }

	o2, _ := newOrchestrator(t, states[2:], apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o2.Journal = o.Journal // same host, same journal
	// Reuse run 1's plan content for run 2 is impossible via a fresh Prepare
	// on a fresh orchestrator without history — so run 2 prepares its own
	// (identical) plan against the same machine state.
	p2 := o2.Prepare(fail2banConfig(), rootOn())
	out2, err := o2.Execute(p2, Confirmation{PlanFingerprint: Fingerprint(p2.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageCompleted || !out2.Persisted { t.Fatalf("clean retry must complete: %s %v", out2.Stage, out2.Blockers) }
}

// Finalize transition: a post-mutation failure on a plan containing a
// NO_AUTONOMOUS_RETRY action latches recovery. (SSH_FINALIZE plans cannot
// be prepared yet — TASK-10 pins that — so the transition is exercised at
// the finalize boundary with a synthetic transaction.)
func TestFinalizeLatchesRecoveryForNoAutonomousRetryActions(t *testing.T) {
	o, _ := newOrchestrator(t, nil, apply.Registry{}, nil)
	rec := &journal.Record{
		TransactionID: "tx-finalize", PlanFingerprint: "fp",
		Stage: "MUTATING", MutationPossible: true,
		Actions: []journal.ActionRecord{{
			ID: "f1", Resource: "ssh.port", Kind: string(state.ActionSSHFinalize),
			RetryClass: journal.NoAutonomousRetry, Status: "APPLY_FAILED",
		}},
	}
	out := Outcome{Stage: StageFailedTransaction, Transaction: apply.Transaction{Status: apply.StatusRolledBack}}
	if err := o.finalizeJournal(rec, &out); err != nil { t.Fatal(err) }
	if rec.Outcome != journal.OutcomeRecoveryRequired || !rec.RecoveryRequired {
		t.Fatalf("no-autonomous-retry failure must latch recovery: %+v", rec)
	}

	// Retry-safe counterpart: same failure shape without a danger action
	// stays a plain FAILED record.
	rec2 := &journal.Record{
		TransactionID: "tx-safe", PlanFingerprint: "fp",
		Stage: "MUTATING", MutationPossible: true,
		Actions: []journal.ActionRecord{{
			ID: "s1", Resource: "service.fail2ban.service", Kind: string(state.ActionService),
			RetryClass: journal.RetrySafe, Status: "APPLY_FAILED",
		}},
	}
	out2 := Outcome{Stage: StageFailedTransaction, Transaction: apply.Transaction{Status: apply.StatusRolledBack}}
	if err := o.finalizeJournal(rec2, &out2); err != nil { t.Fatal(err) }
	if rec2.Outcome != journal.OutcomeFailed || rec2.RecoveryRequired {
		t.Fatalf("retry-safe failure must not latch: %+v", rec2)
	}
}
