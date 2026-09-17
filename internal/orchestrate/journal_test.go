package orchestrate

import (
	"crypto/sha256"
	"encoding/hex"
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

// Backup-integrity failure propagates to RECOVERY_REQUIRED: a real
// FileExecutor whose stored backup content is tampered with mid-transaction
// refuses the restore, the engine reports ROLLBACK_FAILED, and the journal
// latches recovery.
type tamperBackupExecutor struct {
	inner    *apply.FileExecutor
	txID     string
	tampered bool
}

func (e *tamperBackupExecutor) BindTransaction(ctx apply.TransactionContext) {
	e.inner.BindTransaction(ctx)
	e.txID = ctx.TransactionID
}
func (e *tamperBackupExecutor) BindActions(actions map[string]state.Action) {
	e.inner.BindActions(actions)
}
func (e *tamperBackupExecutor) Backup(id, resource string) error { return e.inner.Backup(id, resource) }
func (e *tamperBackupExecutor) Validate(id, resource string) error {
	return e.inner.Validate(id, resource)
}
func (e *tamperBackupExecutor) Rollback(id, resource string) error {
	return e.inner.Rollback(id, resource)
}
func (e *tamperBackupExecutor) Apply(id, resource, kind string) error {
	if err := e.inner.Apply(id, resource, kind); err != nil {
		return err
	}
	// Corrupt the stored backup content AFTER the apply succeeded.
	content := filepath.Join(e.inner.Backups, e.txID, id, "content")
	data, err := os.ReadFile(content)
	if err != nil { return err }
	return os.WriteFile(content, append([]byte("XX"), data...), 0600)
}

func TestBackupIntegrityFailureLatchesRecoveryRequired(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc", "vps-gateway", "integrity.conf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, []byte("original\n"), 0640); err != nil { t.Fatal(err) }
	lockedPath := filepath.Join(root, "etc", "vps-gateway", "locked", "locked.conf")
	if err := os.MkdirAll(filepath.Dir(lockedPath), 0555); err != nil { t.Fatal(err) } // Apply of the second file fails here
	yes := true
	inspect := func(p string) (state.FileActual, error) {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) { return state.FileActual{Path: p}, nil }
			return state.FileActual{Path: p}, err
		}
		digest := sha256.Sum256(data)
		return state.FileActual{Path: p, Exists: true, SHA256: hex.EncodeToString(digest[:]), Mode: 0640}, nil
	}
	cfg := &pipeline.Config{
		Desired: &state.Desired{
			Files: []state.FileDesired{
				{Path: path, Content: "mutated\n", Mode: 0640},
				{Path: lockedPath, Content: "x\n", Mode: 0640},
			},
		},
		Ownership: map[string]state.Ownership{
			"file." + path:       state.Owned,
			"file." + lockedPath: state.Owned,
		},
	}
	inner := &apply.FileExecutor{Root: root, Backups: filepath.Join(root, "backups")}
	wrapper := &tamperBackupExecutor{inner: inner}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(true), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionUpdateFile:      wrapper,
			state.ActionCreateFile:      wrapper,
			state.ActionDeleteOwnedFile: wrapper,
		},
	}, nil)
	p := o.Prepare(cfg, pipeline.Options{Root: &yes, InspectFile: inspect})
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }

	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	recs, err := o.Journal.Records()
	if err != nil { t.Fatal(err) }
	if len(recs) != 1 { t.Fatalf("records=%+v", recs) }
	if recs[0].Outcome != journal.OutcomeRecoveryRequired || !recs[0].RecoveryRequired {
		t.Fatalf("backup integrity failure must latch recovery: %+v", recs[0])
	}
	if recs[0].RollbackResult != "ROLLBACK_FAILED" { t.Fatalf("rollback result=%q", recs[0].RollbackResult) }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state must not persist: %v", err) }
	// The managed file must have been left as the rollback found it: since
	// the restore was refused, the mutated content stays and the operator
	// decides (fail-safe, never silent).
	if data, err := os.ReadFile(path); err != nil || string(data) != "mutated\n" {
		t.Fatalf("managed file unexpectedly restored: %q %v", data, err)
	}
}

func ptr(b bool) *bool { return &b }
