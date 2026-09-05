package orchestrate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Security/code audit of the Prepare → Confirm → Execute boundary. Each test
// pins one attack or failure path; the invariant under audit is that the
// mutation happens only after every fail-closed condition holds, and that
// persisted state is written only after re-discovery + final validation +
// convergence.

func noOwnedConfig() *pipeline.Config {
	yes := true
	return &pipeline.Config{Desired: &state.Desired{Services: []state.ServiceDesired{{Name: "fail2ban.service", Active: &yes}}}}
}

// Scenario: plan mutated after the confirmation was produced. The stale
// fingerprint must not match the mutated plan.
func TestExecuteBlocksPlanMutatedAfterConfirmation(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}

	// Mutate the plan after the confirmation exists.
	p.Plan.Actions = append(p.Plan.Actions, state.Action{ID: "extra", Resource: "service.other.service", Kind: state.ActionService, Ownership: state.Owned})

	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with mutated plan: %v", svc.calls) }
}

// Scenario: manually constructed plan whose action kind has no executor.
// Even bypassing Prepare, Execute must block BEFORE the mutation (not fail
// in the middle of a transaction).
func TestExecuteBlocksHandBuiltPlanWithoutCoverage(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, nil, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionUpdateFile: svc},
	}, nil)
	p := Plan{
		Ready:     true,
		Preflight: readyPreflight(),
		Plan: state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
			{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned},
		}},
	}
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "executor-coverage") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted: %v", svc.calls) }
}

// Scenario: manually constructed plan flagged Blocked. Execute must reject it
// even though the caller claims Ready.
func TestExecuteBlocksHandBuiltBlockedPlan(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, nil, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := Plan{
		Ready:     true,
		Preflight: readyPreflight(),
		Plan: state.Plan{SchemaVersion: state.SchemaVersion, Blocked: true, BlockReasons: []string{"forged"}, Actions: []state.Action{
			{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned},
		}},
	}
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted: %v", svc.calls) }
}

// Scenario: not-ready preflight claimed ready by the caller.
func TestExecuteBlocksHandBuiltPlanWithoutPreflight(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, nil, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := Plan{
		Ready: true,
		Plan: state.Plan{SchemaVersion: state.SchemaVersion, Actions: []state.Action{
			{ID: "a1", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned},
		}},
	}
	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted: %v", svc.calls) }
}

// Scenario: UNKNOWN ownership end-to-end. The plan is blocked at Prepare and
// Execute refuses it even if handed in directly.
func TestExecuteUnknownOwnershipEndToEnd(t *testing.T) {
	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(noOwnedConfig(), rootOn())
	if p.Ready { t.Fatal("UNKNOWN ownership must make the plan not ready") }
	if !p.Plan.Blocked { t.Fatal("plan must be blocked on UNKNOWN ownership") }

	p.Ready = true // attacker claims readiness
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted: %v", svc.calls) }
}

// Scenario: backup failure. The transaction reports failure, nothing is
// persisted, the lock is released.
func TestExecuteBackupFailure(t *testing.T) {
	svc := &recordingExecutor{failBackup: true}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	if out.Persisted { t.Fatal("backup failure must never be persisted") }
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
	if _, err := os.Stat(o.LockPath); !os.IsNotExist(err) { t.Fatalf("lock must be released: %v", err) }
}

// Scenario: validation failure inside the transaction. The engine rolls the
// action back; the run fails without persisting.
func TestExecuteValidateFailureRollsBack(t *testing.T) {
	svc := &recordingExecutor{failValidate: true}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	if out.Transaction.Status != apply.StatusRolledBack { t.Fatalf("status=%s", out.Transaction.Status) }
	found := false
	for _, c := range svc.calls {
		if strings.HasPrefix(c, "rollback:") { found = true }
	}
	if !found { t.Fatalf("rollback was not performed: %v", svc.calls) }
	if out.Persisted { t.Fatal("failed transaction must never be persisted") }
}

// Scenario: rollback itself fails. The run still fails, still never persists,
// and the rollback error is visible in the transaction record.
func TestExecuteRollbackFailureStillNoPersist(t *testing.T) {
	svc := &recordingExecutor{failApply: true, failRollback: true}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedTransaction { t.Fatalf("stage=%s", out.Stage) }
	if out.Persisted { t.Fatal("rollback failure must never be persisted as success") }
	if !strings.Contains(out.Transaction.Actions[0].Error, "rollback:") {
		t.Fatalf("rollback error must be visible in the action record: %#v", out.Transaction.Actions[0])
	}
}

// Scenario: re-discovery after an applied transaction reports CONFLICT.
func TestExecuteRediscoveryConflictNoPersist(t *testing.T) {
	svc := &recordingExecutor{}
	conflicted := makeDiscovery(true)
	conflicted.Status = "CONFLICT"
	conflicted.Conflicts = []discovery.Observation{{Code: "PORT_CONFLICT", Component: "ssh", Message: "conflict appeared"}}
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), conflicted}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedRediscovery { t.Fatalf("stage=%s", out.Stage) }
	if out.Persisted { t.Fatal("conflicted re-discovery must never be persisted") }
	if *calls != 3 { t.Fatalf("discovery calls=%d, want 3", *calls) }
}

// Scenario: the machine regressed after apply (SSH hardening vanished).
// Re-discovery is OK but the full validate gate fails.
func TestExecuteFinalValidateFailureNoPersist(t *testing.T) {
	svc := &recordingExecutor{}
	regressed := makeDiscovery(true)
	yes := true
	regressed.SSH.PasswordAuthentication = &yes
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), regressed}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedFinalValidation { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "post-apply validate") { t.Fatalf("blockers=%v", out.Blockers) }
	if out.Persisted { t.Fatal("failed final validation must never be persisted") }
}

// Scenario: persist failure (state path not writable). The machine may be
// applied, but the run is reported FAILED_PERSIST and nothing is persisted.
func TestExecutePersistFailureReported(t *testing.T) {
	svc := &recordingExecutor{}
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0600); err != nil { t.Fatal(err) }
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	o.StatePath = filepath.Join(blocked, "state.json")
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageFailedPersist { t.Fatalf("stage=%s blockers=%v", out.Stage, out.Blockers) }
	if out.Persisted { t.Fatal("failed persist must not claim persistence") }
}

// Scenario: re-running Execute after a failed transaction. No half-state may
// accumulate: the second run fails identically and nothing is persisted.
func TestExecuteTwiceAfterFailureIsSafe(t *testing.T) {
	svc := &recordingExecutor{failApply: true}
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	for run := 1; run <= 2; run++ {
		out, err := o.Execute(p, conf, nil)
		if err != nil { t.Fatal(err) }
		if out.Stage != StageFailedTransaction { t.Fatalf("run %d stage=%s", run, out.Stage) }
		if out.Persisted { t.Fatalf("run %d persisted a failed transaction", run) }
	}
	if _, err := os.Stat(o.StatePath); !os.IsNotExist(err) { t.Fatalf("state file must not exist: %v", err) }
	if *calls != 3 { t.Fatalf("discovery calls=%d, want 3 (1 prepare + 1 staleness per run)", *calls) }
}

// Scenario: two concurrent Executes on the same target. The lock must make
// the second one block before any mutation.
func TestParallelExecuteMutualExclusion(t *testing.T) {
	svc := &recordingExecutor{}
	release := make(chan struct{})
	blocking := &blockingExecutor{inner: svc, release: release, started: make(chan struct{})}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: blocking},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}

	var out1 Outcome
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, err := o.Execute(p, conf, nil)
		if err != nil { t.Error(err); return }
		out1 = out
	}()
	<-blocking.started // first run holds the lock and is inside the transaction

	out2, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out2.Stage != StageBlocked { t.Fatalf("second concurrent execute stage=%s, want BLOCKED_PRE_MUTATION", out2.Stage) }
	if !strings.Contains(strings.Join(out2.Blockers, "; "), "lock") { t.Fatalf("blockers=%v", out2.Blockers) }

	close(release)
	wg.Wait()
	if out1.Stage != StageCompleted { t.Fatalf("first run stage=%s blockers=%v", out1.Stage, out1.Blockers) }
}

// Scenario: the machine changed between Prepare and Execute. The staleness
// gate must refuse the mutation: regenerate the plan, never apply a stale one.
func TestExecuteBlocksStalePlan(t *testing.T) {
	svc := &recordingExecutor{}
	o, calls := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}

	// Between Prepare and Execute the machine drifted: fail2ban repaired
	// itself, so the rebuilt plan no longer matches the prepared one.
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageBlocked { t.Fatalf("stage=%s", out.Stage) }
	if !strings.Contains(strings.Join(out.Blockers, "; "), "stale") { t.Fatalf("blockers=%v", out.Blockers) }
	if len(svc.calls) != 0 { t.Fatalf("mutation attempted with stale plan: %v", svc.calls) }
	if *calls != 2 { t.Fatalf("discovery calls=%d, want 2 (prepare + staleness)", *calls) }
}

func readyPreflight() state.Preflight {
	return state.Preflight{Status: state.PreflightReady}
}

// blockingExecutor holds the transaction inside Apply until released, so the
// test can start a second concurrent Execute while the lock is held.
type blockingExecutor struct {
	inner   *recordingExecutor
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingExecutor) Backup(id, resource string) error   { return b.inner.Backup(id, resource) }
func (b *blockingExecutor) Validate(id, resource string) error { return b.inner.Validate(id, resource) }
func (b *blockingExecutor) Rollback(id, resource string) error { return b.inner.Rollback(id, resource) }
func (b *blockingExecutor) Apply(id, resource, kind string) error {
	b.inner.calls = append(b.inner.calls, "apply:"+resource)
	b.once.Do(func() { close(b.started) })
	<-b.release
	return nil
}
