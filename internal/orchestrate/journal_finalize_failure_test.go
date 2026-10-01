package orchestrate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// finalizeBreaker is a scripted SERVICE executor that makes the terminal
// journal write fail deterministically, independent of euid. Since R5-A
// the engine persists per-action progress during the transaction, so the
// injection must NOT break those writes (an APPLIED whose persistence
// fails fails the transaction fail-closed — that is the R5-A contract,
// covered by the progress-failure test): the breaker instead lets every
// progress write succeed and swaps the journal record FILE for an empty
// DIRECTORY at the executor's Validate boundary — after the durable
// APPLIED write, before the terminal finalize. Journal.Update's os.Rename
// of the fresh temp file over that directory fails with EISDIR — root
// included; journal loads (loadAll) skip directories, so read-side gates
// still work. The Begin-time record content is kept in stash so a test can
// restore the truthful durable state afterwards.
type finalizeBreaker struct {
	journalDir string
	stash      []byte
	txID       string
	failApply  bool
	broken     bool
	calls      []string
}

func (e *finalizeBreaker) BindTransaction(ctx apply.TransactionContext) {
	e.txID = ctx.TransactionID
}

func (e *finalizeBreaker) Backup(id, resource string) error {
	e.calls = append(e.calls, "backup")
	return nil
}

func (e *finalizeBreaker) Apply(id, resource, kind string) error {
	e.calls = append(e.calls, "apply")
	if e.failApply {
		return errors.New("apply failed (scripted)")
	}
	return nil
}

func (e *finalizeBreaker) Validate(id, resource string) error {
	e.calls = append(e.calls, "validate")
	return e.breakNow()
}

func (e *finalizeBreaker) Rollback(id, resource string) error {
	e.calls = append(e.calls, "rollback")
	// Failed-stage scenario: break the record at the rollback boundary so
	// the terminal finalize fails on an already-FAILED run.
	return e.breakNow()
}

// breakNow swaps the record file for a directory once; idempotent.
func (e *finalizeBreaker) breakNow() error {
	if e.broken {
		return nil
	}
	e.broken = true
	recPath := filepath.Join(e.journalDir, e.txID+".json")
	data, err := os.ReadFile(recPath)
	if err != nil {
		return err
	}
	e.stash = data
	if err := os.Remove(recPath); err != nil {
		return err
	}
	return os.Mkdir(recPath, 0700)
}

// restoreJournalRecord puts the Begin-time record content back so the
// durable state can be inspected as it would exist in production.
func restoreJournalRecord(t *testing.T, dir, txID string, stash []byte) {
	t.Helper()
	recPath := filepath.Join(dir, txID+".json")
	info, err := os.Stat(recPath)
	if err != nil {
		t.Fatalf("journal record path missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("record was not replaced by a directory; injection did not run")
	}
	if err := os.Remove(recPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recPath, stash, 0600); err != nil {
		t.Fatal(err)
	}
}

// T1/T2 (ZAI-04): when the terminal journal update fails, the caller must
// see the failure — a fully successful transaction (mutation, validation,
// convergence, persistence all passed) must NOT be reported as a clean
// COMPLETED result with no blockers. Before the named-return fix this test
// failed: the finalization blocker was appended to a local Outcome copy the
// caller never saw, and the run reported clean success while the durable
// record stayed in progress.
func TestExecuteSurfacesJournalFinalizationFailure(t *testing.T) {
	brk := &finalizeBreaker{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: brk},
	}, nil)
	brk.journalDir = o.Journal.Dir
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("prepare must be ready: %v", p.Blockers)
	}

	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted || !out.Persisted {
		t.Fatalf("transaction itself must complete and persist: stage=%s persisted=%v blockers=%v", out.Stage, out.Persisted, out.Blockers)
	}
	// T1: the finalization failure is caller-visible.
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "journal:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("journal finalization failure is invisible to the caller: %v", out.Blockers)
	}
	// T2: no clean COMPLETED result.
	if len(out.Blockers) == 0 {
		t.Fatal("clean COMPLETED result reported despite failed journal finalization")
	}

	// T5: the durable journal remains truthful — no record falsely claims
	// COMPLETED; the on-disk record is the in-progress Begin version.
	restoreJournalRecord(t, o.Journal.Dir, brk.txID, brk.stash)
	if !strings.Contains(string(brk.stash), `"transaction_id"`) || strings.Contains(string(brk.stash), `"outcome"`) {
		t.Fatalf("stashed Begin record is not an in-progress record: %s", brk.stash)
	}
	j := &journal.Journal{Dir: o.Journal.Dir}
	records, err := j.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Outcome != "" {
		t.Fatalf("durable journal must hold the in-progress record, got %+v", records)
	}
	blockers, err := j.BlockingRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(blockers) != 1 {
		t.Fatalf("next mutating run must be fail-safe blocked, got %d blockers", len(blockers))
	}
}

// T4 (ZAI-04): a pre-existing failure path keeps its semantics — the
// transaction still reports FAILED_TRANSACTION with the rollback recorded,
// and the fix only ADDS the previously invisible finalization blocker; it
// must not transform the failure into success.
func TestExecuteSurfacesFinalizationFailureOnFailedStage(t *testing.T) {
	brk := &finalizeBreaker{failApply: true}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: brk},
	}, nil)
	brk.journalDir = o.Journal.Dir
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("prepare must be ready: %v", p.Blockers)
	}

	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageFailedTransaction {
		t.Fatalf("failure path semantics changed: stage=%s", out.Stage)
	}
	if out.Transaction.Status != apply.StatusRolledBack {
		t.Fatalf("transaction must remain rolled back: %s", out.Transaction.Status)
	}
	found := false
	for _, b := range out.Blockers {
		if strings.Contains(b, "journal:") {
			found = true
		}
	}
	if !found {
		t.Fatalf("finalization failure invisible on the failed stage: %v", out.Blockers)
	}
}

// T3 (ZAI-04): successful finalization is unchanged — a clean run still
// returns COMPLETED with no blockers, and the durable record reaches the
// COMPLETED outcome.
func TestExecuteCleanCompletionHasNoBlockers(t *testing.T) {
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &recordingExecutor{}},
	}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready {
		t.Fatalf("prepare must be ready: %v", p.Blockers)
	}

	out, err := o.Execute(p, Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "operator", At: time.Now().UTC()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted || !out.Persisted || len(out.Blockers) != 0 {
		t.Fatalf("clean completion changed: stage=%s persisted=%v blockers=%v", out.Stage, out.Persisted, out.Blockers)
	}
	records, err := o.Journal.Records()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Outcome != journal.OutcomeCompleted {
		t.Fatalf("durable record must be COMPLETED, got %+v", records)
	}
}
