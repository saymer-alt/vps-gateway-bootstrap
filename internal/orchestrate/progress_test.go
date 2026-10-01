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
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// R5-A orchestration tests (ZAI-22 §14/§19/§49): per-action lifecycle
// transitions become durable during the transaction — an external observer
// reading the journal mid-flight sees the APPLIED boundary — and a lost
// progress write after a successful mutation fails the transaction
// closed.

// durableReadExecutor returns success everywhere, and during Apply/Validate
// snapshots the on-disk journal record so the test can prove what was
// durable at that exact boundary.
type durableReadExecutor struct {
	journalPath  func() string
	applySnap    string
	validateSnap string
	failValidate bool
}

func (e *durableReadExecutor) BindTransaction(ctx apply.TransactionContext) {}
func (e *durableReadExecutor) BindActions(actions map[string]state.Action)  {}
func (e *durableReadExecutor) Backup(id, resource string) error             { return nil }
func (e *durableReadExecutor) Apply(id, resource, kind string) error {
	if data, err := os.ReadFile(e.journalPath()); err == nil {
		e.applySnap = string(data)
	}
	return nil
}
func (e *durableReadExecutor) Validate(id, resource string) error {
	if data, err := os.ReadFile(e.journalPath()); err == nil {
		e.validateSnap = string(data)
	}
	if e.failValidate {
		return errors.New("validation failed (scripted)")
	}
	return nil
}
func (e *durableReadExecutor) Rollback(id, resource string) error { return nil }

// Mid-flight durability: after the executor's Apply returns success, the
// on-disk record already carries the APPLIED status and the canonical
// intended-specification hash — evidence that survives a crash at any
// later point.
func TestExecutePersistsAppliedBoundaryDurably(t *testing.T) {
	ex := &durableReadExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: ex},
	}, nil)
	ex.journalPath = func() string {
		records, err := o.Journal.Records()
		if err != nil || len(records) == 0 {
			return filepath.Join(o.Journal.Dir, "none.json")
		}
		return filepath.Join(o.Journal.Dir, records[0].TransactionID+".json")
	}
	p := o.Prepare(fail2banConfig(), rootOn())
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s (%v)", out.Stage, out.Blockers)
	}
	// The engine's validate-time snapshot (taken after the durable APPLIED
	// write, before the terminal finalize) must show the progress.
	if !strings.Contains(ex.validateSnap, `"status": "APPLIED"`) {
		t.Fatalf("APPLIED not durable at validate boundary: %s", ex.validateSnap)
	}
	if !strings.Contains(ex.validateSnap, `"spec_hash"`) {
		t.Fatalf("intended-spec evidence not durable at validate boundary: %s", ex.validateSnap)
	}
	// The engine's apply-time snapshot (taken inside Apply, before the
	// APPLIED write) must still show the honest pre-state: PENDING.
	if !strings.Contains(ex.applySnap, `"status": "PENDING"`) {
		t.Fatalf("pre-apply record must be PENDING: %s", ex.applySnap)
	}
	if strings.Contains(ex.applySnap, `"status": "APPLIED"`) {
		t.Fatal("APPLIED must not be durable before the apply boundary returned")
	}
}

// Spec hashes at Begin: the durable record from a completed transaction
// carries the canonical intended-specification hash for every mutating
// action (state.ActionSpecHash domain).
func TestExecuteJournalsCanonicalSpecHashes(t *testing.T) {
	ex := &durableReadExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{makeDiscovery(false), makeDiscovery(false), makeDiscovery(true)}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: ex},
	}, nil)
	ex.journalPath = func() string {
		records, err := o.Journal.Records()
		if err != nil || len(records) == 0 {
			return filepath.Join(o.Journal.Dir, "none.json")
		}
		return filepath.Join(o.Journal.Dir, records[0].TransactionID+".json")
	}
	p := o.Prepare(fail2banConfig(), rootOn())
	want, err := state.ActionSpecHash(p.Plan.Actions[0])
	if err != nil {
		t.Fatal(err)
	}
	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	if _, err := o.Execute(p, conf, nil); err != nil {
		t.Fatal(err)
	}
	records, err := o.Journal.Records()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range records {
		for _, a := range r.Actions {
			if a.SpecHash == want.Hex() {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("canonical spec hash %s not journaled: %+v", want.Hex(), records)
	}
}

// Fault injection (§49): the executor's mutation succeeds, but the durable
// APPLIED write fails (sink error). The engine must fail the action
// conservatively — the action is rolled back and marked ROLLBACK_FAILED
// (the revert happened but its durable proof failed) — so the transaction
// never continues as if durable proof existed.
type sinkFaultExecutor struct {
	failBackup bool
	calls      []string
}

func (e *sinkFaultExecutor) Backup(id, resource string) error {
	e.calls = append(e.calls, "backup")
	return nil
}
func (e *sinkFaultExecutor) Apply(id, resource, kind string) error {
	e.calls = append(e.calls, "apply")
	return nil
}
func (e *sinkFaultExecutor) Validate(id, resource string) error {
	e.calls = append(e.calls, "validate")
	return nil
}
func (e *sinkFaultExecutor) Rollback(id, resource string) error {
	e.calls = append(e.calls, "rollback")
	return nil
}

func TestEngineAppliedProgressFailureFailsClosed(t *testing.T) {
	ex := &sinkFaultExecutor{}
	sinkErr := errors.New("disk full (injected)")
	engine := apply.Engine{
		Executor: ex,
		Progress: func(event apply.ProgressEvent, actionID string) error {
			if event == apply.ProgressApplied {
				return sinkErr
			}
			return nil
		},
	}
	tr := engine.Apply(state.Plan{
		SchemaVersion: state.SchemaVersion,
		Actions: []state.Action{{
			ID: "a1", Resource: "service.x.service", Kind: state.ActionService, Ownership: state.Owned,
			Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "x.service", Operation: "restart", ExpectedState: "active"}},
		}},
	}, preflightGate{pf: state.Preflight{Status: state.PreflightReady}})
	if tr.Status != apply.StatusRolledBack {
		t.Fatalf("status=%s (%v), want rolled back", tr.Status, tr.Error)
	}
	vis := false
	for _, ar := range tr.Actions {
		if strings.Contains(ar.Error, sinkErr.Error()) {
			vis = true
		}
		if ar.Status == "ROLLBACK_FAILED" {
			vis = true
		}
	}
	if !vis {
		t.Fatalf("lost durable proof must be visible: %+v", tr.Actions)
	}
	rb := 0
	for _, c := range ex.calls {
		if c == "rollback" {
			rb++
		}
	}
	if rb == 0 {
		t.Fatalf("rollback must have run: %v", ex.calls)
	}
}
