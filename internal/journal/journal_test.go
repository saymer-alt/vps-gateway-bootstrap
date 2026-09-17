package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func testRecord(id string) *Record {
	return &Record{
		TransactionID:    id,
		PlanFingerprint:  "fp-" + id,
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions:          []ActionRecord{{ID: "a1", Resource: "service.x.service", Kind: string(state.ActionService), RetryClass: RetrySafe, Status: "PENDING"}},
	}
}

func TestBeginDurablyCreatesRecordBeforeUse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	rec := testRecord("tx-1")
	if err := j.Begin(rec); err != nil { t.Fatal(err) }
	if _, err := os.Stat(filepath.Join(dir, "tx-1.json")); err != nil {
		t.Fatalf("record file missing after Begin: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "tx-1.json"))
	if json.Valid(raw) == false { t.Fatal("record is not valid JSON") }
	if rec.SchemaVersion != SchemaVersion { t.Fatal("schema version not stamped") }

	if err := j.Update(rec); err != nil { t.Fatal(err) }
	parsed, err := j.loadAll()
	if err != nil { t.Fatal(err) }
	if len(parsed) != 1 || parsed[0].TransactionID != "tx-1" { t.Fatalf("records=%v", parsed) }
}

func TestNewTransactionIDUnique(t *testing.T) {
	now := time.Unix(1758000000, 0)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := NewTransactionID(now)
		if seen[id] { t.Fatalf("duplicate transaction id %s", id) }
		seen[id] = true
	}
}

func TestClassifyRetryClosedMap(t *testing.T) {
	safe := map[state.ActionKind]bool{
		state.ActionCreateFile: true, state.ActionUpdateFile: true,
		state.ActionDeleteOwnedFile: true, state.ActionService: true,
	}
	for kind := range safe {
		if cls, err := ClassifyRetry(kind); err != nil || cls != RetrySafe {
			t.Fatalf("kind %s: class=%q err=%v", kind, cls, err)
		}
	}
	for _, kind := range []state.ActionKind{state.ActionSSH, state.ActionReboot} {
		if cls, err := ClassifyRetry(kind); err != nil || cls != StagedRecovery {
			t.Fatalf("kind %s: class=%q err=%v", kind, cls, err)
		}
	}
	for _, kind := range []state.ActionKind{state.ActionSSHFinalize, state.ActionFirewall, state.ActionRouting, state.ActionInstaller} {
		if cls, err := ClassifyRetry(kind); err != nil || cls != NoAutonomousRetry {
			t.Fatalf("kind %s: class=%q err=%v", kind, cls, err)
		}
	}
	// Unknown mutating kinds fail closed: no silent retryable default.
	if _, err := ClassifyRetry(state.ActionKind("SOMETHING_NEW")); err == nil {
		t.Fatal("unknown mutating kind must fail closed")
	}
}

func TestBlockingRecordsFamilies(t *testing.T) {
	j := &Journal{Dir: filepath.Join(t.TempDir(), "journal")}

	done := testRecord("tx-done")
	done.Outcome = OutcomeCompleted
	if err := j.Begin(done); err != nil { t.Fatal(err) }
	blocked, err := j.BlockingRecords()
	if err != nil || len(blocked) != 0 { t.Fatalf("completed record must not block: %v %v", blocked, err) }

	recovery := testRecord("tx-recovery")
	recovery.Outcome = OutcomeRecoveryRequired
	recovery.RecoveryRequired = true
	if err := j.Begin(recovery); err != nil { t.Fatal(err) }
	crashed := testRecord("tx-crashed")
	crashed.Outcome = "" // in progress: crash left no final outcome
	if err := j.Begin(crashed); err != nil { t.Fatal(err) }

	blocked, err = j.BlockingRecords()
	if err != nil { t.Fatal(err) }
	if len(blocked) != 2 { t.Fatalf("want recovery+crashed blocking, got %v", blocked) }
}

func TestPersistenceBlockersFamilies(t *testing.T) {
	j := &Journal{Dir: filepath.Join(t.TempDir(), "journal")}

	failedPostMutation := testRecord("tx-failed-post")
	failedPostMutation.Outcome = OutcomeFailed
	// MutationPossible stays true: the transaction reached the engine.
	if err := j.Begin(failedPostMutation); err != nil { t.Fatal(err) }

	// A mutating run is not blocked by a clean FAILED record (hybrid retry).
	if blockers, err := j.PersistenceBlockers("tx-new", true); err != nil || len(blockers) != 0 {
		t.Fatalf("mutating rerun must not be blocked by failed-rolled-back history: %v %v", blockers, err)
	}
	// A NO-mutation run IS blocked: no autonomous NO_CHANGE laundering.
	blockers, err := j.PersistenceBlockers("tx-new", false)
	if err != nil || len(blockers) != 1 { t.Fatalf("no-mutation persistence must be blocked: %v %v", blockers, err) }

	// A recovery-required record blocks persistence for both run shapes.
	recovery := testRecord("tx-recovery")
	recovery.Outcome = OutcomeRecoveryRequired
	recovery.RecoveryRequired = true
	if err := j.Begin(recovery); err != nil { t.Fatal(err) }
	if blockers, err := j.PersistenceBlockers("tx-new", true); err != nil || len(blockers) != 1 {
		t.Fatalf("recovery must block mutating persistence: %v %v", blockers, err)
	}
	if blockers, err := j.PersistenceBlockers("tx-new", false); err != nil || len(blockers) != 2 {
		t.Fatalf("recovery + failed history must block no-mutation persistence: %v %v", blockers, err)
	}

	// The current transaction's own record never blocks itself.
	if blockers, err := j.PersistenceBlockers("tx-recovery", true); err != nil || len(blockers) != 0 {
		t.Fatalf("own record must be excluded: %v %v", blockers, err)
	}

	// A corrupt record fails closed.
	if err := os.WriteFile(filepath.Join(j.Dir, "tx-broken.json"), []byte("{broken"), 0600); err != nil { t.Fatal(err) }
	if _, err := j.PersistenceBlockers("tx-new", true); err == nil { t.Fatal("corrupt journal record must fail closed") }
	if _, err := j.BlockingRecords(); err == nil { t.Fatal("corrupt journal record must fail closed") }
}
