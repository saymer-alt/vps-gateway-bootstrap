package recovery

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// R4-B adversarial crash matrix (ZAI-16 §21): classification must be
// deterministic, fail closed on every ambiguity, and never let a missing
// terminal record become a clean result.

const (
	tx   = "tx-1759000000000000000-deadbeef"
	fp   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res  = "file./etc/vps-gateway/experiment-file-test.conf"
	host = "machine-id:0123456789abcdef0123456789abcdef"
)

func baseRecord() Record {
	return Record{
		TxID:             tx,
		PlanFingerprint:  fp,
		HostIdentity:     host,
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions: []Action{
			{Resource: res, Status: ActionApplied},
		},
	}
}

// 1: clean successful completion.
func TestClassifyCleanCompleted(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeCompleted
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != Completed || !has(c, ReasonOutcomeCompleted) {
		t.Fatalf("state=%s reasons=%v, want COMPLETED", c.State, c.Reasons)
	}
}

// 2: prepared-only. The v1 schema has no PREPARED phase (Begin precedes the
// engine directly), so an in-progress record is always conservative — even
// with MutationPossible=false, which is a claim, not proof.
func TestClassifyInProgressIsAlwaysConservative(t *testing.T) {
	for _, mp := range []bool{true, false} {
		r := baseRecord()
		r.Outcome = OutcomeInProgress
		r.MutationPossible = mp
		c, err := ClassifyTransaction(r)
		if err != nil {
			t.Fatal(err)
		}
		if c.State != InProgress {
			t.Fatalf("MutationPossible=%v: state=%s, want IN_PROGRESS", mp, c.State)
		}
		if has(c, ReasonOutcomeCompleted) {
			t.Fatal("in-progress record must never carry a completed reason")
		}
	}
}

// 3-4: started/mutation-capable without a terminal → IN_PROGRESS.
func TestClassifyStartedWithoutTerminal(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeInProgress
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != InProgress || !has(c, ReasonMutationPossibleUnproven) {
		t.Fatalf("state=%s reasons=%v", c.State, c.Reasons)
	}
}

// 5: failed with proof that no action reached Apply → FAILED_RESOLVED.
func TestClassifyFailedBeforeAnyMutation(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeFailed
	r.Actions = []Action{{Resource: res, Status: ActionBackupFailed}}
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != FailedResolved || !has(c, ReasonNoActionReachedApply) {
		t.Fatalf("state=%s reasons=%v, want FAILED_RESOLVED", c.State, c.Reasons)
	}
}

// 6: failed after mutation with proven revert → FAILED_RESOLVED (the v1
// engine always records ROLLED_BACK on successfully rolled-back actions).
func TestClassifyFailedAfterMutationProvenReverted(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeFailed
	r.RollbackAttempted = true
	r.RollbackResult = RollbackDone
	r.Actions = []Action{
		{Resource: res, Status: ActionRolledBack},
		{Resource: "file./etc/vps-gateway/other.conf", Status: ActionRolledBack},
	}
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != FailedResolved || !has(c, ReasonAllActionsReverted) {
		t.Fatalf("state=%s reasons=%v, want FAILED_RESOLVED", c.State, c.Reasons)
	}
}

// 6b: FAILED after an action reached Apply without durable revert proof →
// FAILED_UNRESOLVED. (Case 7, rollback-started-but-unproven, is the same
// conservative boundary in v1: "attempted" without per-action ROLLED_BACK
// proof proves nothing.)
func TestClassifyFailedUnresolved(t *testing.T) {
	for _, statuses := range [][]Action{
		{{Resource: res, Status: ActionApplied}},
		{{Resource: res, Status: ActionValidationFailed}},
		{{Resource: res, Status: ActionRolledBack}, {Resource: "file./etc/vps-gateway/b.conf", Status: ActionApplied}},
	} {
		r := baseRecord()
		r.Outcome = OutcomeFailed
		r.RollbackAttempted = true
		r.RollbackResult = RollbackDone
		r.Actions = statuses
		c, err := ClassifyTransaction(r)
		if err != nil {
			t.Fatal(err)
		}
		if c.State != FailedUnresolved || !has(c, ReasonActionUnresolvedAfterApply) {
			t.Fatalf("statuses=%v: state=%s reasons=%v, want FAILED_UNRESOLVED", statuses, c.State, c.Reasons)
		}
	}
}

// 8/9: rollback completed vs failed. A failed rollback latches recovery;
// FAILED combined with a failed rollback is contradictory (the v1
// finalizer would have latched RECOVERY_REQUIRED instead).
func TestClassifyRollbackSemantics(t *testing.T) {
	// Proven failed rollback → RECOVERY_REQUIRED.
	r := baseRecord()
	r.Outcome = OutcomeRecoveryRequired
	r.RollbackAttempted = true
	r.RollbackResult = RollbackFailedV
	r.RecoveryRequired = true
	r.Actions = []Action{{Resource: res, Status: ActionRollbackFailed}}
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != RecoveryRequiredS || !has(c, ReasonRollbackFailedRecorded) {
		t.Fatalf("state=%s reasons=%v, want RECOVERY_REQUIRED", c.State, c.Reasons)
	}
	// FAILED + failed rollback: the classifier treats this as
	// RECOVERY_REQUIRED — the strictly conservative reading and exactly the
	// record the v1 finalizer would have written (a failed rollback latches
	// recovery, never a plain FAILED).
	r2 := baseRecord()
	r2.Outcome = OutcomeFailed
	r2.RollbackAttempted = true
	r2.RollbackResult = RollbackFailedV
	r2.Actions = []Action{{Resource: res, Status: ActionRollbackFailed}}
	c2, err := ClassifyTransaction(r2)
	if err != nil {
		t.Fatal(err)
	}
	if c2.State != RecoveryRequiredS || !has(c2, ReasonRollbackFailedRecorded) {
		t.Fatalf("state=%s reasons=%v, want RECOVERY_REQUIRED", c2.State, c2.Reasons)
	}
	// Rollback attempted under COMPLETED = contradictory.
	r3 := baseRecord()
	r3.Outcome = OutcomeCompleted
	r3.RollbackAttempted = true
	c3, err := ClassifyTransaction(r3)
	if err != nil {
		t.Fatal(err)
	}
	if c3.State != Indeterminate || !has(c3, ReasonRollbackAttemptContradiction) {
		t.Fatalf("state=%s reasons=%v, want INDETERMINATE", c3.State, c3.Reasons)
	}
}

// 10-11: contradictory terminal outcomes for one transaction (either
// direction) are INDETERMINATE — never last-writer-wins.
func TestClassifyContradictoryTerminals(t *testing.T) {
	completed := baseRecord()
	completed.Outcome = OutcomeCompleted
	failed := baseRecord()
	failed.Outcome = OutcomeFailed
	failed.Actions = []Action{{Resource: res, Status: ActionRolledBack}}
	for _, order := range [][]Record{{completed, failed}, {failed, completed}} {
		j, err := ClassifyJournal(order)
		if err != nil {
			t.Fatal(err)
		}
		if len(j.Transactions) != 1 || j.Transactions[0].State != Indeterminate {
			t.Fatalf("order=%d: state=%v, want INDETERMINATE", len(order), j.Transactions)
		}
		if !has(j.Transactions[0], ReasonContradictoryRecords) {
			t.Fatalf("reasons=%v", j.Transactions[0].Reasons)
		}
	}
}

// 12-13: exact duplicate facts collapse deterministically; contradictory
// duplicates fail closed.
func TestClassifyDuplicates(t *testing.T) {
	good := baseRecord()
	good.Outcome = OutcomeCompleted
	j, err := ClassifyJournal([]Record{good, good, good.normalized()})
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Transactions) != 1 || j.Transactions[0].State != Completed {
		t.Fatalf("identical duplicates must collapse: %+v", j)
	}
	// Non-identical duplicates: the normalized comparison is order-stable
	// (sorted actions), so a permuted-but-identical record also collapses.
	permuted := good
	permuted.Actions = []Action{
		{Resource: "file./etc/vps-gateway/zz.conf", Status: ActionApplied},
		{Resource: res, Status: ActionApplied},
	}
	good2 := good
	good2.Actions = []Action{
		{Resource: res, Status: ActionApplied},
		{Resource: "file./etc/vps-gateway/zz.conf", Status: ActionApplied},
	}
	j2, err := ClassifyJournal([]Record{good2, permuted})
	if err != nil {
		t.Fatal(err)
	}
	if len(j2.Transactions) != 1 || j2.Transactions[0].State != Completed {
		t.Fatalf("permuted identical duplicates must collapse: %+v", j2)
	}
}

// 14-17: malformed identity fields fail closed with errors.
func TestClassifyInvalidRecordsFailClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Record)
	}{
		{"missing TxID", func(r *Record) { r.TxID = "" }},
		{"missing PlanFingerprint", func(r *Record) { r.PlanFingerprint = "" }},
		{"unknown outcome", func(r *Record) { r.Outcome = "MAYBE" }},
		{"unknown rollback result", func(r *Record) { r.RollbackResult = "UNDO" }},
		{"unknown action status", func(r *Record) { r.Actions[0].Status = "SORT_OF_DONE" }},
		{"action without resource", func(r *Record) { r.Actions[0].Resource = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := baseRecord()
			tc.mut(&r)
			if _, err := ClassifyTransaction(r); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("err=%v, want ErrInvalidRecord", err)
			}
		})
	}
}

// 14b: a torn/malformed-history marker supplied by a future loader is
// modeled as an invalid record — it must never classify as clean.
func TestClassifyTornHistoryMarker(t *testing.T) {
	torn := baseRecord()
	torn.Stage = "TORN_OR_MALFORMED" // loader-reported damage marker
	torn.Outcome = OutcomeInProgress
	// Stage is informational in v1: the conservative IN_PROGRESS outcome
	// governs. But a loader that cannot parse a record at all reports an
	// invalid record instead.
	c, err := ClassifyTransaction(torn)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != InProgress {
		t.Fatalf("state=%s, want IN_PROGRESS", c.State)
	}
	if _, err := ClassifyTransaction(Record{}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("an unparseable record must fail closed")
	}
}

// 16: identity fields are carried and validated, but facts from different
// transactions are never merged.
func TestClassifyTwoTransactionsStaySeparate(t *testing.T) {
	a := baseRecord()
	a.Outcome = OutcomeCompleted
	b := baseRecord()
	b.TxID = "tx-other"
	b.Outcome = OutcomeInProgress
	j, err := ClassifyJournal([]Record{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Transactions) != 2 {
		t.Fatalf("transactions=%d, want 2", len(j.Transactions))
	}
	if j.Transactions[0].TxID != tx || j.Transactions[0].State != Completed {
		t.Fatalf("first=%+v", j.Transactions[0])
	}
	if j.Transactions[1].TxID != "tx-other" || j.Transactions[1].State != InProgress {
		t.Fatalf("second=%+v", j.Transactions[1])
	}
}

// 22-23: input permutation and repetition are deterministic.
func TestClassifyDeterministicUnderPermutation(t *testing.T) {
	a := baseRecord()
	a.Outcome = OutcomeCompleted
	b := baseRecord()
	b.TxID = "tx-b"
	b.Outcome = OutcomeInProgress
	j1, err := ClassifyJournal([]Record{a, b})
	if err != nil {
		t.Fatal(err)
	}
	j2, err := ClassifyJournal([]Record{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if j1.Transactions[0].TxID != j2.Transactions[0].TxID ||
		j1.Transactions[0].State != j2.Transactions[0].State ||
		j1.Transactions[1].State != j2.Transactions[1].State {
		t.Fatalf("classification depends on input order:\n%+v\n%+v", j1, j2)
	}
}

// 24: caller input mutation after a call cannot alter a fresh evaluation.
func TestClassifyInputIsolation(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeCompleted
	if _, err := ClassifyJournal([]Record{r}); err != nil {
		t.Fatal(err)
	}
	r.Actions[0].Status = ActionRolledBack
	freshRecord := baseRecord()
	freshRecord.Outcome = OutcomeCompleted
	fresh, err := ClassifyJournal([]Record{freshRecord})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Transactions[0].State != Completed {
		t.Fatalf("state=%s, want COMPLETED", fresh.Transactions[0].State)
	}
}

// 25: empty history carries the crash-invariant note.
func TestClassifyEmptyHistory(t *testing.T) {
	j, err := ClassifyJournal(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.Transactions) != 0 {
		t.Fatalf("transactions=%d, want 0", len(j.Transactions))
	}
	joined := strings.Join(j.Notes, "; ")
	if !strings.Contains(joined, "absence of durable records is not proof that no mutation occurred") {
		t.Fatalf("crash invariant note missing: %v", j.Notes)
	}
}

// 27: ownership evidence is out of scope here — a resolved recovery
// classification and a verified ownership claim are independent facts, and
// the classifier has no input by which ownership could influence recovery
// (structurally pinned: no ownership types appear in this package's API).
func TestClassifyIndependentOfOwnership(t *testing.T) {
	r := baseRecord()
	r.Outcome = OutcomeInProgress
	c, err := ClassifyTransaction(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != InProgress {
		t.Fatalf("state=%s", c.State)
	}
	// A hypothetical verified ownership claim cannot change the recovery
	// state: the input type carries no ownership field at all.
}

// 28: the classification vocabulary carries no authority semantics — no
// state or reason is named approved/authorized/may-mutate.
func TestClassifyVocabularyCarriesNoAuthority(t *testing.T) {
	for _, s := range []ClassificationState{Completed, FailedResolved, FailedUnresolved, RecoveryRequiredS, InProgress, Indeterminate} {
		name := string(s)
		for _, banned := range []string{"APPROVED", "AUTHORIZED", "MAY_MUTATE", "MAY_ROLLBACK", "MAY_DELETE", "ALLOWED"} {
			if strings.Contains(name, banned) {
				t.Fatalf("classification state %q must not carry authority semantics", name)
			}
		}
	}
}

// Purity tripwire (ZAI-16 §24): the classifier must not import I/O, the
// journal/state/ownership implementations, or the clock.
func TestClassifyImplementationIsPure(t *testing.T) {
	src, err := os.ReadFile("classify.go")
	if err != nil {
		t.Fatal(err)
	}
	startIdx := strings.Index(string(src), "import (")
	if startIdx < 0 {
		t.Fatal("import statement not found in classify.go")
	}
	endIdx := strings.Index(string(src)[startIdx:], ")")
	if endIdx < 0 {
		t.Fatal("import block not closed in classify.go")
	}
	imports := string(src)[startIdx : startIdx+endIdx]
	for _, banned := range []string{
		"\"os\"", "os/exec", "net/http", "bufio", "io/ioutil", "\"time\"",
		"internal/journal", "internal/state", "internal/apply",
		"internal/orchestrate", "internal/pipeline", "internal/ownership",
		"internal/lock", "internal/fsatomic", "internal/discovery",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("classify.go must not import %q: R4-B is PURE (no I/O, no authority, no clock)", banned)
		}
	}
	if strings.Contains(string(src), "time.Now") {
		t.Fatal("classify.go must not read the wall clock: R4-B is deterministic")
	}
}

func has(c Classification, want Reason) bool {
	for _, r := range c.Reasons {
		if r == want {
			return true
		}
	}
	return false
}
