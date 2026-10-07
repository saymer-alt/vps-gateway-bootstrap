package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// Observed postcondition hash persistence (ZAI-59 / J4). The field means
// exactly one thing — an independently observed semantic spec hash of the
// live resource after the action's mutation/validation leg — and every
// honesty boundary below is pinned here: Begin never initializes it, the
// typed write API refuses zero/unknown/ambiguous/terminal targets, the
// recorded proof is write-once (same-value replay idempotent, different
// value a conflict), mismatch is representable, absence is absence,
// malformed persisted proof fails the whole load closed, and Blocking
// semantics are untouched.

func observedHash(s string) ownership.SpecHash {
	h, err := ownership.ParseSpecHashHex(s)
	if err != nil {
		panic(err)
	}
	return h
}

const (
	hashX = "1111111111111111111111111111111111111111111111111111111111111111"
	hashY = "2222222222222222222222222222222222222222222222222222222222222222"
)

func observedTestRecord(txID string) *Record {
	return &Record{
		SchemaVersion:    SchemaVersion,
		TransactionID:    txID,
		PlanFingerprint:  "fp-" + txID,
		Stage:            "MUTATING",
		MutationPossible: true,
		Actions:          []ActionRecord{{ID: "a1", Resource: "mss-rule.vpsgw_in/muvg443", Kind: "MSS_RULE", RetryClass: NoAutonomousRetry, Status: "PENDING"}},
	}
}

func loadOneRecord(t *testing.T, dir, txID string) Record {
	t.Helper()
	recs, err := (&Journal{Dir: dir}).Records()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.TransactionID == txID {
			return r
		}
	}
	t.Fatalf("no record %s in %s", txID, dir)
	return Record{}
}

// Begin leaves the observed hash absent — structurally (zero value) and
// in the durable bytes (no JSON key at all): no API derives an observed
// hash from the intended one (anti-laundering, ZAI-59 §19).
func TestObservedHashBeginLeavesAbsent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	rec := observedTestRecord("tx-begin")
	rec.Actions[0].SpecHash = hashX
	if err := j.Begin(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Actions[0].ObservedSpecHash != "" {
		t.Fatal("Begin must not initialize the observed hash")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "tx-begin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	actions := doc["actions"].([]any)
	first := actions[0].(map[string]any)
	if _, present := first["observed_spec_hash"]; present {
		t.Fatal("durable Begin record must carry no observed_spec_hash key")
	}
	if _, present := first["spec_hash"]; !present {
		t.Fatal("the intended hash must still be recorded at Begin")
	}
}

// Write → persists → reloads byte-identical through a fresh Journal.
func TestObservedHashWritePersistsAndReloads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-w")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-w", "a1", "mss-rule.vpsgw_in/muvg443", observedHash(hashX)); err != nil {
		t.Fatal(err)
	}
	got := loadOneRecord(t, dir, "tx-w")
	if got.Actions[0].ObservedSpecHash != hashX {
		t.Fatalf("observed hash not persisted: %q", got.Actions[0].ObservedSpecHash)
	}
	// A fresh reader over the same directory sees the same value.
	again := loadOneRecord(t, dir, "tx-w")
	if again.Actions[0].ObservedSpecHash != hashX {
		t.Fatalf("reloaded observed hash differs: %q", again.Actions[0].ObservedSpecHash)
	}
}

// Same-value replay is idempotent success and does NOT rewrite the
// durable record (no UpdatedAt churn, no silent proof rewriting).
func TestObservedHashReplayIdempotentNoRewrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-idem")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-idem", "a1", "", observedHash(hashX)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "tx-idem.json"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond) // UpdatedAt would differ if rewritten
	if err := j.RecordObservedSpecHash("tx-idem", "a1", "", observedHash(hashX)); err != nil {
		t.Fatalf("same-hash replay must succeed idempotently: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(dir, "tx-idem.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("idempotent replay must not rewrite the durable record")
	}
}

// A different observed hash is refused as a conflict; the durable proof
// stays the originally recorded one.
func TestObservedHashRewriteRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-rw")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-rw", "a1", "", observedHash(hashX)); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-rw", "a1", "", observedHash(hashY)); err == nil {
		t.Fatal("different-hash rewrite must be refused")
	}
	got := loadOneRecord(t, dir, "tx-rw")
	if got.Actions[0].ObservedSpecHash != hashX {
		t.Fatalf("durable proof must stay the original: %q", got.Actions[0].ObservedSpecHash)
	}
}

// A zero hash is refused and nothing is recorded.
func TestObservedHashZeroRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-zero")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-zero", "a1", "", ownership.SpecHash{}); err == nil {
		t.Fatal("zero observed hash must be refused")
	}
	got := loadOneRecord(t, dir, "tx-zero")
	if got.Actions[0].ObservedSpecHash != "" {
		t.Fatalf("refused write must leave absence: %q", got.Actions[0].ObservedSpecHash)
	}
}

func TestObservedHashUnknownTransactionRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-real")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-missing", "a1", "", observedHash(hashX)); err == nil {
		t.Fatal("unknown transaction must be refused")
	}
}

func TestObservedHashUnknownActionRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-act")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-act", "no-such-action", "", observedHash(hashX)); err == nil {
		t.Fatal("unknown action must be refused")
	}
}

// A supplied resource coordinate must match the durable one; an empty
// coordinate skips the leg.
func TestObservedHashResourceCoordinateBinding(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-res")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-res", "a1", "mss-rule.other/x", observedHash(hashX)); err == nil {
		t.Fatal("wrong resource coordinate must be refused")
	}
	if err := j.RecordObservedSpecHash("tx-res", "a1", "mss-rule.vpsgw_in/muvg443", observedHash(hashX)); err != nil {
		t.Fatalf("matching resource coordinate must be accepted: %v", err)
	}
}

// An ambiguous action id (duplicate ids inside one record) is refused —
// never resolved by position.
func TestObservedHashAmbiguousActionRefused(t *testing.T) {
	dir := t.TempDir()
	rec := observedTestRecord("tx-amb")
	rec.Actions = append(rec.Actions, rec.Actions[0])
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tx-amb.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	j := &Journal{Dir: dir}
	if err := j.RecordObservedSpecHash("tx-amb", "a1", "", observedHash(hashX)); err == nil {
		t.Fatal("ambiguous action must be refused")
	}
	got := loadOneRecord(t, dir, "tx-amb")
	if got.Actions[0].ObservedSpecHash != "" || got.Actions[1].ObservedSpecHash != "" {
		t.Fatal("refused ambiguous write must record nothing")
	}
}

// Terminal transactions refuse observed-hash writes (the J4 ordering:
// observation is established during the transaction, before the terminal
// outcome is durable — §13/§26). Every terminal outcome refuses.
func TestObservedHashTerminalRefused(t *testing.T) {
	for _, outcome := range []string{OutcomeCompleted, OutcomeFailed, OutcomeRecoveryRequired} {
		dir := filepath.Join(t.TempDir(), "journal")
		j := &Journal{Dir: dir}
		if err := j.Begin(observedTestRecord("tx-term")); err != nil {
			t.Fatal(err)
		}
		rec := loadOneRecord(t, dir, "tx-term")
		rec.Outcome = outcome
		if err := j.Update(&rec); err != nil {
			t.Fatal(err)
		}
		if err := j.RecordObservedSpecHash("tx-term", "a1", "", observedHash(hashX)); err == nil {
			t.Fatalf("terminal outcome %s must refuse observed-hash writes", outcome)
		}
		got := loadOneRecord(t, dir, "tx-term")
		if got.Actions[0].ObservedSpecHash != "" {
			t.Fatalf("refused terminal write must record nothing (outcome %s)", outcome)
		}
	}
}

// A non-mutating transaction refuses observed-hash writes: an observed
// postcondition cannot exist where no mutation was possible.
func TestObservedHashNonMutatingRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	rec := observedTestRecord("tx-nomut")
	rec.MutationPossible = false
	if err := j.Begin(rec); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-nomut", "a1", "", observedHash(hashX)); err == nil {
		t.Fatal("non-mutating transaction must refuse observed-hash writes")
	}
}

// Mismatch is representable: intended X, observed Y both survive a
// reload, distinctly. The journal records the fact; it does not decide
// success (§15).
func TestObservedHashMismatchRepresentable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	rec := observedTestRecord("tx-mm")
	rec.Actions[0].SpecHash = hashX
	if err := j.Begin(rec); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-mm", "a1", "", observedHash(hashY)); err != nil {
		t.Fatalf("recording a mismatching observed hash must be allowed as fact: %v", err)
	}
	got := loadOneRecord(t, dir, "tx-mm")
	if got.Actions[0].SpecHash != hashX || got.Actions[0].ObservedSpecHash != hashY {
		t.Fatalf("intended and observed must survive distinctly: intended=%q observed=%q", got.Actions[0].SpecHash, got.Actions[0].ObservedSpecHash)
	}
}

// Legacy v1 records load with the observed hash explicitly absent —
// absence is never upgraded, never backfilled (§24).
func TestLegacyRecordCarriesNoObservedHash(t *testing.T) {
	dir := t.TempDir()
	rec := observedTestRecord("tx-legacy")
	rec.SchemaVersion = 1
	rec.Actions[0].SpecHash = "" // v1 carried no spec hashes
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tx-legacy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadOneRecord(t, dir, "tx-legacy")
	if got.Actions[0].ObservedSpecHash != "" {
		t.Fatalf("legacy record must carry no observed hash: %q", got.Actions[0].ObservedSpecHash)
	}
}

// Malformed persisted proof fails the WHOLE load closed — never ignored,
// dropped, zeroed or repaired (§21).
func TestObservedHashMalformedFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "malformed hex",
			body: `{"schema_version":3,"transaction_id":"tx-bad","plan_fingerprint":"` + strings.Repeat("a", 64) + `","stage":"MUTATING","mutation_possible":true,"actions":[{"id":"a1","resource":"r","kind":"MSS_RULE","retry_class":"no-autonomous-retry","observed_spec_hash":"NOTAHASH"}]}`,
		},
		{
			name: "uppercase hex",
			body: `{"schema_version":3,"transaction_id":"tx-bad","plan_fingerprint":"` + strings.Repeat("a", 64) + `","stage":"MUTATING","mutation_possible":true,"actions":[{"id":"a1","resource":"r","kind":"MSS_RULE","retry_class":"no-autonomous-retry","observed_spec_hash":"` + strings.Repeat("A", 64) + `"}]}`,
		},
		{
			name: "legacy schema carrying the v3 field",
			body: `{"schema_version":2,"transaction_id":"tx-bad","plan_fingerprint":"` + strings.Repeat("a", 64) + `","stage":"MUTATING","mutation_possible":true,"actions":[{"id":"a1","resource":"r","kind":"SERVICE","retry_class":"retry-safe","observed_spec_hash":"` + hashX + `"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "tx-bad.json"), []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := (&Journal{Dir: dir}).Records(); err == nil {
				t.Fatal("malformed observed proof must fail the whole load")
			}
		})
	}
}

// The ZAI-J1 filename↔body invariant is unaffected by schema evolution:
// a record whose observed proof is well formed still fails the load when
// the filename does not match the body identity.
func TestObservedHashJ1MismatchStillRejected(t *testing.T) {
	dir := t.TempDir()
	rec := observedTestRecord("tx-body")
	rec.Actions[0].ObservedSpecHash = hashX
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tx-file.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = (&Journal{Dir: dir}).Records()
	if err == nil || !strings.Contains(err.Error(), "does not match the file name identity") {
		t.Fatalf("filename/body mismatch must still be rejected, got: %v", err)
	}
}

// Blocking semantics are untouched: an in-progress record blocks with or
// without an observed hash, and a latched record blocks regardless of any
// recorded proof (observed hash alone must never un-block a transaction).
func TestObservedHashBlockingUnaffected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	j := &Journal{Dir: dir}
	if err := j.Begin(observedTestRecord("tx-inprog")); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordObservedSpecHash("tx-inprog", "a1", "", observedHash(hashX)); err != nil {
		t.Fatal(err)
	}
	latched := observedTestRecord("tx-latch")
	latched.Outcome = OutcomeRecoveryRequired
	latched.RecoveryRequired = true
	latched.Actions[0].ObservedSpecHash = hashX
	if err := j.Begin(latched); err != nil {
		t.Fatal(err)
	}
	blockers, err := j.BlockingRecords()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, b := range blockers {
		ids[b.TransactionID] = true
	}
	if !ids["tx-inprog"] || !ids["tx-latch"] {
		t.Fatalf("blocking records must be unaffected by observed hashes: %v", ids)
	}
}

// v3 records flow the existing corroboration adapter legs unchanged: the
// intended hash still translates; the observed hash is journal-plane
// evidence and does not alter the fact vocabulary (§23: the ownership
// plane is untouched).
func TestObservedHashV3CorroborationFactUnchanged(t *testing.T) {
	dir := t.TempDir()
	rec := observedTestRecord("tx-v3")
	rec.HostIdentity = "machine-id:" + strings.Repeat("0", 32)
	rec.Actions[0].SpecHash = hashX
	rec.Actions[0].Status = "APPLIED"
	rec.Actions[0].ObservedSpecHash = hashY
	rec.Outcome = OutcomeCompleted
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tx-v3.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded := loadOneRecord(t, dir, "tx-v3")
	fact, err := loaded.CorroborationFact()
	if err != nil {
		t.Fatalf("v3 record must translate: %v", err)
	}
	if len(fact.Actions) != 1 || fact.Actions[0].SpecHash == nil || fact.Actions[0].SpecHash.Hex() != hashX {
		t.Fatalf("intended hash leg must translate unchanged: %+v", fact.Actions)
	}
}
