package orchestrate

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// R5-B first-slice test matrix (ZAI-30 §88). The reconstruction pure core
// reuses the O5-E1 mint verbatim; these tests pin the equivalence, the
// ordering contract, every fail-closed skip, and the test-only composition
// chain through Corroborate and DeriveVerdict.

var t0 = time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)

// reconAction builds one file action (plan form) for a record.
func reconAction(id, path, content string, kind state.ActionKind) state.Action {
	return state.Action{ID: id, Resource: "file." + path, Kind: kind, Ownership: state.Owned,
		Spec: &state.ActionSpec{File: &state.FileActionSpec{Path: path, Content: content, Mode: 0o600}}}
}

// reconRecord builds a journal record for the given actions, with the
// ZAI-29 mint-time invariants: per-action SpecHash, statuses applied.
func reconRecord(t *testing.T, txID string, started time.Time, statuses map[string]string, actions ...state.Action) *journal.Record {
	t.Helper()
	rec := &journal.Record{
		SchemaVersion:   journal.SchemaVersion,
		TransactionID:   txID,
		HostIdentity:    evHost,
		PlanFingerprint: "fp-" + txID,
		StartedAt:       started,
		Stage:           StageCompleted,
		Outcome:         journal.OutcomeCompleted,
	}
	for _, a := range actions {
		h, err := state.ActionSpecHash(a)
		if err != nil {
			t.Fatal(err)
		}
		status := statuses[a.ID]
		if status == "" {
			status = "APPLIED"
		}
		rec.Actions = append(rec.Actions, journal.ActionRecord{
			ID: a.ID, Resource: a.Resource, Kind: string(a.Kind), Status: status, SpecHash: h.Hex(),
		})
	}
	return rec
}

func mustMint(t *testing.T, rec *journal.Record) []state.EvidenceRecord {
	t.Helper()
	out, err := MintTransactionEvidence(rec, mustSynthPlan(t, rec), nil)
	if err != nil {
		t.Fatal(err)
	}
	return out.Minted
}

func mustSynthPlan(t *testing.T, rec *journal.Record) state.Plan {
	t.Helper()
	p, err := synthesizedMintPlan(rec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustSerialize(t *testing.T, records []journal.Record) string {
	t.Helper()
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustSerializeEvidence(e []state.EvidenceRecord) string {
	b, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func osReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func reconStatuses(res Reconstruction) map[string]ReconstructionRecordStatus {
	out := map[string]ReconstructionRecordStatus{}
	for _, r := range res.Records {
		out[r.TxID] = r.Status
	}
	return out
}

func reconReasons(res Reconstruction) map[string]string {
	out := map[string]string{}
	for _, r := range res.Records {
		out[r.TxID] = r.Reason
	}
	return out
}

// 1/2: valid COMPLETED CREATE and UPDATE records reconstruct.
func TestReconstructCreateAndUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind state.ActionKind
	}{
		{"create", state.ActionCreateFile},
		{"update", state.ActionUpdateFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := reconAction("a1", evPath, "content\n", tc.kind)
			rec := reconRecord(t, "tx-1", t0, nil, a)
			res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Claims) != 1 {
				t.Fatalf("claims=%d (%+v)", len(res.Claims), res)
			}
			c := res.Claims[0]
			if c.Identity.Path != evPath || c.TxID != "tx-1" || c.HostIdentity != evHost || c.PlanFingerprint != "fp-tx-1" {
				t.Fatalf("claim provenance wrong: %+v", c)
			}
			if !c.MintedAt.Equal(t0) {
				t.Fatalf("MintedAt must be the journal StartedAt: %s", c.MintedAt)
			}
			if st := reconStatuses(res)["tx-1"]; st != RecordReconstructed {
				t.Fatalf("record status %s", st)
			}
		})
	}
}

// 3/§67: a hostless COMPLETED record reconstructs nothing.
func TestReconstructHostlessRecord(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	rec.HostIdentity = ""
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("hostless record must reconstruct nothing: %+v", res.Claims)
	}
	if reconReasons(res)["tx-1"] != SkipHostless {
		t.Fatalf("reason=%s", reconReasons(res)["tx-1"])
	}
}

// 4/5/6/§61/§62: FAILED, RECOVERY_REQUIRED and in-progress records
// reconstruct zero claims — even with APPLIED actions — and latched or
// failed-after-mutation records surface in the Latched diagnostics.
func TestReconstructNonTerminalRecordsFailClosed(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	cases := []struct {
		name   string
		mutate func(*journal.Record)
		reason string
		bucket bool
	}{
		{"failed-after-mutation", func(r *journal.Record) {
			r.Outcome = journal.OutcomeFailed
			r.MutationPossible = true
		}, SkipFailedOutcome, true},
		{"recovery-required", func(r *journal.Record) { r.Outcome = journal.OutcomeRecoveryRequired; r.RecoveryRequired = true }, SkipRecoveryLatched, true},
		{"latch-flag-only", func(r *journal.Record) { r.RecoveryRequired = true }, SkipRecoveryLatched, true},
		{"in-progress", func(r *journal.Record) { r.Outcome = "" }, SkipInProgress, false},
		{"failed-no-mutation", func(r *journal.Record) {
			r.Outcome = journal.OutcomeFailed
			r.MutationPossible = false
		}, SkipFailedOutcome, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := reconRecord(t, "tx-1", t0, nil, a)
			tc.mutate(rec)
			res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Claims) != 0 {
				t.Fatalf("non-terminal record must reconstruct nothing: %+v", res.Claims)
			}
			if reconReasons(res)["tx-1"] != tc.reason {
				t.Fatalf("reason=%s want %s", reconReasons(res)["tx-1"], tc.reason)
			}
			inBucket := len(res.Latched) == 1 && res.Latched[0] == "tx-1"
			if tc.bucket != inBucket {
				t.Fatalf("latched visibility=%v want %v", inBucket, tc.bucket)
			}
		})
	}
}

// 7: an APPLIED action inside a non-COMPLETED transaction reconstructs
// nothing — the per-action success never outranks the missing terminal
// proof (critical pin).
func TestReconstructAppliedActionInsideNonCompletedTransaction(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	rec.Outcome = journal.OutcomeFailed
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("APPLIED action inside a FAILED transaction must reconstruct nothing: %+v", res.Claims)
	}
}

// 8/9: non-APPLIED statuses and unsupported kinds reconstruct nothing.
func TestReconstructIneligibleActions(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	for _, status := range []string{"PENDING", "APPLY_FAILED", "VALIDATION_FAILED", "ROLLBACK_FAILED", "ROLLED_BACK"} {
		rec := reconRecord(t, "tx-1", t0, map[string]string{"a1": status}, a)
		res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Claims) != 0 {
			t.Fatalf("status %s must not reconstruct", status)
		}
	}
	// Service actions are never evidence-capable.
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x", state.ActionCreateFile))
	svc := state.Action{ID: "a2", Resource: "service.fail2ban.service", Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "fail2ban.service", Operation: "restart"}}}
	rec.Actions = nil
	sh, err := state.ActionSpecHash(svc)
	if err != nil {
		t.Fatal(err)
	}
	rec.Actions = append(rec.Actions, journal.ActionRecord{ID: "a2", Resource: svc.Resource, Kind: "SERVICE", Status: "APPLIED", SpecHash: sh.Hex()})
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("service actions must not reconstruct: %+v", res.Claims)
	}
	if st := reconStatuses(res)["tx-1"]; st != RecordZeroEligible {
		t.Fatalf("status=%s want ZERO_ELIGIBLE", st)
	}
}

// 10/11: missing and invalid spec hashes fail closed for the record.
func TestReconstructSpecHashFailures(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	rec.Actions[0].SpecHash = ""
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || reconReasons(res)["tx-1"] != SkipMintRefused {
		t.Fatalf("missing spec hash must fail closed: %+v", res.Records)
	}
	rec.Actions[0].SpecHash = "deadbeef"
	res, err = ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || reconReasons(res)["tx-1"] != SkipMintRefused {
		t.Fatalf("invalid spec hash must fail closed: %+v", res.Records)
	}
}

// 12/§40: out-of-confinement actions are skipped exactly like O5-E1.
func TestReconstructOutOfConfinementSkipped(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", "/etc/ssh/sshd_config.d/99-x.conf", "x", state.ActionCreateFile))
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("out-of-confinement action must not reconstruct: %+v", res.Claims)
	}
	if st := reconStatuses(res)["tx-1"]; st != RecordZeroEligible {
		t.Fatalf("status=%s want ZERO_ELIGIBLE (mirrors O5-E1 skip)", st)
	}
}

// 13/25/§55: an exact existing claim is idempotent — no duplicate.
func TestReconstructExactExistingClaimDeduplicates(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	first, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ReconstructEvidence([]journal.Record{*rec}, first.Claims)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Claims) != 1 {
		t.Fatalf("reconstruction must be idempotent, got %d claims", len(second.Claims))
	}
	// Feeding the same record twice is a deduplicated no-op.
	third, err := ReconstructEvidence([]journal.Record{*rec, *rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(third.Claims) != 1 {
		t.Fatalf("duplicate input records must deduplicate, got %d claims", len(third.Claims))
	}
}

// 14: the primary crash-window case — journal proves the resource, state
// has no evidence → the claim is reconstructed.
func TestReconstructMissingEvidence(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "recovered\n", state.ActionCreateFile))
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].TxID != "tx-1" {
		t.Fatalf("crash-window recovery failed: %+v", res.Claims)
	}
}

// 15/16: older state vs newer journal reconstructs forward; newer state vs
// older journal never rolls evidence backwards.
func TestReconstructOrderingAgainstPrior(t *testing.T) {
	a1 := reconAction("a1", evPath, "older\n", state.ActionUpdateFile)
	a2 := reconAction("a1", evPath, "newer\n", state.ActionUpdateFile)
	old := reconRecord(t, "tx-old", t0, nil, a1)
	new := reconRecord(t, "tx-new", t0.Add(time.Hour), nil, a2)

	// Older state + newer journal → the journal claim replaces it.
	stateClaim := mustMint(t, old)[0]
	res, err := ReconstructEvidence([]journal.Record{*new}, []state.EvidenceRecord{stateClaim})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].TxID != "tx-new" {
		t.Fatalf("newer journal must replace older state: %+v", res.Claims)
	}

	// Newer state + older journal → state is never rolled backwards.
	newClaim := mustMint(t, new)[0]
	res, err = ReconstructEvidence([]journal.Record{*old}, []state.EvidenceRecord{newClaim})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].TxID != "tx-new" {
		t.Fatalf("older journal must never roll state backwards: %+v", res.Claims)
	}
}

// 17: multiple ordered updates of one resource → the newest transaction.
func TestReconstructMultipleOrderedUpdates(t *testing.T) {
	a1 := reconAction("a1", evPath, "v1\n", state.ActionCreateFile)
	a2 := reconAction("a1", evPath, "v2\n", state.ActionUpdateFile)
	a3 := reconAction("a1", evPath, "v3\n", state.ActionUpdateFile)
	records := []journal.Record{
		*reconRecord(t, "tx-3", t0.Add(2*time.Hour), nil, a3),
		*reconRecord(t, "tx-1", t0, nil, a1),
		*reconRecord(t, "tx-2", t0.Add(time.Hour), nil, a2),
	}
	res, err := ReconstructEvidence(records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].TxID != "tx-3" {
		t.Fatalf("newest transaction must win regardless of input order: %+v", res.Claims)
	}
}

// 18/§30: equal ordering keys with different content are ambiguous →
// conflict for that identity, never a choice.
func TestReconstructEqualOrderingKeyConflict(t *testing.T) {
	a1 := reconAction("a1", evPath, "one\n", state.ActionUpdateFile)
	a2 := reconAction("a1", evPath, "two\n", state.ActionUpdateFile)
	records := []journal.Record{
		*reconRecord(t, "tx-a", t0, nil, a1),
		*reconRecord(t, "tx-b", t0, nil, a2),
	}
	res, err := ReconstructEvidence(records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("ambiguous history must reconstruct nothing: %+v", res.Claims)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0].Identity.Path != evPath {
		t.Fatalf("conflict must be typed and identity-bound: %+v", res.Conflicts)
	}
	if !strings.Contains(res.Conflicts[0].Reason, "tx-a") || !strings.Contains(res.Conflicts[0].Reason, "tx-b") {
		t.Fatalf("conflict must name the competing transactions: %s", res.Conflicts[0].Reason)
	}
}

// 20/§56: same TxID with different content is adversarial corruption —
// the whole reconstruction fails closed.
func TestReconstructSameTxIDDifferentContentFailsClosed(t *testing.T) {
	a1 := reconAction("a1", evPath, "one\n", state.ActionCreateFile)
	r1 := reconRecord(t, "tx-1", t0, nil, a1)
	r2 := reconRecord(t, "tx-1", t0, nil, a1)
	r2.PlanFingerprint = "fp-forged"
	if _, err := ReconstructEvidence([]journal.Record{*r1, *r2}, nil); err == nil {
		t.Fatal("same-TxID/different-content must fail closed")
	}
}

// 22/§60: one COMPLETED transaction reconstructs multiple eligible claims.
func TestReconstructMultiActionTransaction(t *testing.T) {
	a1 := reconAction("a1", evPath, "one\n", state.ActionCreateFile)
	a2 := reconAction("a2", "/etc/vps-gateway/two.conf", "two\n", state.ActionUpdateFile)
	a3 := reconAction("a3", evDropIn, "drop\n", state.ActionUpdateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a1, a2, a3)
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 3 {
		t.Fatalf("want 3 claims, got %d: %+v", len(res.Claims), res.Claims)
	}
}

// 23/§31: cross-host records for the same identity are separate histories
// that never merge — and conflict rather than being collapsed by choice.
func TestReconstructCrossHostConflicts(t *testing.T) {
	a := reconAction("a1", evPath, "x\n", state.ActionCreateFile)
	r1 := reconRecord(t, "tx-1", t0, nil, a)
	r2 := reconRecord(t, "tx-2", t0.Add(time.Hour), nil, a)
	r2.HostIdentity = "machine-id:ffff0000ffff0000ffff0000ffff0000"
	res, err := ReconstructEvidence([]journal.Record{*r1, *r2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 {
		t.Fatalf("cross-host claims must not merge into one plane: %+v", res.Claims)
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("cross-host same-identity must conflict: %+v", res.Conflicts)
	}
}

// 24/§35: legacy v1 records never reconstruct ownership evidence.
func TestReconstructLegacySchema(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	rec.SchemaVersion = 1
	rec.Actions[0].SpecHash = "" // v1 carried no spec hashes
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || reconReasons(res)["tx-1"] != SkipLegacySchema {
		t.Fatalf("legacy v1 must be non-reconstructable: %+v", res.Records)
	}
	// An unknown future schema version fails closed too.
	rec.SchemaVersion = 99
	res, err = ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || reconReasons(res)["tx-1"] != SkipUnknownSchema {
		t.Fatalf("unknown schema must fail closed: %+v", res.Records)
	}
}

// §63: a terminal COMPLETED record carrying rollback metadata is
// contradictory and reconstructs nothing.
func TestReconstructRollbackMetadataRefused(t *testing.T) {
	a := reconAction("a1", evPath, "x", state.ActionCreateFile)
	rec := reconRecord(t, "tx-1", t0, nil, a)
	rec.RollbackAttempted = true
	rec.RollbackResult = "ROLLED_BACK"
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 0 || reconReasons(res)["tx-1"] != SkipRollbackMetadata {
		t.Fatalf("rollback metadata must refuse reconstruction: %+v", res.Records)
	}
}

// §66: the anti-laundering shape — a latched transaction in the directory
// never blocks reconstruction of an INDEPENDENT completed record, but the
// latch is surfaced so a future persistence adapter sees what the gate
// would see.
func TestReconstructAntiLaunderingVisibility(t *testing.T) {
	good := reconRecord(t, "tx-good", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	latched := reconRecord(t, "tx-latched", t0.Add(time.Hour), nil, reconAction("a2", "/etc/vps-gateway/other.conf", "y\n", state.ActionUpdateFile))
	latched.Outcome = journal.OutcomeRecoveryRequired
	latched.RecoveryRequired = true
	res, err := ReconstructEvidence([]journal.Record{*good, *latched}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != 1 || res.Claims[0].TxID != "tx-good" {
		t.Fatalf("independent completed record must reconstruct: %+v", res.Claims)
	}
	if len(res.Latched) != 1 || res.Latched[0] != "tx-latched" {
		t.Fatalf("the latch must be visible: %+v", res.Latched)
	}
}

// 26/§52: input permutation never changes the result.
func TestReconstructDeterministicUnderPermutation(t *testing.T) {
	a1 := reconAction("a1", evPath, "v1\n", state.ActionCreateFile)
	a2 := reconAction("a1", evPath, "v2\n", state.ActionUpdateFile)
	a3 := reconAction("a3", "/etc/vps-gateway/two.conf", "x\n", state.ActionCreateFile)
	records := []journal.Record{
		*reconRecord(t, "tx-2", t0.Add(time.Hour), nil, a2),
		*reconRecord(t, "tx-3", t0.Add(2*time.Hour), nil, a3),
		*reconRecord(t, "tx-1", t0, nil, a1),
	}
	first, err := ReconstructEvidence(records, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		// Rotate the slice deterministically.
		records = append(records[1:], records[0])
		again, err := ReconstructEvidence(records, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(again.Claims) != len(first.Claims) {
			t.Fatalf("claim count changed under permutation")
		}
		for j := range again.Claims {
			if !equalEvidenceRecords(again.Claims[j], first.Claims[j]) {
				t.Fatalf("claims differ under permutation at %d", j)
			}
		}
		if len(again.Records) != len(first.Records) || len(again.Conflicts) != len(first.Conflicts) {
			t.Fatal("diagnostics changed under permutation")
		}
	}
}

// 27/§53: reconstruction never mutates its inputs.
func TestReconstructInputImmutability(t *testing.T) {
	a1 := reconAction("a1", evPath, "v1\n", state.ActionCreateFile)
	rec1 := reconRecord(t, "tx-1", t0, nil, a1)
	rec2 := reconRecord(t, "tx-2", t0.Add(time.Hour), nil, reconAction("a1", evPath, "v2\n", state.ActionUpdateFile))
	input := []journal.Record{*rec1, *rec2}
	snapshot := mustSerialize(t, input)
	prior := mustMint(t, rec1)
	priorSnapshot := mustSerializeEvidence(prior)
	if _, err := ReconstructEvidence(input, prior); err != nil {
		t.Fatal(err)
	}
	if string(mustSerialize(t, input)) != snapshot {
		t.Fatal("journal records were mutated")
	}
	if string(mustSerializeEvidence(prior)) != priorSnapshot {
		t.Fatal("prior evidence was mutated")
	}
}

// 28/§54: returned claims are fresh values — mutating the returned slice
// cannot alter a later reconstruction.
func TestReconstructOutputIsolation(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	first, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first.Claims[0].SpecHash = strings.Repeat("0", 64)
	second, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if second.Claims[0].SpecHash == first.Claims[0].SpecHash {
		t.Fatal("output mutation leaked into a later reconstruction")
	}
}

// §22/§30: the equivalence invariant — reconstruction produces EXACTLY
// what the O5-E1 mint produced for the same record (field equality and
// canonical-JSON byte equality), and no second minting algorithm exists
// (the reconstruction delegates verbatim).
func TestReconstructEquivalentToOriginalMint(t *testing.T) {
	actions := []state.Action{
		reconAction("a1", evPath, "one\n", state.ActionCreateFile),
		reconAction("a2", "/etc/vps-gateway/two.conf", "two\n", state.ActionUpdateFile),
	}
	rec := reconRecord(t, "tx-1", t0, nil, actions...)
	original, err := MintTransactionEvidence(rec, state.Plan{SchemaVersion: state.SchemaVersion, Actions: actions}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Claims) != len(original.Minted) {
		t.Fatalf("claim counts differ: %d vs %d", len(res.Claims), len(original.Minted))
	}
	for i := range original.Minted {
		if !equalEvidenceRecords(original.Minted[i], res.Claims[i]) {
			t.Fatalf("claim %d differs from the original mint:\n%+v\n%+v", i, original.Minted[i], res.Claims[i])
		}
		origJSON, err := json.Marshal(original.Minted[i])
		if err != nil {
			t.Fatal(err)
		}
		reconJSON, err := json.Marshal(res.Claims[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(origJSON) != string(reconJSON) {
			t.Fatalf("canonical serialization differs at claim %d", i)
		}
	}
}

// §59: cross-action substitution — a claim reconstructs only from the
// transaction that actually contains its action.
func TestReconstructActionMembership(t *testing.T) {
	rec := reconRecord(t, "tx-1", t0, nil, reconAction("a1", evPath, "x\n", state.ActionCreateFile))
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := res.Claims[0].ToClaim()
	if err != nil {
		t.Fatal(err)
	}
	other := reconRecord(t, "tx-2", t0.Add(time.Hour), nil,
		reconAction("a1", "/etc/vps-gateway/unrelated.conf", "y\n", state.ActionCreateFile))
	otherFact, err := other.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	v, err := ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: "file." + evPath,
		Candidates: []ownership.TransactionFact{otherFact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("substituted transaction must never corroborate, got %s", v.Status)
	}
}

// §69-§73 (test-only composition): reconstructed evidence + the original
// terminal journal + the ZAI-28 live fact reach the full downstream chain.
func TestReconstructedClaimComposition(t *testing.T) {
	started := t0
	rec := reconRecord(t, "tx-1", started, nil, reconAction("a1", evPath, "owned content\n", state.ActionCreateFile))
	res, err := ReconstructEvidence([]journal.Record{*rec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := res.Claims[0].ToClaim()
	if err != nil {
		t.Fatal(err)
	}
	fact, err := rec.CorroborationFact()
	if err != nil {
		t.Fatal(err)
	}
	liveHash := mustLiveHash(t, evPath, "owned content\n", 0o600, state.ActionCreateFile)
	live := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &liveHash}

	// Corroboration of a reconstructed claim reaches VERIFIED.
	v, err := ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: "file." + evPath,
		Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationVerified {
		t.Fatalf("reconstructed claim must corroborate: %s (%v)", v.Status, v.Reasons)
	}

	// Full chain: OWNED_VERIFIED.
	d, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: live, Claim: &claim,
		JournalResource: "file." + evPath, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.OwnedVerified {
		t.Fatalf("want OWNED_VERIFIED, got %s", d.Verdict)
	}

	// Drift: reconstructed provenance is not current-state truth.
	driftHash := mustLiveHash(t, evPath, "tampered\n", 0o600, state.ActionCreateFile)
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &driftHash},
		Claim: &claim, JournalResource: "file." + evPath, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.OwnedDrift {
		t.Fatalf("want OWNED_DRIFT, got %s", d.Verdict)
	}

	// Missing live observation → UNDETERMINED.
	d, err = ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: evFileID(evPath), Live: ownership.LiveFact{State: ownership.LivePresent},
		Claim: &claim, JournalResource: "file." + evPath, Candidates: []ownership.TransactionFact{fact}, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != ownership.Undetermined {
		t.Fatalf("missing live must fail closed, got %s", d.Verdict)
	}

	// Missing journal: even reconstructed state evidence does not
	// self-corroborate — the authoritative journal stays required.
	v, err = ownership.Corroborate(ownership.VerificationInput{
		Claim: claim, JournalResource: "file." + evPath, Candidates: nil, CurrentHost: evHost,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != ownership.VerificationIncomplete {
		t.Fatalf("missing journal must stay INCOMPLETE, got %s", v.Status)
	}
}

// §45/§48: the reconstruction module is a pure derivation — no I/O, no
// clock, no environment, and no mutation/authority vocabulary.
func TestReconstructImplementationIsPure(t *testing.T) {
	src, err := osReadFile("evidence_reconstruct.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	for _, banned := range []string{
		"\"os\"", "\"io\"", "os.", "time.Now", "Getenv", "exec.",
		"Corroborate(", "DeriveVerdict(", "Admit(", "BirthrightEligible(",
		"OwnedVerified", "OwnedDrift", "Verdict",
		"SaveModel", "LoadModel", "Apply(", "Executor",
	} {
		if strings.Contains(s, banned) {
			t.Fatalf("evidence_reconstruct.go must not reference %q: reconstruction is a pure derivation", banned)
		}
	}
}
