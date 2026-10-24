package p1achain

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/fileobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Synthetic fixtures only: every identifier, hash, fingerprint and host
// identity below is fabricated for the audit; none resembles any real host.

const (
	hexIntended = "1111111111111111111111111111111111111111111111111111111111111111"
	hexOther    = "2222222222222222222222222222222222222222222222222222222222222222"
	fingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	nsFile      = "/etc/vps-gateway/p1achain-sample.conf" // birthright namespace (compiled)
	outsideFile = "/etc/other/p1achain-sample.conf"       // outside the project namespace
)

var (
	hostA        = "machine-id:" + strings.Repeat("a", 32)
	hostB        = "machine-id:" + strings.Repeat("b", 32)
	specIntended = mustSpecHash(hexIntended)
	specOther    = mustSpecHash(hexOther)
)

func mustSpecHash(hex string) ownership.SpecHash {
	h, err := ownership.ParseSpecHashHex(hex)
	if err != nil {
		panic("audit fixture: " + err.Error())
	}
	return h
}

func fileIdentity(path string) ownership.ResourceIdentity {
	return ownership.ResourceIdentity{Class: ownership.ClassFile, Path: path}
}

func mintClaim(t *testing.T, id ownership.ResourceIdentity, specHex, txID, fp, host string) ownership.StateEvidence {
	t.Helper()
	rec := state.EvidenceRecord{
		Identity:        id,
		SpecHash:        specHex,
		TxID:            txID,
		PlanFingerprint: fp,
		HostIdentity:    host,
		MintedAt:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	claim, err := rec.ToClaim()
	if err != nil {
		t.Fatalf("synthetic evidence record rejected: %v", err)
	}
	return claim
}

// journalRecord builds a synthetic durable record. schema 1 stores no spec
// hash (and v1 without host identity is structurally rejected downstream);
// schema 3 carries the intended spec hash and, optionally, an independently
// observed postcondition hash.
func journalRecord(schema int, txID, fp, host, resource, status, intendedHex, observedHex string) journal.Record {
	return journal.Record{
		SchemaVersion:   schema,
		TransactionID:   txID,
		HostIdentity:    host,
		PlanFingerprint: fp,
		Stage:           "PERSIST",
		Outcome:         "COMPLETED",
		Actions: []journal.ActionRecord{{
			ID: "a1", Resource: resource, Kind: "CREATE_FILE",
			RetryClass: journal.RetrySafe, Status: status, SpecHash: intendedHex,
			ObservedSpecHash: observedHex,
		}},
	}
}

func factFrom(t *testing.T, rec journal.Record) ownership.TransactionFact {
	t.Helper()
	f, err := rec.CorroborationFact()
	if err != nil {
		t.Fatalf("journal record rejected by the adapter: %v", err)
	}
	return f
}

// derive runs derivation + the MODIFY admission leg and returns all layers
// so assertions can distinguish structural rejection, verification status,
// verdict and admission decision. An unexpected DeriveVerdict error fails
// the test explicitly — it is never swallowed into a zero value.
func derive(t *testing.T, id ownership.ResourceIdentity, live ownership.LiveFact, claim *ownership.StateEvidence, resource string, candidates []ownership.TransactionFact, currentHost string) (ownership.Derivation, ownership.AdmissionDecision) {
	t.Helper()
	d, err := ownership.DeriveVerdict(ownership.DerivationInput{
		Identity: id, Live: live, Claim: claim,
		JournalResource: resource, Candidates: candidates, CurrentHost: currentHost,
	})
	if err != nil {
		t.Fatalf("unexpected DeriveVerdict error (fail loudly, never a zero-value verdict): %v", err)
	}
	adm, admErr := ownership.Admit(ownership.OperationModify, d.Verdict, id)
	if admErr != nil {
		t.Fatalf("Admit(MODIFY, %s) errored: %v", d.Verdict, admErr)
	}
	return d, adm
}

func hasReason(adm ownership.AdmissionDecision, want ownership.AdmissionReason) bool {
	for _, r := range adm.Reasons {
		if r == want {
			return true
		}
	}
	return false
}

// 1 + 9: a config "OWNED" label has no conversion into the verdict model
// (unknown verdicts fail closed at the admission boundary); presence
// without corroborated evidence is COLLISION inside the reserved namespace
// and UNPROVEN outside it — neither grants modification.
func TestConfigLabelAndUnprovenOccupantNeverGrantOwnership(t *testing.T) {
	if _, err := ownership.Admit(ownership.OperationModify, ownership.Verdict("OWNED"), fileIdentity(nsFile)); !errors.Is(err, ownership.ErrInvalidVerdict) {
		t.Fatalf("the legacy OWNED label must fail closed at the verdict boundary, got err=%v", err)
	}
	for _, tc := range []struct {
		path string
		want ownership.Verdict
		deny ownership.AdmissionReason
	}{
		{nsFile, ownership.Collision, ownership.ReasonCollisionReserved},
		{outsideFile, ownership.Unproven, ownership.ReasonUnprovenOccupant},
	} {
		id := fileIdentity(tc.path)
		d, adm := derive(t, id, ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, nil, tc.path, nil, hostA)
		if d.Verdict != tc.want {
			t.Fatalf("present without evidence in %s: verdict=%s want %s (reasons %v)", tc.path, d.Verdict, tc.want, d.Reasons)
		}
		if adm.Decision != ownership.DecisionDeny || !hasReason(adm, tc.deny) {
			t.Fatalf("admission must deny unproven occupancy: %v", adm)
		}
	}
}

// 2: a structurally valid claim with no matching durable transaction is
// incomplete evidence — never a grant.
func TestClaimWithoutMatchingTransactionIsIncomplete(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	if v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: nil, CurrentHost: hostA}); err != nil || v.Status != ownership.VerificationIncomplete {
		t.Fatalf("no candidates must be INCOMPLETE, got %v / %v", v, err)
	}
	other := factFrom(t, journalRecord(3, "tx-synthetic-other", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	if v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{other}, CurrentHost: hostA}); err != nil || v.Status != ownership.VerificationIncomplete {
		t.Fatalf("unrelated candidates must be INCOMPLETE, got %v / %v", v, err)
	}
	d, adm := derive(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, nil, hostA)
	// Occupied inside the birthright namespace without verified evidence is
	// COLLISION (UNPROVEN is the outside-namespace classification).
	if d.Verdict != ownership.Collision || adm.Decision != ownership.DecisionDeny || !hasReason(adm, ownership.ReasonCollisionReserved) {
		t.Fatalf("unverified claim must stay COLLISION and denied: %s / %v", d.Verdict, adm)
	}
}

// 3: the v1 schema stores no spec hashes and (without an approval verifier)
// no host identity — the adapter structurally rejects hostless v1 records,
// and a host-bound v1 record caps at INCOMPLETE (never VERIFIED).
func TestJournalV1FailsClosed(t *testing.T) {
	hostless := journalRecord(1, "tx-synthetic-v1", fingerprint, "", nsFile, "APPLIED", "", "")
	if _, err := hostless.CorroborationFact(); err == nil {
		t.Fatal("a v1 record without host identity must be structurally rejected")
	}
	hosted := hostless
	hosted.HostIdentity = hostA
	f := factFrom(t, hosted)
	for _, a := range f.Actions {
		if a.SpecHash != nil {
			t.Fatal("v1 translation must never synthesize a spec hash")
		}
	}
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-v1", fingerprint, hostA)
	v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{f}, CurrentHost: hostA})
	if err != nil || v.Status != ownership.VerificationIncomplete {
		t.Fatalf("v1 facts must cap at INCOMPLETE, got %v / %v", v, err)
	}
	d, adm := derive(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{f}, hostA)
	if d.Verdict != ownership.Collision || adm.Decision != ownership.DecisionDeny || !hasReason(adm, ownership.ReasonCollisionReserved) {
		t.Fatalf("v1-only history must stay COLLISION and denied: %s / %v", d.Verdict, adm)
	}
}

// 4 (corrected contract, ZAI-103): the journal's independently observed
// postcondition hash (ActionRecord.ObservedSpecHash, ZAI-59/J4) is a
// distinct meaning from the intended specification hash, and a record
// whose observed postcondition contradicts the intended specification —
// or the claimed one — must NEVER produce VERIFIED corroboration. The
// pre-hardening behavior (VERIFIED despite a contradictory observed hash)
// is preserved as history in the branch commits; these regressions pin
// the corrected fail-closed contract and fail without the fix.
func TestObservedPostconditionContradictionNeverVerifies(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	// The observed postcondition contradicts the claim (and the intended
	// specification) — the strongest form of the contradiction.
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexOther)
	v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{factFrom(t, rec)}, CurrentHost: hostA})
	if err != nil || v.Status != ownership.VerificationMismatch {
		t.Fatalf("a contradictory observed postcondition must never verify, got %v / %v", v, err)
	}
}

func TestObservedPostconditionMatchVerifies(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
	v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{factFrom(t, rec)}, CurrentHost: hostA})
	if err != nil || v.Status != ownership.VerificationVerified {
		t.Fatalf("intended + observed + claim in agreement must verify, got %v / %v", v, err)
	}
	joined := strings.Join(v.Reasons, "; ")
	if !strings.Contains(joined, "independently observed postcondition matches the claimed specification") {
		t.Fatalf("VERIFIED must record that the observed postcondition was checked: %v", v.Reasons)
	}
}

func TestIntendedContradictsClaimNeverVerifies(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	// The intended specification contradicts the claim even though the
	// observed postcondition matches it: the intent leg still binds.
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexOther, hexIntended)
	v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{factFrom(t, rec)}, CurrentHost: hostA})
	if err != nil || v.Status != ownership.VerificationMismatch {
		t.Fatalf("an intended specification contradicting the claim must never verify, got %v / %v", v, err)
	}
}

func TestMalformedObservedHashFailsClosed(t *testing.T) {
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, "not-hex")
	if _, err := rec.CorroborationFact(); err == nil {
		t.Fatal("a malformed observed postcondition hash must be structurally rejected")
	}
}

func TestDuplicateFactsDifferingInObservedHashConflict(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	a := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	b := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexOther))
	_, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{a, b}, CurrentHost: hostA})
	if !errors.Is(err, ownership.ErrConflictingCorroboration) {
		t.Fatalf("duplicate facts differing in the observed hash must conflict, got %v", err)
	}
}

func TestObservedEvidenceUnderRecoveryAndRollback(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	mk := func(mutate func(*journal.Record)) ownership.TransactionFact {
		rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
		mutate(&rec)
		return factFrom(t, rec)
	}
	for _, tc := range []struct {
		name string
		fact ownership.TransactionFact
	}{
		{"RECOVERY_REQUIRED with observed evidence", mk(func(r *journal.Record) { r.Outcome = "RECOVERY_REQUIRED" })},
		{"recovery latch with observed evidence", mk(func(r *journal.Record) { r.RecoveryRequired = true })},
		{"rollback with observed evidence", mk(func(r *journal.Record) { r.RollbackAttempted = true; r.RollbackResult = "ROLLED_BACK" })},
	} {
		v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{tc.fact}, CurrentHost: hostA})
		if err != nil || v.Status != ownership.VerificationMismatch {
			t.Fatalf("%s: the terminal-state leg dominates observed evidence, got %v / %v", tc.name, v, err)
		}
	}
}

func TestObservedHashOrderDeterminism(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	match := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	noise := factFrom(t, journalRecord(3, "tx-synthetic-x", fingerprint, hostA, nsFile, "APPLIED", hexOther, hexOther))
	run := func(cands []ownership.TransactionFact) ownership.VerificationStatus {
		v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: cands, CurrentHost: hostA})
		if err != nil {
			t.Fatalf("determinism run failed: %v", err)
		}
		return v.Status
	}
	if s := run([]ownership.TransactionFact{noise, match}); s != ownership.VerificationVerified {
		t.Fatalf("order must not change the outcome, got %s", s)
	}
	if s := run([]ownership.TransactionFact{match, noise}); s != ownership.VerificationVerified {
		t.Fatalf("order must not change the outcome, got %s", s)
	}
}

// Compatibility boundary (deliberately pinned, NOT silently changed):
// records that carry no observed postcondition keep the historical
// intent-only corroboration semantics. Requiring an observed hash in
// every favorable case would change established compatibility semantics
// and is reserved for a separate owner decision (v1: no hashes at all —
// INCOMPLETE, see TestJournalV1FailsClosed; v3-without-observation is
// covered by the positive control).
func TestV2IntentOnlyCorroborationCompatibility(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(2, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, "")
	v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{factFrom(t, rec)}, CurrentHost: hostA})
	if err != nil || v.Status != ownership.VerificationVerified {
		t.Fatalf("v2 intent-only corroboration is the pinned compatibility behavior, got %v / %v", v, err)
	}
}

// 5: wrong host identity — past (claim vs record) or present (record vs
// current machine) — can never verify.
func TestWrongHostNeverVerifies(t *testing.T) {
	claimA := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	recA := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	if v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claimA, JournalResource: nsFile, Candidates: []ownership.TransactionFact{recA}, CurrentHost: hostB}); err != nil || v.Status != ownership.VerificationMismatch {
		t.Fatalf("current-host mismatch must be a MISMATCH, got %v / %v", v, err)
	}
	claimB := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostB)
	if v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claimB, JournalResource: nsFile, Candidates: []ownership.TransactionFact{recA}, CurrentHost: hostA}); err != nil || v.Status != ownership.VerificationMismatch {
		t.Fatalf("claim/record host mismatch must be a MISMATCH, got %v / %v", v, err)
	}
	d, adm := derive(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claimB, nsFile, []ownership.TransactionFact{recA}, hostA)
	if d.Verdict != ownership.Collision || adm.Decision != ownership.DecisionDeny || !hasReason(adm, ownership.ReasonCollisionReserved) {
		t.Fatalf("wrong host must stay COLLISION and denied: %s / %v", d.Verdict, adm)
	}
}

// 6: wrong transaction id or plan fingerprint → MISMATCH, no grant.
func TestWrongTxIDOrFingerprintNeverVerifies(t *testing.T) {
	rec := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	for _, tc := range []struct {
		name       string
		txID       string
		fp         string
		wantStatus ownership.VerificationStatus
	}{
		// A claim referencing a transaction that is not in the fact set is
		// INCOMPLETE (absence of the referenced record), while a claim whose
		// transaction exists but carries a different plan fingerprint is a
		// MISMATCH (positive contradiction).
		{"wrong tx id", "tx-synthetic-other", fingerprint, ownership.VerificationIncomplete},
		{"wrong fingerprint", "tx-synthetic-1", strings.Repeat("e", 64), ownership.VerificationMismatch},
	} {
		claim := mintClaim(t, fileIdentity(nsFile), hexIntended, tc.txID, tc.fp, hostA)
		v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{rec}, CurrentHost: hostA})
		if err != nil || v.Status != tc.wantStatus {
			t.Fatalf("%s: want %s, got %v / %v", tc.name, tc.wantStatus, v, err)
		}
	}
}

// 7: unfinished transactions, failures, recovery latches and rollbacks can
// never corroborate.
func TestUnfinishedOrRecoveredTransactionsNeverVerify(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	mk := func(mutate func(*journal.Record)) ownership.TransactionFact {
		rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, "")
		mutate(&rec)
		return factFrom(t, rec)
	}
	cases := []struct {
		name       string
		fact       ownership.TransactionFact
		incomplete bool
	}{
		{"in progress (crashed run)", mk(func(r *journal.Record) { r.Outcome = "" }), true},
		{"FAILED outcome", mk(func(r *journal.Record) { r.Outcome = "FAILED" }), false},
		{"RECOVERY_REQUIRED outcome", mk(func(r *journal.Record) { r.Outcome = "RECOVERY_REQUIRED" }), false},
		{"recovery latch", mk(func(r *journal.Record) { r.RecoveryRequired = true }), false},
		{"rollback attempted", mk(func(r *journal.Record) { r.RollbackAttempted = true; r.RollbackResult = "ROLLED_BACK" }), false},
		{"rollback failed", mk(func(r *journal.Record) { r.RollbackAttempted = true; r.RollbackResult = "ROLLBACK_FAILED" }), false},
		{"action not applied", mk(func(r *journal.Record) { r.Actions[0].Status = "APPLY_FAILED" }), false},
	}
	for _, tc := range cases {
		v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{tc.fact}, CurrentHost: hostA})
		if err != nil {
			t.Fatalf("%s: unexpected structural error: %v", tc.name, err)
		}
		if tc.incomplete && v.Status != ownership.VerificationIncomplete {
			t.Fatalf("%s: want INCOMPLETE, got %v", tc.name, v)
		}
		if !tc.incomplete && v.Status != ownership.VerificationMismatch {
			t.Fatalf("%s: want MISMATCH, got %v", tc.name, v)
		}
	}
}

// 8: live UNKNOWN dominates — UNDETERMINED, never ABSENT; admission
// resolves to the explicit fail-closed UNDETERMINED decision.
func TestLiveUnknownIsUndetermined(t *testing.T) {
	d, adm := derive(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LiveUnknown}, nil, nsFile, nil, hostA)
	if d.Verdict != ownership.Undetermined {
		t.Fatalf("UNKNOWN live state must be UNDETERMINED, got %s", d.Verdict)
	}
	if adm.Decision != ownership.DecisionUndetermined || !hasReason(adm, ownership.ReasonUndeterminedOwnership) {
		t.Fatalf("UNDETERMINED must resolve explicitly: %v", adm)
	}
}

// 10: a positively absent birthright identity satisfies only the CREATE
// ownership leg; GONE never counts as ABSENT; the ownership leg alone is
// not mutation authorization. Absence is established by a SYNTHETIC
// FileObservation with the explicitly constructed ABSENT status — the real
// collector's behavior is covered by fileobs' own suite, and the offline
// chain audit must not depend on any real filesystem path.
func TestAbsentBirthrightSatisfiesOnlyCreateLeg(t *testing.T) {
	id := fileIdentity("/etc/vps-gateway/p1achain-synthetically-absent.conf")
	obs := fileobs.FileObservation{Identity: id, Status: fileobs.StatusAbsent}
	live, err := obs.LiveFact()
	if err != nil {
		t.Fatalf("LiveFact translation failed: %v", err)
	}
	if live.State != ownership.LiveAbsent {
		t.Fatalf("want LiveAbsent, got %+v", live)
	}
	d, derr := ownership.DeriveVerdict(ownership.DerivationInput{Identity: id, Live: live})
	if derr != nil || d.Verdict != ownership.Absent {
		t.Fatalf("proven absence without evidence is ABSENT, got %v / %v", d, derr)
	}
	adm, err := ownership.Admit(ownership.OperationCreate, d.Verdict, id)
	if err != nil {
		t.Fatalf("CREATE against ABSENT must resolve, got %v", err)
	}
	if adm.Decision != ownership.DecisionAllow || !hasReason(adm, ownership.ReasonBirthrightFirstCreation) {
		t.Fatalf("the ownership CREATE leg may be satisfied, got %v", adm)
	}
	// The ownership leg alone is not mutation authorization: the decision
	// type carries no executor, approval or capability input, and MODIFY
	// against ABSENT has nothing to modify.
	if m, merr := ownership.Admit(ownership.OperationModify, d.Verdict, id); merr != nil || m.Decision != ownership.DecisionDeny {
		t.Fatalf("MODIFY against ABSENT must deny, got %v / %v", m, merr)
	}
	// GONE never counts as ABSENT.
	if g, gerr := ownership.Admit(ownership.OperationCreate, ownership.Gone, id); gerr != nil || g.Decision != ownership.DecisionDeny {
		t.Fatalf("CREATE against GONE must deny, got %v / %v", g, gerr)
	}
}

// 11: deletion authority is deliberately unmodeled — DENY for every
// verdict in the closed vocabulary.
func TestDeleteAlwaysDenied(t *testing.T) {
	id := fileIdentity(nsFile)
	for _, v := range []ownership.Verdict{
		ownership.OwnedVerified, ownership.OwnedDrift, ownership.Unproven,
		ownership.Collision, ownership.Conflict, ownership.Absent,
		ownership.Gone, ownership.Undetermined,
	} {
		adm, err := ownership.Admit(ownership.OperationDelete, v, id)
		if err != nil {
			t.Fatalf("DELETE/%s must resolve (never error): %v", v, err)
		}
		if adm.Decision != ownership.DecisionDeny {
			t.Fatalf("DELETE/%s must always deny, got %v", v, adm)
		}
	}
}

// 12: contradictory durable records for the same transaction id fail closed
// with a structural error — ambiguity is never resolved by choice.
func TestContradictoryRecordsFailClosed(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	a := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	b := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexOther, ""))
	_, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{a, b}, CurrentHost: hostA})
	if !errors.Is(err, ownership.ErrConflictingCorroboration) {
		t.Fatalf("contradictory records must fail closed with the conflict error, got %v", err)
	}
	if _, derr := ownership.DeriveVerdict(ownership.DerivationInput{Identity: fileIdentity(nsFile), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, Claim: &claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{a, b}, CurrentHost: hostA}); derr == nil {
		t.Fatal("DeriveVerdict must propagate the conflict as a structural failure")
	}
}

// 13: identical facts in different orders classify identically.
func TestOrderDeterminism(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	match := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	noise1 := factFrom(t, journalRecord(3, "tx-synthetic-x1", fingerprint, hostA, nsFile, "APPLIED", hexOther, ""))
	noise2 := factFrom(t, journalRecord(3, "tx-synthetic-x2", fingerprint, hostB, nsFile, "APPLIED", hexOther, ""))
	id := fileIdentity(nsFile)
	live := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}
	run := func(cands []ownership.TransactionFact) (ownership.Verdict, ownership.Decision, ownership.AdmissionReason) {
		d, err := ownership.DeriveVerdict(ownership.DerivationInput{Identity: id, Live: live, Claim: &claim, JournalResource: nsFile, Candidates: cands, CurrentHost: hostA})
		if err != nil {
			t.Fatalf("determinism run failed: %v", err)
		}
		adm, err := ownership.Admit(ownership.OperationModify, d.Verdict, id)
		if err != nil {
			t.Fatalf("admit failed: %v", err)
		}
		return d.Verdict, adm.Decision, adm.Reasons[0]
	}
	v1, d1, r1 := run([]ownership.TransactionFact{noise1, match, noise2})
	v2, d2, r2 := run([]ownership.TransactionFact{noise2, noise1, match})
	v3, d3, r3 := run([]ownership.TransactionFact{match})
	if v1 != ownership.OwnedVerified || v1 != v2 || v1 != v3 || d1 != d2 || d2 != d3 || r1 != r2 || r2 != r3 {
		t.Fatalf("classification must be order-independent: %s/%s/%s then %s/%s/%s then %s/%s/%s", v1, d1, r1, v2, d2, r2, v3, d3, r3)
	}
}

// Positive control: when every evidence requirement is genuinely met — a
// valid state-v2 claim (through the state conversion path), a matching
// durable v3 transaction on the same host with the same fingerprint and a
// matching intended spec hash, and a live representation hashing to the
// claimed spec — the chain verifies, derives OWNED_VERIFIED and the
// ownership MODIFY leg allows. This is still not complete mutation
// authorization: the other admission planes are separate and unwired.
func TestPositiveControlFullChain(t *testing.T) {
	id := fileIdentity(nsFile)
	claim := mintClaim(t, id, hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, ""))
	live := ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}
	d, err := ownership.DeriveVerdict(ownership.DerivationInput{Identity: id, Live: live, Claim: &claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{rec}, CurrentHost: hostA})
	if err != nil {
		t.Fatalf("positive control derivation failed: %v", err)
	}
	if d.Verdict != ownership.OwnedVerified {
		t.Fatalf("positive control must reach OWNED_VERIFIED, got %s (%v)", d.Verdict, d.Reasons)
	}
	adm, err := ownership.Admit(ownership.OperationModify, d.Verdict, id)
	if err != nil || adm.Decision != ownership.DecisionAllow {
		t.Fatalf("the ownership MODIFY leg must allow a verified owner, got %v / %v", adm, err)
	}
	claims, err := state.EvidenceRecordsToClaims([]state.EvidenceRecord{{
		Identity: id, SpecHash: hexIntended, TxID: "tx-synthetic-1",
		PlanFingerprint: fingerprint, HostIdentity: hostA,
		MintedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}})
	if err != nil || len(claims) != 1 || claims[0] != claim {
		t.Fatalf("state evidence conversion diverged: %v / %#v", err, claims)
	}
}
