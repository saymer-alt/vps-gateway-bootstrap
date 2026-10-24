package p1achain

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// ZAI-105 adversarial matrix for the strict observed-evidence policy
// (ownership.ClassifyObservedEvidence). Synthetic fixtures only. The
// classifier composes Corroborate + DeriveVerdict and adds exactly one
// gate: future production admission requires a durably recorded, matching
// independently observed postcondition. SUFFICIENT is a classification for
// consideration — never mutation authority; the legacy Corroborate
// compatibility (intent-only VERIFIED) is retained one layer down and is
// deliberately NOT treated as sufficient here.

func classify(t *testing.T, id ownership.ResourceIdentity, live ownership.LiveFact, claim *ownership.StateEvidence, resource string, candidates []ownership.TransactionFact, currentHost string) ownership.ObservedEvidenceClassification {
	t.Helper()
	res, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
		Identity: id, Live: live, Claim: claim,
		JournalResource: resource, Candidates: candidates, CurrentHost: currentHost,
	})
	if err != nil {
		t.Fatalf("unexpected classification error: %v", err)
	}
	return res
}

// 1: journal v1 stores no spec hashes — the strict policy can never reach
// SUFFICIENT from a v1 history.
func TestSufficiencyV1Insufficient(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-v1", fingerprint, hostA)
	rec := journalRecord(1, "tx-synthetic-v1", fingerprint, hostA, nsFile, "APPLIED", "", "")
	rec.HostIdentity = hostA
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
	if res.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("v1 history must be INSUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
}

// 2: journal v2 with the intended hash only — Corroborate's legacy
// compatibility reports VERIFIED, and the strict policy deliberately
// classifies the same evidence INSUFFICIENT.
func TestSufficiencyV2IntentOnlyInsufficientWhileCorroborateVerifies(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(2, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, "")
	f := factFrom(t, rec)
	if v, err := ownership.Corroborate(ownership.VerificationInput{Claim: claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{f}, CurrentHost: hostA}); err != nil || v.Status != ownership.VerificationVerified {
		t.Fatalf("legacy compatibility must hold at the Corroborate layer, got %v / %v", v, err)
	}
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{f}, hostA)
	if res.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("v2 intent-only must be INSUFFICIENT under the strict policy, got %s (%v)", res.Evidence, res.Reasons)
	}
	if !strings.Contains(strings.Join(res.Reasons, "; "), "intended specification only") {
		t.Fatalf("the insufficient reason must name the intent-only gap: %v", res.Reasons)
	}
}

// 3: journal v3 without an independently observed postcondition —
// INSUFFICIENT.
func TestSufficiencyV3WithoutObservationInsufficient(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, "")
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
	if res.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("v3 without observation must be INSUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
}

// 4: journal v3 with matching intended/observed/claimed specification and
// live agreement — SUFFICIENT for this evidence dimension (with the full
// hypothetical verdict recorded alongside; neither is authority).
func TestSufficiencyV3MatchingSufficient(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
	if res.Evidence != ownership.EvidenceSufficient {
		t.Fatalf("matching observed postcondition must be SUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
	if res.Verdict != ownership.OwnedVerified {
		t.Fatalf("the complete hypothetical scenario must reach OWNED_VERIFIED, got %s", res.Verdict)
	}
}

// 5 + 6: every observed/intended/claim contradiction is CONTRADICTORY.
func TestSufficiencyContradictionsFailClosed(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	for _, tc := range []struct {
		name               string
		intended, observed string
	}{
		{"observed contradicts intended and claim", hexIntended, hexOther},
		{"observed contradicts claim", hexOther, hexOther},
	} {
		rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", tc.intended, tc.observed)
		res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
		if res.Evidence != ownership.EvidenceContradictory {
			t.Fatalf("%s: want CONTRADICTORY, got %s (%v)", tc.name, res.Evidence, res.Reasons)
		}
	}
}

// 7: a zero observed hash inside a fact is structurally invalid — the
// classifier fails closed (the journal adapter rejects malformed strings
// upstream; see TestMalformedObservedHashFailsClosed).
func TestSufficiencyMalformedObservedHashFailsClosed(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	f := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	zero := ownership.SpecHash{}
	f.Actions[0].ObservedSpecHash = &zero
	if _, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
		Identity: fileIdentity(nsFile), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended},
		Claim: &claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{f}, CurrentHost: hostA,
	}); err == nil {
		t.Fatal("a zero observed hash must fail closed structurally")
	}
}

// 8: wrong host (past or present) or wrong fingerprint — positive
// contradictions, fail closed.
func TestSufficiencyWrongHostOrFingerprintContradictory(t *testing.T) {
	rec := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	for _, tc := range []struct {
		name  string
		claim ownership.StateEvidence
		host  string
	}{
		{"claim on another host", mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostB), hostA},
		{"record is another machine", mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA), hostB},
		{"wrong fingerprint", mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", strings.Repeat("e", 64), hostA), hostA},
	} {
		res, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
			Identity: fileIdentity(nsFile), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended},
			Claim: &tc.claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{rec}, CurrentHost: tc.host,
		})
		if err != nil {
			t.Fatalf("%s: unexpected structural error: %v", tc.name, err)
		}
		if res.Evidence != ownership.EvidenceContradictory {
			t.Fatalf("%s: want CONTRADICTORY, got %s (%v)", tc.name, res.Evidence, res.Reasons)
		}
	}
}

// 9: an unfinished (crashed) transaction proves nothing — INSUFFICIENT.
func TestSufficiencyUnfinishedTransactionInsufficient(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
	rec.Outcome = ""
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
	if res.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("unfinished transaction must be INSUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
}

// 10: recovery latch and rollbacks — positive contradictions, fail closed
// even with fully matching observed evidence.
func TestSufficiencyRecoveryAndRollbackContradictory(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	for _, tc := range []struct {
		name   string
		mutate func(*journal.Record)
	}{
		{"recovery latch", func(r *journal.Record) { r.RecoveryRequired = true }},
		{"RECOVERY_REQUIRED outcome", func(r *journal.Record) { r.Outcome = "RECOVERY_REQUIRED" }},
		{"rollback attempted", func(r *journal.Record) { r.RollbackAttempted = true; r.RollbackResult = "ROLLED_BACK" }},
	} {
		rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
		tc.mutate(&rec)
		res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
		if res.Evidence != ownership.EvidenceContradictory {
			t.Fatalf("%s: want CONTRADICTORY, got %s (%v)", tc.name, res.Evidence, res.Reasons)
		}
	}
}

// 11: live UNKNOWN dominates the complete-ownership scenario — the
// evidence dimension may classify on the durable history alone, but the
// recorded verdict is UNDETERMINED and no favorable complete-ownership
// conclusion exists.
func TestSufficiencyLiveUnknownNoFavorableConclusion(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	rec := journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended)
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LiveUnknown}, &claim, nsFile, []ownership.TransactionFact{factFrom(t, rec)}, hostA)
	if res.Verdict != ownership.Undetermined {
		t.Fatalf("live UNKNOWN must record UNDETERMINED, got %s", res.Verdict)
	}
	if res.Verdict == ownership.OwnedVerified {
		t.Fatal("no favorable complete-ownership conclusion may exist under live UNKNOWN")
	}
}

// 12: a self-declared OWNED label is not an evidence input — a scenario
// with no claim classifies INSUFFICIENT and the occupant stays COLLISION
// inside the reserved namespace.
func TestSufficiencyLabelAloneInsufficient(t *testing.T) {
	res := classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, nil, nsFile, nil, hostA)
	if res.Evidence != ownership.EvidenceInsufficient {
		t.Fatalf("label-only scenarios must be INSUFFICIENT, got %s (%v)", res.Evidence, res.Reasons)
	}
	if res.Verdict != ownership.Collision {
		t.Fatalf("unproven occupant of a reserved identity stays COLLISION, got %s", res.Verdict)
	}
}

// 13: reordering equivalent facts cannot change the classification.
func TestSufficiencyOrderDeterminism(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	match := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	noise := factFrom(t, journalRecord(3, "tx-synthetic-x", fingerprint, hostA, nsFile, "APPLIED", hexOther, hexOther))
	run := func(cands []ownership.TransactionFact) ownership.EvidenceSufficiency {
		return classify(t, fileIdentity(nsFile), ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended}, &claim, nsFile, cands, hostA).Evidence
	}
	if s := run([]ownership.TransactionFact{noise, match}); s != ownership.EvidenceSufficient {
		t.Fatalf("order must not change the outcome, got %s", s)
	}
	if s := run([]ownership.TransactionFact{match, noise}); s != ownership.EvidenceSufficient {
		t.Fatalf("order must not change the outcome, got %s", s)
	}
}

// 14: duplicate facts for one transaction differing in the observed hash
// are conflicting corroboration — structural fail-closed, never resolved.
func TestSufficiencyContradictoryDuplicatesFailClosed(t *testing.T) {
	claim := mintClaim(t, fileIdentity(nsFile), hexIntended, "tx-synthetic-1", fingerprint, hostA)
	a := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexIntended))
	b := factFrom(t, journalRecord(3, "tx-synthetic-1", fingerprint, hostA, nsFile, "APPLIED", hexIntended, hexOther))
	if _, err := ownership.ClassifyObservedEvidence(ownership.DerivationInput{
		Identity: fileIdentity(nsFile), Live: ownership.LiveFact{State: ownership.LivePresent, SpecHash: &specIntended},
		Claim: &claim, JournalResource: nsFile, Candidates: []ownership.TransactionFact{a, b}, CurrentHost: hostA,
	}); err == nil {
		t.Fatal("contradictory duplicates must fail closed structurally")
	}
}
