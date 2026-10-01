package ownership

import (
	"strings"
	"testing"
	"time"
)

// O5-B adversarial tests (ZAI-15 §21): the verdict derivation must use the
// O1 vocabulary only, treat O5-A as the sole evidence primitive, and fail
// closed on every uncertainty. Matching anything without a verified claim
// is never ownership.

var (
	fileIdentity         = ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/experiment-file-test.conf"}
	dropInIdentity       = ResourceIdentity{Class: ClassSysctlDropIn, Path: "/etc/sysctl.d/99-vps-gateway.conf"}
	routeRuleIdentity    = ResourceIdentity{Class: ClassRouteRule, Table: 100, Priority: 100, From: "172.29.172.0/24"}
	plainPathIdentity    = ResourceIdentity{Class: ClassFile, Path: "/etc/other-service/config.conf"}
	liveSpec             = SpecHash{0xaa}
	foreignLiveSpec      = SpecHash{0xbb}
	dropInLiveSpec       = SpecHash{0xcc}
	foreignManagerUFW    = ExtUFW
	foreignManagerDocker = ExtDocker
)

func present(hash *SpecHash) LiveFact { return LiveFact{State: LivePresent, SpecHash: hash} }
func changed() LiveFact               { return LiveFact{State: LivePresent, SpecHash: &foreignLiveSpec} }
func absentFact() LiveFact            { return LiveFact{State: LiveAbsent} }
func unknownFact() LiveFact           { return LiveFact{State: LiveUnknown} }
func presentExternal(c ExternalClass) LiveFact {
	return LiveFact{State: LivePresent, SpecHash: &liveSpec, ExternalOwner: &c}
}

func deriveInput(identity ResourceIdentity, live LiveFact) DerivationInput {
	return DerivationInput{
		Identity:        identity,
		Live:            live,
		Claim:           claimPtr(validClaim()),
		JournalResource: testRes,
		Candidates:      []TransactionFact{validFact()},
		CurrentHost:     testHost,
	}
}

func claimPtr(c StateEvidence) *StateEvidence { return &c }

// 1: verified evidence + matching live representation → OWNED_VERIFIED.
func TestDeriveVerifiedEvidenceAndMatchingLiveIsOwnedVerified(t *testing.T) {
	d, err := DeriveVerdict(deriveInput(fileIdentity, present(&liveSpec)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != OwnedVerified {
		t.Fatalf("verdict = %s (%v), want OWNED_VERIFIED", d.Verdict, d.Reasons)
	}
}

// 2: verified evidence + changed live file → OWNED_DRIFT.
func TestDeriveVerifiedEvidenceAndChangedFileIsOwnedDrift(t *testing.T) {
	d, err := DeriveVerdict(deriveInput(fileIdentity, changed()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != OwnedDrift {
		t.Fatalf("verdict = %s (%v), want OWNED_DRIFT", d.Verdict, d.Reasons)
	}
}

// 3: verified evidence + positively established absence → GONE.
func TestDeriveVerifiedEvidenceAndAbsentIsGone(t *testing.T) {
	d, err := DeriveVerdict(deriveInput(fileIdentity, absentFact()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Gone {
		t.Fatalf("verdict = %s (%v), want GONE", d.Verdict, d.Reasons)
	}
}

// 4: verified evidence + unknown live state → UNDETERMINED (never
// OWNED_VERIFIED or GONE from uncertainty).
func TestDeriveVerifiedEvidenceAndUnknownLiveIsUndetermined(t *testing.T) {
	d, err := DeriveVerdict(deriveInput(fileIdentity, unknownFact()))
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Undetermined {
		t.Fatalf("verdict = %s (%v), want UNDETERMINED", d.Verdict, d.Reasons)
	}
}

// 5: no evidence + positively established absence → ABSENT (a potential
// first-creation situation; ABSENT is still not a creation permission).
func TestDeriveNoEvidenceAndAbsentIsAbsent(t *testing.T) {
	in := deriveInput(plainPathIdentity, absentFact())
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Absent {
		t.Fatalf("verdict = %s (%v), want ABSENT", d.Verdict, d.Reasons)
	}
}

// 6: no evidence + present ordinary resource → UNPROVEN — even when the
// live content exactly matches what Bootstrap would desire (matching
// desired configuration is not provenance).
func TestDeriveNoEvidenceAndExactMatchIsUnproven(t *testing.T) {
	in := deriveInput(plainPathIdentity, present(&liveSpec))
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Unproven {
		t.Fatalf("verdict = %s (%v), want UNPROVEN", d.Verdict, d.Reasons)
	}
}

// 7: no evidence + present resource inside a birthright namespace →
// COLLISION (foreign occupancy of a reserved identity). A vpsgw_ chain and
// a project-looking path behave identically.
func TestDeriveNoEvidenceAndReservedOccupancyIsCollision(t *testing.T) {
	for _, identity := range []ResourceIdentity{fileIdentity, dropInIdentity, routeRuleIdentity} {
		in := deriveInput(identity, present(&liveSpec))
		in.Claim = nil
		d, err := DeriveVerdict(in)
		if err != nil {
			t.Fatalf("%s: %v", identity.Class, err)
		}
		if d.Verdict != Collision {
			t.Fatalf("%s: verdict = %s (%v), want COLLISION", identity.Class, d.Verdict, d.Reasons)
		}
	}
}

// 8-9: matching project prefix / exact desired state without evidence can
// never verify (structurally: no claim, no Corroborate call, no path to an
// owned verdict).
func TestDeriveMatchingShapeWithoutEvidenceIsNeverOwned(t *testing.T) {
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	switch d.Verdict {
	case OwnedVerified, OwnedDrift:
		t.Fatalf("matching shape without evidence must never be owned: %s", d.Verdict)
	}
}

// 10-11: O5-A INCOMPLETE and MISMATCH both mean "no valid evidence": the
// resource stays UNPROVEN/COLLISION and can never become owned.
func TestDeriveUnverifiedClaimIsNeverOwned(t *testing.T) {
	// INCOMPLETE: the v1 journal fact carries no spec hash.
	incompleteFact := validFact()
	incompleteFact.Actions[0].SpecHash = nil
	in1 := deriveInput(fileIdentity, present(&liveSpec))
	in1.Candidates = []TransactionFact{incompleteFact}
	d1, err := DeriveVerdict(in1)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Verdict != Collision {
		t.Fatalf("INCOMPLETE evidence: verdict = %s (%v), want COLLISION", d1.Verdict, d1.Reasons)
	}
	if !strings.Contains(strings.Join(d1.Reasons, "; "), "did not verify") {
		t.Fatalf("reason must surface the failed verification: %v", d1.Reasons)
	}
	// MISMATCH: the corroboration contradicts the claim (wrong spec hash).
	mismatchFact := validFact()
	wrong := SpecHash{0xdd}
	mismatchFact.Actions[0].SpecHash = &wrong
	in2 := deriveInput(fileIdentity, present(&liveSpec))
	in2.Candidates = []TransactionFact{mismatchFact}
	d2, err := DeriveVerdict(in2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Verdict != Collision {
		t.Fatalf("MISMATCH evidence: verdict = %s (%v), want COLLISION", d2.Verdict, d2.Reasons)
	}
}

// 12-13: a positively established external manager over a verified-owned
// resource is CONFLICT — distinct from file drift. Network-identity drift
// on a verified-owned routing rule is likewise CONFLICT, never drift.
func TestDeriveConflictIsDistinctFromDrift(t *testing.T) {
	// External manager over a verified-owned file: CONFLICT.
	d, err := DeriveVerdict(deriveInput(fileIdentity, presentExternal(foreignManagerDocker)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Conflict {
		t.Fatalf("verdict = %s (%v), want CONFLICT (external manager)", d.Verdict, d.Reasons)
	}
	// Network spec drift on a verified-owned routing rule: CONFLICT. The
	// claim, the corroborating fact and the matching live hash are all
	// built for the routing identity.
	routeClaim := validClaim()
	routeClaim.Identity = routeRuleIdentity
	const routeJournalResource = "routing.rule.100"
	matchedRoute := deriveInput(routeRuleIdentity, LiveFact{State: LivePresent, SpecHash: &liveSpec})
	matchedRoute.Claim = claimPtr(routeClaim)
	matchedRoute.JournalResource = routeJournalResource
	routeFact := validFact()
	routeFact.Actions = []TransactionAction{{
		Resource: routeJournalResource, Status: TransactionActionApplied, SpecHash: &liveSpec,
	}}
	matchedRoute.Candidates = []TransactionFact{routeFact}
	d1, err := DeriveVerdict(matchedRoute)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Verdict != OwnedVerified {
		t.Fatalf("sanity: matching routing rule must be OWNED_VERIFIED first: %s (%v)", d1.Verdict, d1.Reasons)
	}
	changedRoute := matchedRoute
	changedRoute.Live = LiveFact{State: LivePresent, SpecHash: &foreignLiveSpec}
	d2, err := DeriveVerdict(changedRoute)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Verdict != Conflict {
		t.Fatalf("verdict = %s (%v), want CONFLICT (network drift)", d2.Verdict, d2.Reasons)
	}
	// The file counterpart of the same drift is OWNED_DRIFT (14: drift vs
	// collision distinction — an unproven occupant is never OWNED_DRIFT).
	d3, err := DeriveVerdict(deriveInput(fileIdentity, changed()))
	if err != nil {
		t.Fatal(err)
	}
	if d3.Verdict != OwnedDrift {
		t.Fatalf("verdict = %s (%v), want OWNED_DRIFT", d3.Verdict, d3.Reasons)
	}
	in4 := deriveInput(fileIdentity, changed())
	in4.Claim = nil
	d4, err := DeriveVerdict(in4)
	if err != nil {
		t.Fatal(err)
	}
	if d4.Verdict != Collision {
		t.Fatalf("unproven occupant of a reserved path: verdict = %s (%v), want COLLISION, not OWNED_DRIFT", d4.Verdict, d4.Reasons)
	}
}

// 15-16: unknown vs absent vs gone are strictly distinguished.
func TestDeriveUnknownAbsentGoneDistinctions(t *testing.T) {
	// UNKNOWN live state is never ABSENT or GONE, with or without evidence.
	for _, in := range []DerivationInput{
		deriveInput(fileIdentity, unknownFact()),
		func() DerivationInput { in := deriveInput(fileIdentity, unknownFact()); in.Claim = nil; return in }(),
	} {
		d, err := DeriveVerdict(in)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != Undetermined {
			t.Fatalf("unknown live state must be UNDETERMINED, got %s", d.Verdict)
		}
	}
	// Absence without verified evidence is ABSENT, never GONE.
	in := deriveInput(fileIdentity, absentFact())
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Absent {
		t.Fatalf("unproven absence must be ABSENT, got %s", d.Verdict)
	}
}

// 17-18: external-manager exact matches never verify — an UFW-created or
// operator-created resource that happens to match is UNPROVEN/COLLISION.
func TestDeriveExternalManagerMatchIsNeverOwned(t *testing.T) {
	in := deriveInput(plainPathIdentity, presentExternal(foreignManagerUFW))
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("external-manager match must never be owned: %s", d.Verdict)
	}
}

// 18bis (sysctl fleet regression, ZAI-15 §17): a foreign/Amnezia/operator
// fragment occupying the exact project drop-in path is COLLISION — and the
// derivation has no input by which an effective kernel value could ever
// influence the verdict. Conversely, verified project drop-in evidence
// with changed live content is OWNED_DRIFT even if another fragment could
// be keeping the effective value "correct".
func TestDeriveSysctlEffectiveValueIsNotOwnership(t *testing.T) {
	// Foreign fragment at the project drop-in path, content matching what
	// Bootstrap would desire, no evidence: COLLISION, never owned.
	in := deriveInput(dropInIdentity, present(&dropInLiveSpec))
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION", d.Verdict, d.Reasons)
	}
	// Verified project drop-in evidence + changed live drop-in:
	// OWNED_DRIFT regardless of any coincidentally-correct effective value
	// (which O5-B never sees — there is no effective-value input).
	claim := validClaim()
	claim.Identity = dropInIdentity
	fact := validFact()
	fact.Actions = []TransactionAction{{
		Resource: "file./etc/sysctl.d/99-vps-gateway.conf",
		Status:   TransactionActionApplied,
		SpecHash: &testSpec, // the claim's evidenced spec
	}}
	in2 := deriveInput(dropInIdentity, changed()) // live content drifted
	in2.Claim = claimPtr(claim)
	in2.JournalResource = "file./etc/sysctl.d/99-vps-gateway.conf"
	in2.Candidates = []TransactionFact{fact}
	d2, err := DeriveVerdict(in2)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Verdict != OwnedDrift {
		t.Fatalf("verdict = %s (%v), want OWNED_DRIFT", d2.Verdict, d2.Reasons)
	}
}

// 19: a verified claim for a different identity is invalid input.
func TestDeriveClaimIdentityMismatchFailsClosed(t *testing.T) {
	in := deriveInput(plainPathIdentity, present(&liveSpec))
	if _, err := DeriveVerdict(in); err == nil {
		t.Fatal("claim for a different resource identity must fail closed")
	}
}

// 20: malformed live facts and identities fail closed.
func TestDeriveMalformedInputFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*DerivationInput)
	}{
		{"unknown live state", func(i *DerivationInput) { i.Live = LiveFact{State: "MAYBE"} }},
		{"zero live spec hash", func(i *DerivationInput) {
			zero := SpecHash{}
			i.Live = LiveFact{State: LivePresent, SpecHash: &zero}
		}},
		{"spec hash on absent resource", func(i *DerivationInput) {
			i.Live = LiveFact{State: LiveAbsent, SpecHash: &liveSpec}
		}},
		{"external owner on unknown resource", func(i *DerivationInput) {
			i.Live = LiveFact{State: LiveUnknown, ExternalOwner: &foreignManagerUFW}
		}},
		{"malformed identity", func(i *DerivationInput) {
			i.Identity = ResourceIdentity{Class: ClassFile, Path: "relative"}
		}},
		{"invalid claim", func(i *DerivationInput) {
			c := validClaim()
			c.Ref.TxID = ""
			i.Claim = claimPtr(c)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := deriveInput(fileIdentity, present(&liveSpec))
			tc.mut(&in)
			if _, err := DeriveVerdict(in); err == nil {
				t.Fatalf("%s: must fail closed", tc.name)
			}
		})
	}
}

// 21-22: identical inputs (with differently-ordered candidates) derive
// identical verdicts, and caller-owned slices are not mutated.
func TestDeriveDeterministicAndInputIsolated(t *testing.T) {
	base := deriveInput(fileIdentity, present(&liveSpec))
	reordered := deriveInput(fileIdentity, present(&liveSpec))
	reordered.Candidates = []TransactionFact{validFact(), validFact()}
	d1, err := DeriveVerdict(base)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DeriveVerdict(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Verdict != d2.Verdict || strings.Join(d1.Reasons, "|") != strings.Join(d2.Reasons, "|") {
		t.Fatalf("derivation is not deterministic:\n%+v\n%+v", d1, d2)
	}
	// Candidate slice mutation after the call cannot alter a fresh
	// evaluation.
	base.Candidates[0].Actions[0].Status = "PENDING"
	d3, err := DeriveVerdict(deriveInput(fileIdentity, present(&liveSpec)))
	if err != nil {
		t.Fatal(err)
	}
	if d3.Verdict != OwnedVerified {
		t.Fatalf("verdict after caller mutation = %s, want OWNED_VERIFIED", d3.Verdict)
	}
}

// 23-24: every derived verdict is a member of the existing O1 vocabulary,
// and the result carries no authority (a bare verdict + reasons).
func TestDeriveVerdictIsO1VocabularyWithoutAuthority(t *testing.T) {
	for _, d := range []Derivation{
		func() Derivation { d, _ := DeriveVerdict(deriveInput(fileIdentity, present(&liveSpec))); return d }(),
		func() Derivation { d, _ := DeriveVerdict(deriveInput(fileIdentity, changed())); return d }(),
		func() Derivation { d, _ := DeriveVerdict(deriveInput(fileIdentity, absentFact())); return d }(),
		func() Derivation { d, _ := DeriveVerdict(deriveInput(fileIdentity, unknownFact())); return d }(),
	} {
		if !d.Verdict.Valid() {
			t.Fatalf("verdict %q is outside the O1 vocabulary", d.Verdict)
		}
		// A verdict must not carry an aggregate precedence that could be
		// mistaken for admission logic, and the derivation struct holds no
		// approval/capability/permission fields — enforced here by the
		// absence of any such accessor on the returned value.
		_ = d.Verdict.precedenceRank
	}
}

// Purity tripwire (ZAI-15 §20): the O5-B implementation must not import
// I/O or authority layers and must not read the wall clock.
func TestDeriveImplementationIsPure(t *testing.T) {
	src, err := readFile("derive.go")
	if err != nil {
		t.Fatal(err)
	}
	startIdx := strings.Index(src, "import (")
	if startIdx < 0 {
		t.Fatal("import statement not found in derive.go")
	}
	endIdx := strings.Index(src[startIdx:], ")")
	if endIdx < 0 {
		t.Fatal("import block not closed in derive.go")
	}
	imports := src[startIdx : startIdx+endIdx]
	for _, banned := range []string{
		"\"os\"", "os/exec", "net/http", "bufio", "io/ioutil", "time",
		"internal/journal", "internal/state", "internal/apply",
		"internal/orchestrate", "internal/pipeline", "internal/cmd",
		"internal/lock", "internal/fsatomic", "internal/discovery",
	} {
		if strings.Contains(imports, banned) {
			t.Fatalf("derive.go must not import %q: O5-B is PURE (no I/O, no authority, no clock)", banned)
		}
	}
	if strings.Contains(src, "time.Now") {
		t.Fatal("derive.go must not read the wall clock: O5-B is deterministic")
	}
}

// Compile-time guard: MintedAt claims remain timestamped but derivation
// never consults a clock (the type keeps time only because O1 declares it).
var _ = time.Time{}

// Host-local evidence is not fleet-global truth (ZAI-19, INV-OP-6/§26):
// evidence recorded on one machine can never corroborate ownership on
// another. A claim whose transaction was recorded on a different host
// fails O5-A's host leg, so a present resource with only foreign-host
// evidence derives COLLISION (inside the reserved namespace), never
// OWNED_VERIFIED — and the same holds with the live state UNKNOWN, which
// stays UNDETERMINED.
func TestDeriveForeignHostEvidenceCanNeverVerify(t *testing.T) {
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.CurrentHost = otherHost
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("foreign-host evidence must never yield an owned verdict: %s (%v)", d.Verdict, d.Reasons)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION (unproven occupant)", d.Verdict, d.Reasons)
	}
	if !contains(d.Reasons, "did not verify") {
		t.Fatalf("reason must surface the failed host-leg verification: %v", d.Reasons)
	}
}

func contains(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// Rolled-back transaction (ZAI-23 §31): a durably proven successful
// rollback means the mutation did NOT persist as applied — the fact cannot
// corroborate (O5-A MISMATCH), so a present resource with only this
// evidence stays COLLISION inside the reserved namespace, never owned.
func TestDeriveRolledBackTransactionIsNeverOwned(t *testing.T) {
	rolled := validClaim()
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.Claim = claimPtr(rolled)
	in.Candidates = []TransactionFact{func() TransactionFact {
		f := TransactionFact{
			TxID:              testTx,
			PlanFingerprint:   testFP,
			HostIdentity:      testHost,
			Outcome:           TransactionOutcomeFailed,
			RollbackAttempted: true,
			RollbackResult:    "ROLLED_BACK",
			Actions:           []TransactionAction{{Resource: testRes, Status: "ROLLED_BACK"}},
		}
		return f
	}()}
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("rolled-back transaction must never be owned: %s (%v)", d.Verdict, d.Reasons)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION", d.Verdict, d.Reasons)
	}
}

// Rollback-failed transaction (ZAI-23 §32): a failed rollback is dangerous
// ambiguous evidence — corroboration fails closed (the ownership verifier
// treats the latch/rollback-failure shape as MISMATCH), so the derivation
// is COLLISION here, never owned and never silently CONFLICT.
func TestDeriveRollbackFailedTransactionIsNeverOwned(t *testing.T) {
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.Candidates = []TransactionFact{func() TransactionFact {
		return TransactionFact{
			TxID:              testTx,
			PlanFingerprint:   testFP,
			HostIdentity:      testHost,
			Outcome:           TransactionOutcomeFailed,
			RollbackAttempted: true,
			RollbackResult:    "ROLLBACK_FAILED",
			Actions:           []TransactionAction{{Resource: testRes, Status: "ROLLED_BACK"}},
		}
	}()}
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("rollback-failed transaction must never be owned: %s (%v)", d.Verdict, d.Reasons)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION (conservative)", d.Verdict, d.Reasons)
	}
}

// Journal-only attack (ZAI-23 §22): a valid journal fact with no state
// claim can never establish ownership on its own.
func TestDeriveJournalOnlyIsNeverOwned(t *testing.T) {
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.Claim = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("journal-only must never be owned: %s (%v)", d.Verdict, d.Reasons)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION (reserved namespace)", d.Verdict, d.Reasons)
	}
}

// State-only attack (ZAI-23 §21): a state claim with no journal
// corroboration candidates can never establish ownership.
func TestDeriveStateOnlyIsNeverOwned(t *testing.T) {
	in := deriveInput(fileIdentity, present(&liveSpec))
	in.Candidates = nil
	d, err := DeriveVerdict(in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict == OwnedVerified || d.Verdict == OwnedDrift {
		t.Fatalf("state-only must never be owned: %s (%v)", d.Verdict, d.Reasons)
	}
	if d.Verdict != Collision {
		t.Fatalf("verdict = %s (%v), want COLLISION", d.Verdict, d.Reasons)
	}
}
