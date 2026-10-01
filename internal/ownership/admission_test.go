package ownership

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// O6-A tests (ZAI-24 §27–§39): the complete operation × verdict admission
// table, typed-error boundaries, structural exclusion of approval and
// capability planes, determinism, and the ownership-leg boundary.

func admitOp(op Operation, v Verdict) (AdmissionDecision, error) {
	return Admit(op, v, ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/x.conf"})
}

// identityBirthright is the shared birthright-eligible test identity.
var identityBirthright = ResourceIdentity{Class: ClassFile, Path: "/etc/vps-gateway/x.conf"}

// §27: the complete operation × verdict table — every cell intentional.
func TestAdmitCompleteMatrix(t *testing.T) {
	build := func(op Operation, v Verdict, id ResourceIdentity, want Decision) func(*testing.T) {
		return func(t *testing.T) {
			d, err := Admit(op, v, id)
			if err != nil {
				t.Fatalf("Admit: %v", err)
			}
			if d.Decision != want {
				t.Fatalf("decision = %q (%v), want %q", d.Decision, d.Reasons, want)
			}
		}
	}

	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		// CREATE matrix.
		{"create/absent+birthright/allow", build(OperationCreate, Absent, identityBirthright, DecisionAllow)},
		{"create/absent+no-birthright/deny", build(OperationCreate, Absent, plainPathIdentity, DecisionDeny)},
		{"create/gone/deny", build(OperationCreate, Gone, identityBirthright, DecisionDeny)},
		{"create/unproven/deny", build(OperationCreate, Unproven, identityBirthright, DecisionDeny)},
		{"create/collision/deny", build(OperationCreate, Collision, identityBirthright, DecisionDeny)},
		{"create/conflict/deny", build(OperationCreate, Conflict, identityBirthright, DecisionDeny)},
		{"create/undetermined/undetermined", build(OperationCreate, Undetermined, identityBirthright, DecisionUndetermined)},
		{"create/owned-verified/deny", build(OperationCreate, OwnedVerified, identityBirthright, DecisionDeny)},
		{"create/owned-drift/deny", build(OperationCreate, OwnedDrift, identityBirthright, DecisionDeny)},
		// MODIFY matrix.
		{"modify/owned-verified/allow", build(OperationModify, OwnedVerified, identityBirthright, DecisionAllow)},
		{"modify/owned-drift/allow", build(OperationModify, OwnedDrift, identityBirthright, DecisionAllow)},
		{"modify/unproven/deny", build(OperationModify, Unproven, identityBirthright, DecisionDeny)},
		{"modify/collision/deny", build(OperationModify, Collision, identityBirthright, DecisionDeny)},
		{"modify/conflict/deny", build(OperationModify, Conflict, identityBirthright, DecisionDeny)},
		{"modify/undetermined/undetermined", build(OperationModify, Undetermined, identityBirthright, DecisionUndetermined)},
		{"modify/gone/deny", build(OperationModify, Gone, identityBirthright, DecisionDeny)},
		{"modify/absent/deny", build(OperationModify, Absent, identityBirthright, DecisionDeny)},
		// DELETE: deny across the board.
		{"delete/owned-verified/deny", build(OperationDelete, OwnedVerified, identityBirthright, DecisionDeny)},
		{"delete/absent/deny", build(OperationDelete, Absent, identityBirthright, DecisionDeny)},
		{"delete/unproven/deny", build(OperationDelete, Unproven, identityBirthright, DecisionDeny)},
		{"delete/gone/deny", build(OperationDelete, Gone, identityBirthright, DecisionDeny)},
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

// CREATE attack matrix (§29): birthright eligibility never converts
// occupied/conflicted/unknown targets.
func TestAdmitCreateBirthrightAttacks(t *testing.T) {
	cases := []struct {
		name string
		v    Verdict
	}{
		{"collision + birthright", Collision},
		{"unproven + birthright", Unproven},
		{"unknown + birthright", Undetermined},
		{"existing matching-shape object (owned-verified)", OwnedVerified},
		{"existing foreign object (conflict)", Conflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Admit(OperationCreate, tc.v, identityBirthright)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision == DecisionAllow {
				t.Fatalf("birthright attack must not gain admission: %s (%v)", d.Decision, d.Reasons)
			}
		})
	}
}

// MODIFY attack matrix (§30): unproven exact-shape, collision, conflict,
// undetermined, and external-owner conflict must never admit.
func TestAdmitModifyAttacks(t *testing.T) {
	cases := []struct {
		name string
		v    Verdict
	}{
		{"unproven exact shape match", Unproven},
		{"collision", Collision},
		{"conflict", Conflict},
		{"undetermined", Undetermined},
		{"external owner conflict", Conflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Admit(OperationModify, tc.v, identityBirthright)
			if err != nil {
				t.Fatal(err)
			}
			if d.Decision == DecisionAllow {
				t.Fatalf("attack must not gain modification admission: %s (%v)", d.Decision, d.Reasons)
			}
		})
	}
}

// DELETE (§31): denied across the board regardless of verdict — the
// dual-leg deletion authority is deliberately unmodeled.
func TestAdmitDeleteAlwaysDenied(t *testing.T) {
	for _, v := range []Verdict{OwnedVerified, OwnedDrift, Unproven, Collision, Conflict, Absent, Gone, Undetermined} {
		d, err := Admit(OperationDelete, v, identityBirthright)
		if err != nil {
			t.Fatalf("delete/%s: %v", v, err)
		}
		if d.Decision != DecisionDeny {
			t.Fatalf("delete/%s: decision = %q, want DENY", v, d.Decision)
		}
		if !hasAdmissionReason(d, ReasonDeletionNotModeled) {
			t.Fatalf("delete/%s: reason must name the unmodeled authority", v)
		}
	}
}

// GONE is not ABSENT (§11/§32): same operation, different decisions.
func TestAdmitGoneVsAbsentDistinction(t *testing.T) {
	gone, err := Admit(OperationCreate, Gone, identityBirthright)
	if err != nil {
		t.Fatal(err)
	}
	absent, err := Admit(OperationCreate, Absent, identityBirthright)
	if err != nil {
		t.Fatal(err)
	}
	if gone.Decision == absent.Decision {
		t.Fatalf("GONE and ABSENT must differ for CREATE: gone=%q absent=%q", gone.Decision, absent.Decision)
	}
}

// Structural exclusion (§36/§37): the Admit input is (Operation, Verdict,
// ResourceIdentity) — approval and capability values cannot reach the API
// at all. Pinned as a structural compile-level statement plus a check that
// the input types carry no such fields.
func TestAdmitStructurallyExcludesApprovalAndCapabilities(t *testing.T) {
	// The API signature accepts exactly three typed inputs; there is no
	// approval/capability/safety parameter. Enforce via the source.
	raw, err := os.ReadFile("admission.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, banned := range []string{"Approval", "Capability", "SafeToApply", "CanExecute", "Authorized"} {
		if strings.Contains(src, banned) {
			t.Fatalf("admission.go must not reference %q: the ownership leg is structurally separate from approval/capability/authority planes", banned)
		}
	}
}

// Invalid input (§39): unknown operation and unknown verdict are errors
// (structurally invalid), distinct from valid-but-prohibited (DENY).
func TestAdmitInvalidInputIsErrorNotDeny(t *testing.T) {
	if _, err := Admit(Operation("EXPLODE"), OwnedVerified, identityBirthright); !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("unknown operation: %v", err)
	}
	if _, err := Admit(OperationModify, Verdict("KIND_OF_OWNED"), identityBirthright); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("unknown verdict: %v", err)
	}
	// Malformed identity fails closed even for a benign verdict.
	if _, err := Admit(OperationCreate, Absent, ResourceIdentity{Class: ClassFile, Path: "relative"}); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatal("malformed identity must fail closed")
	}
}

// Determinism (§24): same inputs → same decision and reasons.
func TestAdmitDeterministic(t *testing.T) {
	d1, err := Admit(OperationModify, OwnedVerified, identityBirthright)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Admit(OperationModify, OwnedVerified, identityBirthright)
	if err != nil {
		t.Fatal(err)
	}
	if d1.Decision != d2.Decision || strings.Join(admissionReasonStrings(d1), "|") != strings.Join(admissionReasonStrings(d2), "|") {
		t.Fatalf("nondeterministic: %+v vs %+v", d1, d2)
	}
}

// Vocabulary integrity: decisions, reasons and operations are closed sets
// with no authority-bearing names.
func TestAdmitVocabularyIntegrity(t *testing.T) {
	for _, d := range []Decision{DecisionAllow, DecisionDeny, DecisionUndetermined} {
		if !d.Valid() {
			t.Fatalf("decision %q invalid", d)
		}
		if strings.Contains(strings.ToUpper(string(d)), "AUTHORIZED") {
			t.Fatalf("decision %q carries authority semantics", d)
		}
	}
	for _, r := range []AdmissionReason{
		ReasonVerifiedOwner, ReasonDriftRepairOwned, ReasonBirthrightFirstCreation,
		ReasonTargetAbsent, ReasonUnprovenOccupant, ReasonCollisionReserved,
		ReasonConflictEvidence, ReasonUndeterminedOwnership, ReasonGoneNotAuthorizing,
		ReasonAlreadyPresent, ReasonNothingToModify, ReasonDeletionNotModeled,
		ReasonOperationUnknown, ReasonVerdictUnknown,
	} {
		upper := strings.ToUpper(string(r))
		for _, banned := range []string{"AUTHORIZED", "MAY_MUTATE", "APPROVED"} {
			if strings.Contains(upper, banned) {
				t.Fatalf("reason %q carries authority semantics", r)
			}
		}
	}
	for _, op := range []Operation{OperationCreate, OperationModify, OperationDelete} {
		if !op.Valid() {
			t.Fatalf("operation %q invalid", op)
		}
	}
	if Operation("RECOVER").Valid() {
		t.Fatal("RECOVER must not be part of the ownership-leg operation vocabulary")
	}
}

func hasAdmissionReason(d AdmissionDecision, want AdmissionReason) bool {
	for _, r := range d.Reasons {
		if r == want {
			return true
		}
	}
	return false
}

func admissionReasonStrings(d AdmissionDecision) []string {
	out := make([]string, 0, len(d.Reasons))
	for _, r := range d.Reasons {
		out = append(out, string(r))
	}
	return out
}
