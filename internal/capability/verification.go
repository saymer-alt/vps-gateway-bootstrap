// Capability-grant verification (C4, ZAI-27 / O6-B audit §20 prerequisite 2):
// a PURE, deterministic, total check that an explicitly granted canonical
// capability set EXACTLY matches the canonical capability set a plan
// requires.
//
// It answers exactly one question:
//
//	given the canonical required set (e.g. derived by the C3-A plan
//	mapper) and a canonical granted set supplied by some future
//	authority source, are the requirements satisfied?
//
// It answers nothing else:
//
//   - NOT where the grant came from: no approval parsing, no signature
//     checking, no config/environment/plan/executor/ownership/operator
//     inference, no grant creation. The authenticated grant source is a
//     future layer (approval-v2, operator decisions G2/G4 — both open).
//   - NOT whether the plan may execute: SATISFIED is one leg of the
//     reconstructed admission equation (O6-B audit §4), never mutation
//     authority. No production path consumes this package.
//
// Binding contract — EXACT-SET equality (not subset authorization):
//
//	required = {A}   granted = {A}     → SATISFIED
//	required = {A}   granted = {A,B}   → MISMATCH (Unexpected = {B})
//	required = {A,B} granted = {A}     → MISMATCH (Missing = {B})
//
// The repository chose exact-set in the decided approval architecture
// (docs/security-model.md §6: the approval payload binds "the named
// capability set the plan exercises", so "the operator approved plan F"
// means "the operator granted capabilities {…} to this exact action set")
// and pinned it in the O6-B audit's admission equation ("C3-A derived ==
// approval-granted, exact set"). Over-granting is itself an authorization
// mismatch: an approval must never silently carry broader authority than
// the plan it covers, and since the capability set is inside the signed
// fingerprint coverage, a different set is a different approval. Do not
// weaken this to subset semantics for convenience.
//
// Error vs mismatch: structural validation happens at set construction
// (NewCapabilitySet rejects unknown, malformed, duplicate members;
// ParseCapability rejects noncanonical representation), so a CapabilitySet
// value can never carry structurally invalid data. VerifyCapabilityGrant is
// therefore TOTAL over valid sets — its only outcomes are SATISFIED and
// MISMATCH. A missing required capability and an unexpected granted
// capability are authorization mismatches, never parser errors.
package capability

// GrantVerificationStatus is the closed result vocabulary for C4.
// Deliberately authority-free naming: SATISFIED says the sets match; it
// never says the plan is authorized.
type GrantVerificationStatus string

const (
	// GrantSatisfied: granted is canonically identical to required.
	GrantSatisfied GrantVerificationStatus = "SATISFIED"
	// GrantMismatch: the sets differ (missing requirements, unexpected
	// grants, or both).
	GrantMismatch GrantVerificationStatus = "MISMATCH"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s GrantVerificationStatus) Valid() bool {
	switch s {
	case GrantSatisfied, GrantMismatch:
		return true
	}
	return false
}

// GrantVerification is the result of one exact-set check. Missing and
// Unexpected are meaningful only when Status is GrantMismatch; both are
// always non-nil freshly-allocated slices in canonical sorted order
// (possibly empty), so callers can never mutate verifier state through
// them.
type GrantVerification struct {
	Status GrantVerificationStatus
	// Missing = Required − Granted: requirements the grant does not cover.
	Missing []CapabilityID
	// Unexpected = Granted − Required: authority the grant carries beyond
	// the plan's requirements. Non-empty Unexpected alone is a mismatch:
	// over-granting is itself an authorization mismatch.
	Unexpected []CapabilityID
}

// VerifyCapabilityGrant checks the exact-set match between the canonical
// required set (typically the output of the C3-A plan mapper) and the
// canonical granted set (typed input from a future authenticated grant
// source). Required and granted are structurally distinct inputs: no
// function in this package derives a grant set from a required set — a
// plan can never grant itself the capabilities it requires.
//
// The check operates on canonical CapabilityID identity — byte equality of
// the canonical string — so two capabilities sharing a vocabulary name but
// differing in any parameter are different capabilities. Deterministic and
// order-independent: both inputs are canonical sorted sets, and the
// reported Missing/Unexpected sets are in canonical order.
func VerifyCapabilityGrant(required, granted CapabilitySet) GrantVerification {
	req := required.IDs()
	gra := granted.IDs()
	// Both slices are canonically sorted (CapabilitySet invariant), so a
	// sorted-set difference walk yields canonical order directly.
	missing, unexpected := setDifference(req, gra)
	v := GrantVerification{
		Missing:    missing,
		Unexpected: unexpected,
	}
	if len(missing) == 0 && len(unexpected) == 0 {
		v.Status = GrantSatisfied
	} else {
		v.Status = GrantMismatch
	}
	return v
}

// setDifference returns a−b and b−a over two canonically sorted, duplicate
// -free slices, each result freshly allocated in canonical order.
func setDifference(a, b []CapabilityID) (aMinusB, bMinusA []CapabilityID) {
	aMinusB = []CapabilityID{}
	bMinusA = []CapabilityID{}
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] < b[j]:
			aMinusB = append(aMinusB, a[i])
			i++
		case a[i] > b[j]:
			bMinusA = append(bMinusA, b[j])
			j++
		default:
			i++
			j++
		}
	}
	aMinusB = append(aMinusB, a[i:]...)
	bMinusA = append(bMinusA, b[j:]...)
	return aMinusB, bMinusA
}
