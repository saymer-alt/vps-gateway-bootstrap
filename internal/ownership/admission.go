package ownership

// Ownership admission decision model (O6-A, ZAI-24): the PURE ownership
// leg of admission — one operation against one derived ownership verdict,
// resolved through a fully explicit decision table.
//
// Boundary (binding): this layer answers only
//
//	"would the ownership dimension of admission permit this operation?"
//
// It does NOT authorize mutation. OWNED_VERIFIED must never mean "mutation
// is globally authorized": approval validity, capability satisfaction,
// leak/sysctl/recovery safety, plan validity and executor availability are
// separate planes owned by other layers (and none of them is consulted
// here — structurally: this API accepts no such input). Nothing in
// production consumes the result.
//
// Design rules implemented here:
//
//   - closed operation vocabulary; unknown values fail closed;
//   - no implicit default ALLOW: every operation × verdict cell is an
//     intentional table entry, unspecified shapes fail closed;
//   - CREATE requires a positively ABSENT target inside a birthright-
//     eligible namespace (BirthrightEligible is the compiled contract —
//     consumed as a typed fact, never recomputed from names); ABSENT
//     alone never authorizes creation;
//   - MODIFY requires OWNED_VERIFIED (ownership leg satisfied), or
//     OWNED_DRIFT with the bounded meaning "repair to the proven
//     specification" (file-shaped classes only — the derivation already
//     scopes drift verdicts that way);
//   - DELETE is DENY across the board: deletion/decommission authority is
//     a dual-leg design (strong ownership + purpose-bound authorization)
//     that the repository has deliberately not modeled yet (ZAI-08 §15);
//     ownership alone never implies deletion;
//   - GONE never counts as ABSENT: recreation on a GONE location is DENIED
//     at this layer (a fresh admission on a resolved location is the
//     designed path);
//   - UNPROVEN, COLLISION, CONFLICT and UNDETERMINED always DENY:
//     matching shape, project-looking names and birthright eligibility
//     never convert them.
//
// Deterministic and PURE: no I/O, no clock, no environment — typed inputs
// only. Input ordering cannot affect the result (single verdict, no
// aggregation here; multi-evidence aggregation happens in DeriveVerdict
// upstream under the O1 precedence).

import (
	"errors"
	"fmt"
)

// Operation is the closed admission-operation vocabulary. It expresses the
// ownership-leg kind of an operation, not an ActionKind and not a
// capability; unknown values fail closed.
type Operation string

const (
	// OperationCreate: bring a positively absent resource into existence
	// (first creation in a birthright-eligible location).
	OperationCreate Operation = "CREATE"
	// OperationModify: change an existing resource (update/repair).
	OperationModify Operation = "MODIFY"
	// OperationDelete: remove an existing resource. The repository has
	// deliberately not modeled deletion/decommission authority (dual-leg
	// design, ZAI-08 §15); this operation is defined so the policy can
	// answer it explicitly — always DENY at this layer.
	OperationDelete Operation = "DELETE"
)

// Valid reports whether op is a member of the closed vocabulary.
func (op Operation) Valid() bool {
	switch op {
	case OperationCreate, OperationModify, OperationDelete:
		return true
	}
	return false
}

// Decision is the closed admission-decision vocabulary. DENY and
// UNDETERMINED are deliberately distinct: DENY is a known prohibition,
// UNDETERMINED is insufficient knowledge — booleans would erase that
// distinction.
type Decision string

const (
	DecisionAllow        Decision = "ALLOW"
	DecisionDeny         Decision = "DENY"
	DecisionUndetermined Decision = "UNDETERMINED"
)

// Valid reports whether d is a member of the closed vocabulary.
func (d Decision) Valid() bool {
	switch d {
	case DecisionAllow, DecisionDeny, DecisionUndetermined:
		return true
	}
	return false
}

// AdmissionReason is the closed machine-readable reason vocabulary for
// admission decisions. Security-relevant branching must branch on these,
// never on prose.
type AdmissionReason string

const (
	ReasonVerifiedOwner           AdmissionReason = "VERIFIED_OWNER"
	ReasonDriftRepairOwned        AdmissionReason = "OWNED_DRIFT_REPAIR"
	ReasonBirthrightFirstCreation AdmissionReason = "BIRTHRIGHT_FIRST_CREATION"
	ReasonTargetAbsent            AdmissionReason = "TARGET_ABSENT"
	ReasonUnprovenOccupant        AdmissionReason = "UNPROVEN_OCCUPANT"
	ReasonCollisionReserved       AdmissionReason = "COLLISION_RESERVED_IDENTITY"
	ReasonConflictEvidence        AdmissionReason = "CONFLICT_EVIDENCE"
	ReasonUndeterminedOwnership   AdmissionReason = "UNDETERMINED_OWNERSHIP"
	ReasonGoneNotAuthorizing      AdmissionReason = "GONE_NOT_AUTHORIZING"
	ReasonAlreadyPresent          AdmissionReason = "ALREADY_PRESENT"
	ReasonNothingToModify         AdmissionReason = "NOTHING_TO_MODIFY"
	ReasonDeletionNotModeled      AdmissionReason = "DELETION_AUTHORITY_NOT_MODELED"
	ReasonOperationUnknown        AdmissionReason = "OPERATION_UNKNOWN"
	ReasonVerdictUnknown          AdmissionReason = "VERDICT_UNKNOWN"
)

// AdmissionDecision is the deterministic result: a decision plus the
// closed reasons that produced it. It carries no authority.
type AdmissionDecision struct {
	Decision Decision
	Reasons  []AdmissionReason
}

// ErrUnknownOperation classifies operation values outside the closed
// vocabulary.
var ErrUnknownOperation = errors.New("unknown admission operation")

// Admit resolves the ownership leg of admission for one operation against
// one derived ownership verdict. Every operation × verdict cell is an
// intentional table entry; unknown operation or verdict values fail closed
// with an error (never a decision).
func Admit(op Operation, verdict Verdict, identity ResourceIdentity) (AdmissionDecision, error) {
	if !op.Valid() {
		return AdmissionDecision{}, fmt.Errorf("%w: %q", ErrUnknownOperation, string(op))
	}
	if !verdict.Valid() {
		return AdmissionDecision{}, fmt.Errorf("%w: %q", ErrInvalidVerdict, string(verdict))
	}
	// DELETE: deletion/decommission authority is a dual-leg design the
	// repository has deliberately not modeled. Ownership alone never
	// implies deletion — DENY across the board, for every verdict.
	if op == OperationDelete {
		return AdmissionDecision{
			Decision: DecisionDeny,
			Reasons:  []AdmissionReason{ReasonDeletionNotModeled},
		}, nil
	}
	if err := identity.Validate(); err != nil {
		return AdmissionDecision{}, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
	}

	switch op {
	case OperationCreate:
		switch verdict {
		case Absent:
			eligible, err := BirthrightEligible(identity)
			if err != nil {
				return AdmissionDecision{}, fmt.Errorf("%w: %v", ErrInvalidIdentity, err)
			}
			if eligible {
				return AdmissionDecision{
					Decision: DecisionAllow,
					Reasons:  []AdmissionReason{ReasonBirthrightFirstCreation, ReasonTargetAbsent},
				}, nil
			}
			return AdmissionDecision{
				Decision: DecisionDeny,
				Reasons:  []AdmissionReason{ReasonTargetAbsent},
			}, nil
		case Unproven:
			return admitDeny(ReasonUnprovenOccupant), nil
		case Collision:
			return admitDeny(ReasonCollisionReserved), nil
		case Conflict:
			return admitDeny(ReasonConflictEvidence), nil
		case Undetermined:
			return admitUndetermined(ReasonUndeterminedOwnership), nil
		case Gone:
			// Proven provenance + proven absence: recreation is a fresh
			// authority decision, never implied by GONE (GONE is not
			// ABSENT).
			return admitDeny(ReasonGoneNotAuthorizing), nil
		case OwnedVerified, OwnedDrift:
			return admitDeny(ReasonAlreadyPresent), nil
		default:
			return AdmissionDecision{}, fmt.Errorf("%w: %q", ErrInvalidVerdict, string(verdict))
		}
	case OperationModify:
		switch verdict {
		case OwnedVerified:
			// Ownership leg satisfied; approval/capability/safety planes
			// are separate and must be checked by later admission layers.
			return AdmissionDecision{
				Decision: DecisionAllow,
				Reasons:  []AdmissionReason{ReasonVerifiedOwner},
			}, nil
		case OwnedDrift:
			// Bounded drift-repair semantics: the derivation scopes drift
			// verdicts to file-shaped classes, and repair means "restore
			// the proven specification" — never arbitrary mutation.
			return AdmissionDecision{
				Decision: DecisionAllow,
				Reasons:  []AdmissionReason{ReasonDriftRepairOwned},
			}, nil
		case Unproven:
			return admitDeny(ReasonUnprovenOccupant), nil
		case Collision:
			return admitDeny(ReasonCollisionReserved), nil
		case Conflict:
			return admitDeny(ReasonConflictEvidence), nil
		case Undetermined:
			return admitUndetermined(ReasonUndeterminedOwnership), nil
		case Gone:
			return admitDeny(ReasonGoneNotAuthorizing), nil
		case Absent:
			return admitDeny(ReasonNothingToModify), nil
		default:
			return AdmissionDecision{}, fmt.Errorf("%w: %q", ErrInvalidVerdict, string(verdict))
		}
	case OperationDelete:
		// Handled above (verdict-independent DENY); unreachable.
		return admitDeny(ReasonDeletionNotModeled), nil
	default:
		return AdmissionDecision{}, fmt.Errorf("%w: %q", ErrUnknownOperation, string(op))
	}
}

func admitDeny(reason AdmissionReason) AdmissionDecision {
	return AdmissionDecision{Decision: DecisionDeny, Reasons: []AdmissionReason{reason}}
}

func admitUndetermined(reason AdmissionReason) AdmissionDecision {
	return AdmissionDecision{Decision: DecisionUndetermined, Reasons: []AdmissionReason{reason}}
}
