// Live + evidence ownership verdict derivation (O5-B, ZAI-08 §9 /
// HANDOFF-2026-09-28 §J): PURE, deterministic derivation of one ownership
// verdict from the existing O1 vocabulary for one resource, combining
//
//   - the O5-A evidence-corroboration result (Corroborate — the only
//     evidence primitive; its checks are never re-implemented here);
//   - typed, injected live facts about the resource (nothing is read from
//     any machine, file, journal or state document);
//   - the compiled O1 birthright/namespace contract.
//
// The result classifies the resource's ownership status. It is a fact, not
// a permission: even OWNED_VERIFIED here means only "durable evidence and
// live state agree that this resource is project-owned" — never approval,
// capability, admission or mutation authority. Drift never auto-repairs; a
// collision never auto-resolves; an external manager is never adopted.
//
// Fleet-lesson boundaries pinned by tests (2026-09-29/30 evidence): an
// exact desired/live match without a verified claim is never owned; an
// effective sysctl value contributed by a foreign fragment is not project
// ownership; external managers (Docker/UFW/3X-UI/Amnezia/operator) are
// never adopted; IPv6 connectivity/health is out of scope entirely.
package ownership

import (
	"fmt"
	"strings"
)

// LiveState is the closed vocabulary of live observation sufficiency.
// Absence must be positively established by a PRESENT-status inventory;
// a failed command, an unsupported parser or an incomplete inventory is
// UNKNOWN — never absence (UNKNOWN != absent).
type LiveState string

const (
	// LivePresent: the resource was positively observed to exist.
	LivePresent LiveState = "PRESENT"
	// LiveAbsent: absence was positively established by a trustworthy
	// inventory (not by a failed lookup).
	LiveAbsent LiveState = "ABSENT"
	// LiveUnknown: the live state could not be established.
	LiveUnknown LiveState = "UNKNOWN"
)

// Valid reports whether s is a member of the closed vocabulary.
func (s LiveState) Valid() bool {
	switch s {
	case LivePresent, LiveAbsent, LiveUnknown:
		return true
	}
	return false
}

// LiveFact is the typed live observation for one resource. The spec hash
// is the hash of the live representation when the resource class allows
// computing one (files and the sysctl drop-in today); for classes without
// an observable live representation it stays nil and any owned-presence
// derivation fails closed to UNDETERMINED rather than guessing. The
// external owner, when positively established by observation, records
// which external manager controls the resource.
type LiveFact struct {
	State         LiveState
	SpecHash      *SpecHash
	ExternalOwner *ExternalClass
}

// Validate fail-closes malformed live facts.
func (f LiveFact) Validate() error {
	if !f.State.Valid() {
		return fmt.Errorf("invalid live state %q", f.State)
	}
	if f.SpecHash != nil {
		if f.SpecHash.IsZero() {
			return fmt.Errorf("live fact carries a zero spec hash")
		}
		if f.State != LivePresent {
			return fmt.Errorf("a spec hash is only meaningful for a PRESENT resource")
		}
	}
	if f.ExternalOwner != nil && f.State != LivePresent {
		return fmt.Errorf("an external owner is only meaningful for a PRESENT resource")
	}
	return nil
}

// DerivationInput is the typed input of DeriveVerdict. The claim and the
// corroboration candidates are the O5-A inputs: when a claim is supplied,
// Corroborate is the sole evidence primitive consulted.
type DerivationInput struct {
	// Identity is the resource the verdict is about. A supplied claim must
	// carry exactly this identity.
	Identity ResourceIdentity
	// Live is the injected live observation.
	Live LiveFact
	// Claim is the persisted ownership-evidence claim under consideration,
	// or nil when no evidence claim exists.
	Claim *StateEvidence
	// JournalResource, Candidates and CurrentHost are the O5-A
	// corroboration inputs (see Corroborate).
	JournalResource string
	Candidates      []TransactionFact
	CurrentHost     string
}

// Derivation is the deterministic result: the O1 verdict plus the reasons
// that produced it. It carries no authority.
type Derivation struct {
	Verdict Verdict
	Reasons []string
}

// DeriveVerdict derives the ownership verdict for one resource from live
// facts and durable evidence. Deterministic and fail-closed: unknown live
// state is UNDETERMINED (never ABSENT or GONE), an unverified claim is
// treated as no evidence (never GONE), a positively observed foreign or
// unproven occupant of a birthright identity is COLLISION, and the
// spec-drift verdict is class-dependent (files drift, network objects
// conflict). The verdict is classification only — never mutation
// authority, never adoption, never repair permission.
func DeriveVerdict(in DerivationInput) (Derivation, error) {
	if err := in.Identity.Validate(); err != nil {
		return Derivation{}, fmt.Errorf("resource identity: %v", err)
	}
	if err := in.Live.Validate(); err != nil {
		return Derivation{}, fmt.Errorf("live fact: %v", err)
	}
	if in.Claim != nil {
		if err := in.Claim.Validate(); err != nil {
			return Derivation{}, fmt.Errorf("%w: claim: %v", ErrInvalidEvidence, err)
		}
		if in.Claim.Identity != in.Identity {
			return Derivation{}, fmt.Errorf("%w: claim is for a different resource identity", ErrInvalidEvidence)
		}
	}

	// UNKNOWN live state dominates: uncertainty is never downgraded into a
	// proven state, whatever the evidence says.
	if in.Live.State == LiveUnknown {
		return undetermined("live state could not be established (inventory failed, incomplete or ambiguous)"), nil
	}

	verified := false
	var evidenceReason string
	if in.Claim != nil {
		v, err := Corroborate(VerificationInput{
			Claim:           *in.Claim,
			JournalResource: in.JournalResource,
			Candidates:      in.Candidates,
			CurrentHost:     in.CurrentHost,
		})
		if err != nil {
			// Ambiguous or malformed history fails closed; it is never
			// resolved by choice (P1-B stays intact).
			return Derivation{}, err
		}
		verified = v.Status == VerificationVerified
		evidenceReason = fmt.Sprintf("evidence claim did not verify (%s: %s)", v.Status, strings.Join(v.Reasons, "; "))
	}

	switch in.Live.State {
	case LiveAbsent:
		if verified {
			return derivation(Gone, "durable evidence proves prior project ownership and the live inventory positively establishes absence"), nil
		}
		// An unverified claim is not proven history: absence without proven
		// ownership is ABSENT (a potential first-creation situation —
		// ABSENT is still not a creation permission).
		return derivation(Absent, "live inventory positively establishes absence and no verified ownership evidence exists"), nil

	case LivePresent:
		if verified {
			// A positively established external manager contradicts the
			// evidence: the resource may still be "ours" historically, but
			// an external owner now controls it — a network/config owner
			// conflict, never a silent drift.
			if in.Live.ExternalOwner != nil {
				return derivation(Conflict, fmt.Sprintf("durable evidence proves project ownership but live observation establishes external management (%s)", *in.Live.ExternalOwner)), nil
			}
			// Spec fidelity: the live representation hash must agree with
			// the evidenced spec. Without an observable live representation
			// the proof is incomplete — owned presence is never guessed.
			if in.Live.SpecHash == nil {
				return undetermined("resource is present but its live representation is not observable for this class; spec fidelity cannot be proven"), nil
			}
			if *in.Live.SpecHash == in.Claim.Spec {
				return derivation(OwnedVerified, "durable evidence corroborates the claim and the live resource matches the evidenced specification"), nil
			}
			// Spec drift is class-dependent: file-shaped resources drift
			// (restorable with fresh authorization); network objects
			// conflict (never automatic repair).
			switch in.Identity.Class {
			case ClassFile, ClassSysctlDropIn:
				return derivation(OwnedDrift, "durable evidence proves project ownership but the live file-shaped resource no longer matches the evidenced specification"), nil
			default:
				return derivation(Conflict, "durable evidence proves project ownership but the live network resource no longer matches the evidenced specification"), nil
			}
		}
		// Present without verified evidence: matching anything (desired
		// content, a project prefix, an external manager's output) is not
		// provenance. The only distinction is whether the occupied identity
		// is project-reserved.
		if evidenceReason != "" {
			return unprovenLike(in, "resource is present but "+evidenceReason), nil
		}
		return unprovenLike(in, "resource is present without any corroborated ownership evidence"), nil
	}
	// LiveUnknown was handled above; the closed vocabulary makes this
	// unreachable.
	return undetermined("unreachable live state"), nil
}

// unprovenLike classifies an occupied resource without verified evidence:
// inside a birthright namespace the occupant is a COLLISION (foreign
// occupancy of a reserved identity); outside it the resource is UNPROVEN.
// Neither is ownership, and neither grants repair or removal.
func unprovenLike(in DerivationInput, reason string) Derivation {
	eligible, err := BirthrightEligible(in.Identity)
	if err != nil {
		// Malformed identities were rejected at the input boundary; this is
		// defensive only.
		return undetermined("birthright classification failed for the occupied identity")
	}
	if eligible {
		return derivation(Collision, reason+"; the identity is project-reserved and its occupancy is unproven (COLLISION)")
	}
	return derivation(Unproven, reason+" (UNPROVEN)")
}

func derivation(v Verdict, reason string) Derivation {
	return Derivation{Verdict: v, Reasons: []string{reason}}
}

func undetermined(reason string) Derivation {
	return Derivation{Verdict: Undetermined, Reasons: []string{reason}}
}
