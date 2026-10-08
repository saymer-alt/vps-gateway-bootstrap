// Typed MSS mutation action contract (ZAI-51, OWNER-AUTHORIZED INTENT
// ONLY): the typed representation of the ONE future mutation — ensure the
// ZAI-50 project MSS clamp rule — plus the PURE conversion from the
// frozen desired contract and the PURE planner.
//
//	TYPED MUTATION INTENT != MUTATION AUTHORITY
//	PLAN != PROVENANCE
//
// Nothing here executes, registers an executor, writes a journal record,
// mints StateEvidence, infers ownership, adopts, replaces or deletes.
// ActionFirewall stays Defined:false — the bridge from this typed intent
// to a state.Action (and the ActionKind choice) is the future
// owner-authorized mutation task's decision.
//
// ActionSpecHash relationship (§5): the MSS semantic SpecHash
// (vps-gateway/mss-rule-spec/v1, SpecFingerprint) answers "what MSS rule
// semantics?"; the future state-level ActionSpecHash (action-spec/v1
// domain over the whole typed action spec) answers "what mutation action
// was planned?". They are different questions in different domains — the
// semantic hash is CARRIED by the intent as a field and is never
// substituted for an action hash. The intent's own hash leg is always
// RECOMPUTED from the spec (a caller-supplied hash is never trusted).
//
// PURE: typed in, typed out; no I/O, no clock, no commands; inputs never
// mutated; deterministic.
package mssspec

import (
	"errors"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// MSSActionSpec is the typed mutation intent for the project MSS clamp
// rule: the exact resource coordinate, the exact semantic spec (always
// inside the ZAI-50 frozen envelope) and the recomputed semantic hash. It
// carries no raw iptables text, no shell string, no HostIdentity, no
// approval, no journal provenance, no LiveFact, no StateEvidence and no
// ownership verdict.
type MSSActionSpec struct {
	Identity ownership.ResourceIdentity
	Spec     Spec
	SpecHash ownership.SpecHash
}

// Typed action-intent failures.
var (
	ErrMSSActionIdentityInvalid = errors.New("MSS action requires a valid ClassMSSRule identity")
	ErrMSSActionSpecInvalid     = errors.New("MSS action requires a spec inside the frozen MSS envelope")
	ErrMSSActionHashMismatch    = errors.New("MSS action spec hash does not match the recomputed fingerprint of its spec")
)

// BuildMSSAction converts one desired MSS declaration into the typed
// mutation intent. PURE and deterministic; the input is never mutated.
//
// Mandatory consistency checks (§6) — every leg fails closed:
//   - the identity validates and is ClassMSSRule;
//   - the chain/tag satisfy the ZAI-50 project namespace contract;
//   - the spec validates inside the frozen MSS envelope;
//   - the identity coordinate corresponds to the spec chain (identity
//     and spec can never disagree about the chain);
//   - the supplied SpecHash equals the RECOMPUTED SpecFingerprint of the
//     spec — a forged or stale hash is refused, never trusted.
func BuildMSSAction(rule DesiredMSSRule) (MSSActionSpec, error) {
	if err := rule.Identity.Validate(); err != nil {
		return MSSActionSpec{}, fmt.Errorf("%w: %v", ErrMSSActionIdentityInvalid, err)
	}
	if rule.Identity.Class != ownership.ClassMSSRule {
		return MSSActionSpec{}, fmt.Errorf("%w: class %q", ErrMSSActionIdentityInvalid, rule.Identity.Class)
	}
	if err := validateProjectChain(rule.Identity.Chain); err != nil {
		return MSSActionSpec{}, fmt.Errorf("%w: %v", ErrMSSActionIdentityInvalid, err)
	}
	if err := validateProjectTag(rule.Identity.Tag); err != nil {
		return MSSActionSpec{}, fmt.Errorf("%w: %v", ErrMSSActionIdentityInvalid, err)
	}
	if err := rule.Spec.Validate(); err != nil {
		return MSSActionSpec{}, fmt.Errorf("%w: %v", ErrMSSActionSpecInvalid, err)
	}
	// The frozen ZAI-50 contract fixes the table to mangle — Validate
	// (the observation envelope) accepts verbatim table values, but a
	// MUTATION intent outside the fixed contract is refused here, before
	// any command derivation could hardcode "-t mangle" against it.
	if rule.Spec.Table != "mangle" {
		return MSSActionSpec{}, fmt.Errorf("%w: table %q is outside the frozen MSS contract (fixed: mangle)", ErrMSSActionSpecInvalid, rule.Spec.Table)
	}
	if rule.Identity.Chain != rule.Spec.Chain {
		return MSSActionSpec{}, fmt.Errorf("%w: identity chain %q disagrees with spec chain %q", ErrMSSActionIdentityInvalid, rule.Identity.Chain, rule.Spec.Chain)
	}
	recomputed, err := SpecFingerprint(rule.Spec)
	if err != nil {
		return MSSActionSpec{}, fmt.Errorf("%w: %v", ErrMSSActionSpecInvalid, err)
	}
	if recomputed != rule.SpecHash {
		return MSSActionSpec{}, ErrMSSActionHashMismatch
	}
	return MSSActionSpec{Identity: rule.Identity, Spec: rule.Spec, SpecHash: recomputed}, nil
}

// RequiredMSSCapability derives the exact PURE capability requirement of
// one MSS action: the compiled muvg.firewall.mssclamp.v1 bound to the
// action's exact egress interface (the single element canonicalizes to
// itself). No wildcard, no generic firewall capability, no widening to
// other tables/chains/actions. Derivation only — no admission, no
// execution.
func RequiredMSSCapability(a MSSActionSpec) (capability.CapabilityID, error) {
	if err := a.Spec.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMSSActionSpecInvalid, err)
	}
	return capability.DeriveFirewallMSSClamp([]string{a.Spec.OutInterface})
}

// MSSPlannerOutcome is the closed planner decision vocabulary (§7).
type MSSPlannerOutcome string

const (
	// PlannerNoAction: the desired state is already satisfied by an
	// existing rule — nothing to do. Provenance stays unproven.
	PlannerNoAction MSSPlannerOutcome = "NO_ACTION"
	// PlannerCreateMSSRule: absence is POSITIVELY proven (complete
	// mangle inventory, no coordinate occupant) — a candidate insertion
	// intent exists. This is intent, never execution authority.
	PlannerCreateMSSRule MSSPlannerOutcome = "CREATE_MSS_RULE"
	// PlannerBlockedCollision: the coordinate is occupied by a
	// semantically different rule — blocked; never a replacement.
	PlannerBlockedCollision MSSPlannerOutcome = "BLOCKED_COLLISION"
	// PlannerUnknown: the live state could not be characterized — no
	// CREATE (UNKNOWN != ABSENT).
	PlannerUnknown MSSPlannerOutcome = "UNKNOWN"
	// PlannerBlockedPrerequisite: the coordinate-level prerequisites are
	// met but a structural chain/hook prerequisite is PROVEN violated —
	// chain absent, built-in-where-user-defined-required, unattached,
	// provably shadowed or excluding attachment (ZAI-63). Never a
	// replacement; never auto-repair.
	PlannerBlockedPrerequisite MSSPlannerOutcome = "BLOCKED_PREREQUISITE"
)

// Valid reports whether o is a member of the closed vocabulary.
func (o MSSPlannerOutcome) Valid() bool {
	switch o {
	case PlannerNoAction, PlannerCreateMSSRule, PlannerBlockedCollision, PlannerUnknown, PlannerBlockedPrerequisite:
		return true
	}
	return false
}

// MSSPlanDecision is one planner verdict. Action is non-nil exactly when
// Outcome is PlannerCreateMSSRule (a candidate intent — never authority).
// The decision carries no evidence, no provenance and no ownership.
type MSSPlanDecision struct {
	Outcome MSSPlannerOutcome
	Action  *MSSActionSpec
	Reasons []string
}

// PlanMSSAction plans the future MSS mutation for one desired rule
// against one observation of the same coordinate AND one structural
// chain/hook assessment of the target chain (ZAI-63 — computed by
// ObserveChainSuitability from the SAME snapshot the observation came
// from). PURE and deterministic.
//
// Semantics (§7–§10), reusing the ZAI-50 collision classification (no
// second collision engine) and the ZAI-48 observation contract (no
// second observation path):
//
//   - NO_COLLISION (absence POSITIVELY proven under a complete mangle
//     inventory — inherited from ObserveMSSRule; an incomplete inventory
//     can never classify NO_COLLISION) → CREATE_MSS_RULE candidate —
//     ONLY when the chain/hook structural prerequisites are
//     SuitabilityProven; otherwise the decision is BLOCKED_PREREQUISITE
//     (proven violation) or UNKNOWN (undeterminable). CREATE is
//     mechanically unreachable without proven structural prerequisites;
//   - OCCUPIED_MATCHING_SPEC → NO_ACTION: already satisfied, and the
//     matching existing rule gains NO ownership, NO evidence, NO
//     adoption and NO future DELETE authority — "satisfied" and "owned"
//     are separate dimensions (§9). NO_ACTION is semantic convergence
//     at the coordinate; it NEVER claims packet-path effectiveness —
//     when the chain/hook prerequisites are not proven, the decision
//     carries an explicit reason saying so (additive; the outcome
//     vocabulary is unchanged, ZAI-62 §15);
//   - OCCUPIED_CONFLICTING_SPEC → BLOCKED_COLLISION: same identity +
//     different spec never generates a replacement (§10);
//   - AMBIGUOUS (incomplete inventory, unsupported occupants, conflicts)
//     → UNKNOWN: no CREATE (UNKNOWN != ABSENT, §8).
//
// A desired rule whose own conversion fails is a programming error and
// fails closed; different identity + same spec cannot reach this planner
// (classification is coordinate-bound and rejects cross-coordinate
// observations).
func PlanMSSAction(rule DesiredMSSRule, obs MSSObservation, chain ChainObservation) (MSSPlanDecision, error) {
	action, err := BuildMSSAction(rule)
	if err != nil {
		return MSSPlanDecision{}, err
	}
	collision, err := ClassifyLiveState(rule, obs)
	if err != nil {
		return MSSPlanDecision{}, err
	}
	var dec MSSPlanDecision
	switch collision {
	case CollisionNone:
		a := action
		dec = MSSPlanDecision{
			Outcome: PlannerCreateMSSRule,
			Action:  &a,
			Reasons: []string{"absence is positively proven under the complete mangle inventory"},
		}
	case CollisionOccupiedMatchingSpec:
		dec = MSSPlanDecision{
			Outcome: PlannerNoAction,
			Reasons: []string{"an existing rule already matches the desired semantic spec; provenance remains unproven — no ownership, no adoption, no evidence, no DELETE authority"},
		}
	case CollisionOccupiedConflictingSpec:
		dec = MSSPlanDecision{
			Outcome: PlannerBlockedCollision,
			Reasons: []string{"the coordinate is occupied by a semantically different rule; replacement is not an authorized operation"},
		}
	case CollisionAmbiguous:
		dec = MSSPlanDecision{
			Outcome: PlannerUnknown,
			Reasons: append([]string(nil), obs.Reasons...),
		}
	default:
		return MSSPlanDecision{}, fmt.Errorf("collision classification %q is not in the closed vocabulary", collision)
	}

	// Structural chain/hook gate (ZAI-63): the CREATE candidate survives
	// only a PROVEN structural assessment; a proven violation blocks
	// explicitly; undeterminability stays UNKNOWN.
	if dec.Outcome == PlannerCreateMSSRule {
		switch chain.Status {
		case SuitabilityProven:
			dec.Reasons = append(dec.Reasons, chain.Reasons...)
		case SuitabilityUnknown:
			dec = MSSPlanDecision{
				Outcome: PlannerUnknown,
				Reasons: append(append([]string{"structural chain/hook prerequisites are undeterminable"}, chain.Reasons...), "no CREATE (UNKNOWN never becomes a mutation)"),
			}
		case SuitabilityAbsent, SuitabilityUnsuitable, SuitabilityAmbiguous:
			dec = MSSPlanDecision{
				Outcome: PlannerBlockedPrerequisite,
				Reasons: append([]string{"structural chain/hook prerequisites are not proven"}, chain.Reasons...),
			}
		default:
			return MSSPlanDecision{}, fmt.Errorf("chain suitability %q is not in the closed vocabulary", chain.Status)
		}
	}
	// NO_ACTION never claims packet-path effectiveness: surface the
	// structural gap as an additive reason without changing the
	// established outcome semantics (ZAI-62 §15 / ZAI-63 §12).
	if dec.Outcome == PlannerNoAction && chain.Status != SuitabilityProven {
		dec.Reasons = append(dec.Reasons, "semantic convergence at the coordinate is NOT packet-path effectiveness: the structural chain/hook prerequisites are not proven (status "+string(chain.Status)+")")
		dec.Reasons = append(dec.Reasons, chain.Reasons...)
	}
	return dec, nil
}
