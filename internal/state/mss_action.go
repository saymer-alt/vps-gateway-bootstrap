// Typed MSS action representation (ZAI-56, INERT): the state-plane bridge
// for the frozen ZAI-50/ZAI-51 MSS contract.
//
//	ActionMSSRule is a RESERVED, INERT action kind: Defined:false.
//
// What this means, mechanically (each pinned by tests):
//
//   - the type system can now DESCRIBE the exact future MSS mutation
//     (ActionSpec.MSS carries the typed ZAI-51 intent verbatim);
//   - a Plan containing an ActionMSSRule action is still INVALID —
//     ValidateActionTypedSpec refuses reserved kinds, so no production
//     Plan can carry one (representation != acceptance);
//   - no executor is registered for the kind, so even a hypothetical
//     acceptance would block in Prepare's executor-coverage check
//     (defense in depth: Defined:false + executor absent);
//   - no rollback is represented: an MSS CREATE has no authorized
//     semantic rollback (ZAI-55), and none is invented here.
//
// ONE authoritative MSS implementation (§10): the state plane does NOT
// duplicate MSS semantics. MSSActionSpec is a type ALIAS of
// mssspec.MSSActionSpec, and ValidateMSSActionSpec delegates the full
// integrity check to mssspec.BuildMSSAction — identity class/namespace,
// identity-vs-spec chain agreement, envelope validity, and the
// recomputed semantic fingerprint (a supplied SpecHash is never
// trusted). Import direction state → mssspec is cycle-free (mssspec
// imports capability/discovery/identity/ownership; none import state)
// and consistent with the existing state → discovery layering.
//
// Hashing: ActionSpecHash covers the whole typed ActionSpec, so an MSS
// action is hashed in the existing action-spec domain automatically —
// the MSS semantic SpecFingerprint travels INSIDE as a field and the two
// domains stay distinct (ZAI-51). The field is omitempty, so every
// pre-existing action's canonical bytes (and therefore its
// ActionSpecHash and journal assumptions) are unchanged.
package state

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
)

// ActionMSSRule is the reserved action kind for the future project MSS
// clamp CREATE mutation. Semantically distinct from ActionFirewall: the
// kind is both a typed representation class and the executor dispatch
// coordinate, and exact MSS must never share an authority coordinate with
// generic firewall mutation. Defined:false — representation exists,
// acceptance does not.
const ActionMSSRule ActionKind = "MSS_RULE"

// MSSActionSpec is the typed MSS mutation intent (ZAI-51): an alias, not
// a mirror — mssspec remains the ONE authoritative MSS semantic
// implementation (validation, fingerprint, equality).
type MSSActionSpec = mssspec.MSSActionSpec

// ValidateMSSActionSpec revalidates one ActionMSSRule action's typed spec
// through the authoritative mssspec contract: ResourceIdentity class,
// namespace, identity-vs-spec chain agreement, envelope validity, and the
// recomputed semantic fingerprint (a supplied SpecHash is never trusted —
// stale or fabricated hashes DENY). PURE; fail-closed.
func ValidateMSSActionSpec(a Action) error {
	if a.Spec == nil || a.Spec.MSS == nil {
		return fmt.Errorf("MSS action requires a typed MSS spec")
	}
	m := a.Spec.MSS
	_, err := mssspec.BuildMSSAction(mssspec.DesiredMSSRule{
		Identity: m.Identity,
		Spec:     m.Spec,
		SpecHash: m.SpecHash,
	})
	if err != nil {
		return fmt.Errorf("MSS action consistency: %w", err)
	}
	return nil
}

// StateActionFromMSSDecision is the narrow PURE bridge from an MSS planner
// decision to the inert typed state action (ZAI-57). Binding rules:
//
//   - ONLY PlannerCreateMSSRule yields an action (hasAction = true);
//     NO_ACTION, BLOCKED_COLLISION and UNKNOWN yield none — a matching
//     existing rule is never asserted or adopted, a conflicting rule is
//     never replaced, and uncertainty never becomes a mutation (the
//     global UNKNOWN != ABSENT invariant);
//   - the decision's action is REVALIDATED through the authoritative
//     mssspec contract before anything is produced — planner output is
//     typed input, never magical authority (a fabricated decision with a
//     bad identity/namespace/spec/hash is rejected);
//   - the emitted action carries ONLY the typed representation (kind,
//     resource coordinate from the ZAI-50 journal design, MSS spec): no
//     raw commands, argv, shell, HostIdentity, approval, journal or
//     ownership data — the Plan describes intent, not execution;
//   - no rollback is represented: an MSS CREATE has no authorized
//     semantic rollback (ZAI-55); a failed/uncertain CREATE remains
//     RECOVERY_REQUIRED, operator-reviewed.
//
// The result always passes ValidateMSSActionSpec. PURE; deterministic;
// fail-closed.
func StateActionFromMSSDecision(dec mssspec.MSSPlanDecision) (a Action, hasAction bool, err error) {
	if dec.Outcome != mssspec.PlannerCreateMSSRule {
		// NO_ACTION / BLOCKED_COLLISION / UNKNOWN: zero state mutation
		// actions — structurally nothing to convert (anti-adoption).
		return Action{}, false, nil
	}
	if dec.Action == nil {
		return Action{}, false, fmt.Errorf("CREATE decision carries no typed MSS action")
	}
	// Authoritative revalidation of the decision's action (identity,
	// namespace, envelope, recomputed hash).
	validated, err := mssspec.BuildMSSAction(mssspec.DesiredMSSRule{
		Identity: dec.Action.Identity,
		Spec:     dec.Action.Spec,
		SpecHash: dec.Action.SpecHash,
	})
	if err != nil {
		return Action{}, false, fmt.Errorf("MSS decision action failed revalidation: %w", err)
	}
	resource, err := mssspec.JournalResource(validated.Identity)
	if err != nil {
		return Action{}, false, fmt.Errorf("MSS decision resource coordinate: %w", err)
	}
	out := Action{
		ID:       "mss-" + validated.Identity.Chain + "-" + validated.Identity.Tag,
		Resource: resource,
		Kind:     ActionMSSRule,
		Spec: &ActionSpec{
			MSS: &MSSActionSpec{Identity: validated.Identity, Spec: validated.Spec, SpecHash: validated.SpecHash},
		},
	}
	if err := ValidateMSSActionSpec(out); err != nil {
		return Action{}, false, err
	}
	return out, true, nil
}
