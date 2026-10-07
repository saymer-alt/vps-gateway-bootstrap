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
