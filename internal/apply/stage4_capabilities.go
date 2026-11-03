package apply

// Stage 4/B plan mapper (C3, ZAI-132): derives the canonical capability set
// a plan requires from the plan's own TYPED actions (docs/security-model.md
// §9.B, §13 stage 4). This is the trusted compiled code the capability
// package contract names as the only legitimate producer of a required
// set: nothing here reads capability strings from config, persisted state,
// plan payload or caller input, and every unsupported mutating action kind
// fails closed instead of implying an authority.
//
// The compiled Stage-1 resource policy is the derivation bound: only
// actions the executor policy already permits can produce a capability
// requirement, so the derived set can never be broader than what the
// executors would actually enforce. A unit outside the policy, an
// operation outside a unit's per-unit set, or a mutating action kind with
// no compiled derivation refuses the whole derivation — such a plan cannot
// be authorized, and it also could never execute (the Stage-1 executors
// would refuse it).
//
// This function derives REQUIREMENTS only. It grants nothing: the grant
// side (an operator-signed approval v2 artifact) and the exact-set
// comparison are separate layers (capability.VerifyCapabilityGrant; the
// wiring into the confirmation boundary is Stage 2 and deliberately not
// done here).

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// RequiredCapabilities derives the canonical capability set the plan
// requires. Deterministic and order-independent: the aggregate folds
// per-action requirements into one canonical set, collapsing exact
// duplicates and refusing conflicting parametrizations of the same
// capability name.
func RequiredCapabilities(p state.Plan) (capability.CapabilitySet, error) {
	var ids []capability.CapabilityID
	for _, a := range p.Actions {
		switch a.Kind {
		case state.ActionService:
			if a.Spec == nil || a.Spec.Service == nil {
				return capability.CapabilitySet{}, fmt.Errorf("capability derivation: action %q is a SERVICE action without a typed service spec", a.ID)
			}
			s := a.Spec.Service
			// The compiled Stage-1 policy is the derivation bound.
			if _, ok := serviceUnitPolicy[s.Name]; !ok {
				return capability.CapabilitySet{}, fmt.Errorf("capability derivation: unit %q is not in the compiled Stage 1 service policy", s.Name)
			}
			if !allowedServiceOperation(serviceUnitPolicy, s.Name, s.Operation) {
				return capability.CapabilitySet{}, fmt.Errorf("capability derivation: operation %q is not permitted on unit %q by the compiled Stage 1 service policy", s.Operation, s.Name)
			}
			// A rollback is a real mutation too — the executor's Rollback
			// re-checks it against the same compiled policy — so the
			// derivation must not grant an authority for a plan whose
			// restore path the executors would refuse. An empty
			// RollbackOperation means "no rollback mutation" and stays
			// valid.
			if s.RollbackOperation != "" && !allowedServiceOperation(serviceUnitPolicy, s.Name, s.RollbackOperation) {
				return capability.CapabilitySet{}, fmt.Errorf("capability derivation: rollback operation %q is not permitted on unit %q by the compiled Stage 1 service policy", s.RollbackOperation, s.Name)
			}
			id, err := capability.DeriveServiceRestart(s.Name)
			if err != nil {
				return capability.CapabilitySet{}, fmt.Errorf("capability derivation: action %q: %w", a.ID, err)
			}
			ids = append(ids, id)
		case state.ActionValidate:
			// Read-only observation of an external resource: it mutates
			// nothing and carries no capability requirement.
		default:
			return capability.CapabilitySet{}, fmt.Errorf("capability derivation: action %q has kind %q with no compiled capability derivation (fail-closed; security-model §9.B)", a.ID, a.Kind)
		}
	}
	return capability.Aggregate(ids)
}
