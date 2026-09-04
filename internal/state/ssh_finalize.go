package state

// ActionSSHFinalize is the explicit second phase of a staged SSH migration.
// It is never emitted automatically by BuildPlan because cleanup requires a
// real controller-side management probe.
const ActionSSHFinalize ActionKind = "SSH_FINALIZE"

// NewSSHFinalizeAction constructs the explicit cleanup action for a staged
// SSH migration. The supplied SSH spec must identify both ports and the
// management endpoint used for the remote connectivity proof.
func NewSSHFinalizeAction(id, resource string, ownership Ownership, spec SSHActionSpec) Action {
	return Action{
		ID: id, Resource: resource, Kind: ActionSSHFinalize, Ownership: ownership,
		Why: "remove the old SSH listener only after remote management connectivity is proven",
		Risk: RiskCritical,
		Validation: "remote probe succeeds; new listener remains; old listener is gone",
		Rollback: "restore the staged dual-listener configuration and re-validate recovery",
		Spec: &ActionSpec{SSH: &spec},
	}
}
