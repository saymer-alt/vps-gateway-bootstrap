package apply

import "github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"

// validateUnitName is the strict boundary every plan-derived systemd unit
// name must pass before it becomes an argv element of a systemctl (or
// similar) invocation. The rules live in the shared identity package
// (identity.ValidUnitName, relocated verbatim from the original TASK-04
// implementation) so planning-side resource identities and executor-side
// argv validation can never drift apart. It is input validation, not
// authorization: ownership remains the authority boundary.
func validateUnitName(name string) error {
	return identity.ValidUnitName(name)
}
