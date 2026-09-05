package apply

import (
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// PreflightChecker is an optional executor extension: a read-only,
// action-specific pre-mutation check that consults the live machine and
// reports problems before any mutation is attempted.
//
// The canonical example is a configuration test (fail2ban-client -t): a
// restart can never repair a broken configuration, so obvious configuration
// invalidity must block the plan before the first mutation. The orchestrator
// runs these checks in Prepare (operator visibility) and again in Execute
// (freshness, under the lock). Implementations must be strictly read-only.
type PreflightChecker interface {
	PreflightCheck(a state.Action) error
}

// serviceConfigTests maps units to their read-only configuration test
// command. This is explicit per-service knowledge held in code, not a
// generic command mechanism: only units with an actual config-test tool are
// listed, and the command never comes from plan data.
var serviceConfigTests = map[string][]string{
	"fail2ban.service": {"fail2ban-client", "-t"},
}

// PreflightCheck implements PreflightChecker for ServiceExecutor. Units
// without a known configuration test pass vacuously; a failed test blocks
// the action before mutation.
func (e *ServiceExecutor) PreflightCheck(a state.Action) error {
	if a.Spec == nil || a.Spec.Service == nil {
		return nil
	}
	cmd, ok := serviceConfigTests[a.Spec.Service.Name]
	if !ok {
		return nil
	}
	return e.exec(cmd[0], cmd[1:]...)
}
