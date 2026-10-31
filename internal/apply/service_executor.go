package apply

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type ServiceExecutor struct {
	Actions map[string]state.Action
	Runner  func(name string, args ...string) error

	// unitPolicy is a TEST-ONLY seam (Stage 1, docs/security-model.md §13):
	// package-internal tests may substitute an isolated policy to exercise
	// the operation machinery with synthetic units. The field is unexported,
	// so no other package — and therefore no production wiring site, config
	// field, state entry, plan field, environment variable or CLI flag — can
	// set it. Production executors leave it nil and run under the compiled
	// serviceUnitPolicy; that difference is pinned by
	// TestStage1ServicePolicyDefaultIsCompiled.
	unitPolicy map[string][]string
}

// servicePolicy returns the executor's active resource policy: the explicit
// test seam when set, otherwise the compiled production policy.
func (e *ServiceExecutor) servicePolicy() map[string][]string {
	if e.unitPolicy != nil { return e.unitPolicy }
	return serviceUnitPolicy
}

func (e *ServiceExecutor) run(args ...string) error {
	return e.exec("systemctl", args...)
}

// exec runs a machine command through the same injectable path as run, but
// with an explicit binary name. It exists for read-only service-specific
// preflight checks (e.g. fail2ban-client -t), never for plan-supplied
// commands.
func (e *ServiceExecutor) exec(name string, args ...string) error {
	if e.Runner != nil { return e.Runner(name, args...) }
	if _, err := exec.LookPath(name); err != nil { return err }
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil { return fmt.Errorf("%s %v: %w: %s", name, args, err, strings.TrimSpace(string(out))) }
	return nil
}

func (e *ServiceExecutor) spec(id, resource string) (*state.ServiceActionSpec, error) {
	if e.Actions == nil { return nil, errors.New("no action registry configured") }
	a, ok := e.Actions[id]
	if !ok || a.Resource != resource { return nil, fmt.Errorf("unknown action %q", id) }
	if a.Ownership != state.Owned { return nil, errors.New("service mutation requires OWNED resource") }
	if a.Spec == nil || a.Spec.Service == nil || a.Spec.Service.Name == "" { return nil, errors.New("missing service action specification") }
	// The unit name is about to become an argv element of systemctl on every
	// operation path; it must be a plain unit name before that can happen.
	if err := validateUnitName(a.Spec.Service.Name); err != nil { return nil, err }
	// Stage 1 (docs/security-model.md §13): a syntactically valid unit name
	// is not a permission. The unit must be in the compiled service policy —
	// this gates Backup (no-op), Validate (read-only) and every mutating
	// path alike, including direct Registry/Engine calls.
	if _, ok := e.servicePolicy()[a.Spec.Service.Name]; !ok {
		return nil, fmt.Errorf("unit %q is not in the compiled Stage 1 service policy: mutation refused", a.Spec.Service.Name)
	}
	return a.Spec.Service, nil
}

func (e *ServiceExecutor) Backup(actionID, resource string) error { _, err := e.spec(actionID, resource); return err }

func (e *ServiceExecutor) Apply(actionID, resource, kind string) error {
	s, err := e.spec(actionID, resource); if err != nil { return err }
	// Stage 1: the OPERATION is part of the per-unit policy — membership
	// alone never grants every verb over a listed unit.
	if !allowedServiceOperation(e.servicePolicy(), s.Name, s.Operation) {
		return fmt.Errorf("operation %q is not permitted on unit %q by the compiled Stage 1 service policy", s.Operation, s.Name)
	}
	switch s.Operation {
	case "start", "stop", "restart", "reload", "enable", "disable": return e.run(s.Operation, s.Name)
	case "enable-start":
		if err := e.run("enable", s.Name); err != nil { return err }; return e.run("start", s.Name)
	case "disable-stop":
		if err := e.run("stop", s.Name); err != nil { return err }; return e.run("disable", s.Name)
	default: return fmt.Errorf("unsupported service operation %q", s.Operation)
	}
}

func (e *ServiceExecutor) Validate(actionID, resource string) error {
	s, err := e.spec(actionID, resource); if err != nil { return err }
	expected := s.ExpectedState; if expected == "" { expected = "active" }
	switch expected {
	case "active": return e.run("is-active", "--quiet", s.Name)
	case "inactive":
		if err := e.run("is-active", "--quiet", s.Name); err == nil { return errors.New("service is active") }
		return nil
	default: return fmt.Errorf("unsupported expected service state %q", expected)
	}
}

func (e *ServiceExecutor) Rollback(actionID, resource string) error {
	s, err := e.spec(actionID, resource); if err != nil { return err }
	if s.RollbackOperation == "" { return nil }
	// Stage 1: a rollback is a real mutation — the restore operation must
	// itself be permitted for this unit by the compiled policy.
	if !allowedServiceOperation(e.servicePolicy(), s.Name, s.RollbackOperation) {
		return fmt.Errorf("rollback operation %q is not permitted on unit %q by the compiled Stage 1 service policy", s.RollbackOperation, s.Name)
	}
	switch s.RollbackOperation {
	case "start", "stop", "restart", "reload", "enable", "disable": return e.run(s.RollbackOperation, s.Name)
	case "enable-start":
		if err := e.run("enable", s.Name); err != nil { return err }; return e.run("start", s.Name)
	case "disable-stop":
		if err := e.run("stop", s.Name); err != nil { return err }; return e.run("disable", s.Name)
	default: return fmt.Errorf("unsupported rollback operation %q", s.RollbackOperation)
	}
}

// BindActions implements ActionBinder: the orchestrator hands the plan's
// actions to the executor before every transaction.
func (e *ServiceExecutor) BindActions(actions map[string]state.Action) {
	e.Actions = actions
}
