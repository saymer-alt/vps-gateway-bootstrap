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
	return a.Spec.Service, nil
}

func (e *ServiceExecutor) Backup(actionID, resource string) error { _, err := e.spec(actionID, resource); return err }

func (e *ServiceExecutor) Apply(actionID, resource, kind string) error {
	s, err := e.spec(actionID, resource); if err != nil { return err }
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
