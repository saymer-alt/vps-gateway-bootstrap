package apply

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type Registry struct {
	ByKind  map[state.ActionKind]ActionExecutor
	Actions map[string]state.Action
}

func (r Registry) action(id, resource string) (state.Action, error) {
	a, ok := r.Actions[id]
	if !ok || a.Resource != resource { return state.Action{}, fmt.Errorf("unknown action %q", id) }
	return a, nil
}

func (r Registry) executor(kind state.ActionKind) (ActionExecutor, error) {
	if r.ByKind == nil { return nil, fmt.Errorf("no action executors registered") }
	ex, ok := r.ByKind[kind]
	if !ok || ex == nil { return nil, fmt.Errorf("no executor registered for action kind %q", kind) }
	return ex, nil
}

func (r Registry) forAction(actionID, resource string) (ActionExecutor, state.Action, error) {
	a, err := r.action(actionID, resource)
	if err != nil { return nil, state.Action{}, err }
	ex, err := r.executor(a.Kind)
	if err != nil { return nil, state.Action{}, err }
	return ex, a, nil
}

func (r Registry) Backup(actionID, resource string) error {
	ex, _, err := r.forAction(actionID, resource)
	if err != nil { return err }
	return ex.Backup(actionID, resource)
}

func (r Registry) Apply(actionID, resource, kind string) error {
	ex, a, err := r.forAction(actionID, resource)
	if err != nil { return err }
	if a.Kind != state.ActionKind(kind) { return fmt.Errorf("action %q kind mismatch: plan=%q requested=%q", actionID, a.Kind, kind) }
	return ex.Apply(actionID, resource, kind)
}

func (r Registry) Validate(actionID, resource string) error {
	ex, _, err := r.forAction(actionID, resource)
	if err != nil { return err }
	return ex.Validate(actionID, resource)
}

func (r Registry) Rollback(actionID, resource string) error {
	ex, _, err := r.forAction(actionID, resource)
	if err != nil { return err }
	return ex.Rollback(actionID, resource)
}
