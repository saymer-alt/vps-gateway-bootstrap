package apply

import (
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Registry dispatches a plan action to the executor responsible for its kind.
// An action without a registered executor is rejected instead of being guessed.
type Registry struct {
	ByKind map[state.ActionKind]ActionExecutor
}

func (r Registry) executor(kind state.ActionKind) (ActionExecutor, error) {
	if r.ByKind == nil {
		return nil, fmt.Errorf("no action executors registered")
	}
	ex, ok := r.ByKind[kind]
	if !ok || ex == nil {
		return nil, fmt.Errorf("no executor registered for action kind %q", kind)
	}
	return ex, nil
}

func (r Registry) Backup(actionID, resource string) error {
	return r.call(state.ActionKindForResource(resource), func(ex ActionExecutor) error { return ex.Backup(actionID, resource) })
}

func (r Registry) Apply(actionID, resource, kind string) error {
	k := state.ActionKind(kind)
	ex, err := r.executor(k)
	if err != nil { return err }
	return ex.Apply(actionID, resource, kind)
}

func (r Registry) Validate(actionID, resource string) error {
	return r.call(state.ActionKindForResource(resource), func(ex ActionExecutor) error { return ex.Validate(actionID, resource) })
}

func (r Registry) Rollback(actionID, resource string) error {
	return r.call(state.ActionKindForResource(resource), func(ex ActionExecutor) error { return ex.Rollback(actionID, resource) })
}

func (r Registry) call(kind state.ActionKind, fn func(ActionExecutor) error) error {
	ex, err := r.executor(kind)
	if err != nil { return err }
	return fn(ex)
}
