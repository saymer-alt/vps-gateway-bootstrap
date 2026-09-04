package apply

import (
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type registryTestExecutor struct { calls []string }

func (e *registryTestExecutor) Backup(id, resource string) error { e.calls = append(e.calls, "backup:"+id); return nil }
func (e *registryTestExecutor) Apply(id, resource, kind string) error { e.calls = append(e.calls, "apply:"+kind); return nil }
func (e *registryTestExecutor) Validate(id, resource string) error { e.calls = append(e.calls, "validate:"+id); return nil }
func (e *registryTestExecutor) Rollback(id, resource string) error { e.calls = append(e.calls, "rollback:"+id); return nil }

func TestRegistryDispatchesByActionKind(t *testing.T) {
	ex := &registryTestExecutor{}
	a := state.Action{ID: "a1", Resource: "svc.test", Kind: state.ActionService, Ownership: state.Owned}
	r := Registry{ByKind: map[state.ActionKind]ActionExecutor{state.ActionService: ex}, Actions: map[string]state.Action{"a1": a}}
	if err := r.Backup("a1", "svc.test"); err != nil { t.Fatal(err) }
	if err := r.Apply("a1", "svc.test", string(state.ActionService)); err != nil { t.Fatal(err) }
	if err := r.Validate("a1", "svc.test"); err != nil { t.Fatal(err) }
	if err := r.Rollback("a1", "svc.test"); err != nil { t.Fatal(err) }
	if len(ex.calls) != 4 { t.Fatalf("calls=%v", ex.calls) }
}

func TestRegistryRejectsKindMismatch(t *testing.T) {
	ex := &registryTestExecutor{}
	a := state.Action{ID: "a1", Resource: "svc.test", Kind: state.ActionService, Ownership: state.Owned}
	r := Registry{ByKind: map[state.ActionKind]ActionExecutor{state.ActionService: ex}, Actions: map[string]state.Action{"a1": a}}
	if err := r.Apply("a1", "svc.test", string(state.ActionFirewall)); err == nil { t.Fatal("expected kind mismatch") }
}

func TestRegistryRejectsMissingExecutor(t *testing.T) {
	a := state.Action{ID: "a1", Resource: "svc.test", Kind: state.ActionService, Ownership: state.Owned}
	r := Registry{Actions: map[string]state.Action{"a1": a}}
	if err := r.Validate("a1", "svc.test"); err == nil { t.Fatal("expected missing executor") }
}
