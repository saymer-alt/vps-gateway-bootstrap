package apply

import (
	"errors"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func serviceAction(op, expected, rollback string) state.Action {
	return state.Action{ID: "svc1", Resource: "test.service", Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: "demo.service", Operation: op, ExpectedState: expected, RollbackOperation: rollback}}}
}

func TestServiceExecutorUsesTypedOperations(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("restart", "active", "stop")}, Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...)); return nil
	}}
	if err := e.Backup("svc1", "test.service"); err != nil { t.Fatal(err) }
	if err := e.Apply("svc1", "test.service", string(state.ActionService)); err != nil { t.Fatal(err) }
	if err := e.Validate("svc1", "test.service"); err != nil { t.Fatal(err) }
	if err := e.Rollback("svc1", "test.service"); err != nil { t.Fatal(err) }
	if len(calls) != 3 || calls[0][1] != "restart" || calls[1][1] != "is-active" || calls[2][1] != "stop" { t.Fatalf("calls=%v", calls) }
}

func TestServiceExecutorRejectsExternal(t *testing.T) {
	a := serviceAction("restart", "active", ""); a.Ownership = state.External
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": a}, Runner: func(string, ...string) error { return nil }}
	if err := e.Apply("svc1", "test.service", string(state.ActionService)); err == nil { t.Fatal("expected ownership rejection") }
}

func TestServiceExecutorRejectsUnknownOperation(t *testing.T) {
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("shell", "active", "")}, Runner: func(string, ...string) error { return nil }}
	if err := e.Apply("svc1", "test.service", string(state.ActionService)); err == nil { t.Fatal("expected operation rejection") }
}

func TestServiceExecutorCompositeOperationsOrder(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("enable-start", "active", "disable-stop")}, Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...)); return nil
	}}
	if err := e.Apply("svc1", "test.service", string(state.ActionService)); err != nil { t.Fatal(err) }
	if len(calls) != 2 || calls[0][1] != "enable" || calls[1][1] != "start" { t.Fatalf("apply calls=%v", calls) }
	calls = nil
	if err := e.Rollback("svc1", "test.service"); err != nil { t.Fatal(err) }
	if len(calls) != 2 || calls[0][1] != "stop" || calls[1][1] != "disable" { t.Fatalf("rollback calls=%v", calls) }
}

func TestServiceExecutorValidateExpectedStates(t *testing.T) {
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("stop", "inactive", "")}, Runner: func(name string, args ...string) error {
		if args[0] == "is-active" { return errors.New("inactive unit") }
		return nil
	}}
	if err := e.Validate("svc1", "test.service"); err != nil { t.Fatal(err) }
	e.Runner = func(string, ...string) error { return nil }
	if err := e.Validate("svc1", "test.service"); err == nil { t.Fatal("expected active service to fail inactive validation") }
	bad := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("stop", "flying", "")}, Runner: func(string, ...string) error { return nil }}
	if err := bad.Validate("svc1", "test.service"); err == nil { t.Fatal("expected unsupported expected-state rejection") }
}

func TestServiceExecutorRollbackWithoutOperationIsNoop(t *testing.T) {
	var calls [][]string
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("restart", "active", "")}, Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...)); return nil
	}}
	if err := e.Rollback("svc1", "test.service"); err != nil { t.Fatal(err) }
	if len(calls) != 0 { t.Fatalf("calls=%v", calls) }
}

func TestServiceExecutorRollbackRejectsUnknownOperation(t *testing.T) {
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("restart", "active", "reboot")}, Runner: func(string, ...string) error { return nil }}
	if err := e.Rollback("svc1", "test.service"); err == nil { t.Fatal("expected rollback operation rejection") }
}

func TestServiceExecutorApplyPropagatesFailure(t *testing.T) {
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("restart", "active", "")}, Runner: func(name string, args ...string) error {
		if args[0] == "restart" { return errors.New("job failed") }
		return nil
	}}
	if err := e.Apply("svc1", "test.service", string(state.ActionService)); err == nil { t.Fatal("expected apply failure") }
}

func TestServiceExecutorRejectsUnknownActionOrResource(t *testing.T) {
	e := &ServiceExecutor{Actions: map[string]state.Action{"svc1": serviceAction("restart", "active", "")}, Runner: func(string, ...string) error { return nil }}
	if err := e.Backup("missing", "test.service"); err == nil { t.Fatal("expected unknown action rejection") }
	if err := e.Apply("svc1", "other.service", string(state.ActionService)); err == nil { t.Fatal("expected resource mismatch rejection") }
}
