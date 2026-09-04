package apply

import (
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
