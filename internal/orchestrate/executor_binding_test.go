package orchestrate

import (
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Regression for the second production experiment (Saymer3, fail2ban):
// the orchestrator filled Registry.Actions but never bound the plan into the
// kind executors themselves, so the REAL ServiceExecutor rejected every
// action with "no action registry configured". The full lifecycle with the
// real executor must reach COMPLETED through the standard wiring (executors
// constructed without a pre-filled action map).

func TestExecuteBindsPlanActionsIntoRealServiceExecutor(t *testing.T) {
	var calls [][]string
	svc := &apply.ServiceExecutor{Runner: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	// Discovery: #1 Prepare, #2 staleness, #3 re-discovery (fail2ban active).
	o, _ := newOrchestrator(t, []discovery.Result{
		makeDiscovery(false), makeDiscovery(false), makeDiscovery(true),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc}}, nil)
	p := o.Prepare(fail2banConfig(), rootOn())
	if !p.Ready { t.Fatalf("plan not ready: %v", p.Blockers) }

	conf := Confirmation{PlanFingerprint: Fingerprint(p.Plan), ApprovedBy: "op", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil { t.Fatal(err) }
	if out.Stage != StageCompleted {
		t.Fatalf("stage=%s blockers=%v actions=%#v", out.Stage, out.Blockers, out.Transaction.Actions)
	}

	// Executor preflight runs twice (Prepare + Execute under the lock), then
	// the transaction: restart and two is-active validations (in-transaction
	// + final after re-discovery).
	want := []string{
		"fail2ban-client -t",
		"fail2ban-client -t",
		"systemctl restart fail2ban.service",
		"systemctl is-active --quiet fail2ban.service",
		"systemctl is-active --quiet fail2ban.service",
	}
	if len(calls) != len(want) { t.Fatalf("calls=%v", calls) }
	for i := range want {
		if joinArgs(calls[i]) != want[i] { t.Fatalf("call[%d]=%v want %q", i, calls[i], want[i]) }
	}
}

func joinArgs(parts []string) string {
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}
