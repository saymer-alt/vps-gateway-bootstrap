package orchestrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// The first real change the project intends to apply: repair the failed
// fail2ban unit on Saymer3. This test proves the PLANNING ONLY pipeline —
// desired → diff → plan → preflight — produces exactly one expected action
// and nothing that touches SSH, network, firewall or any other unit.
// Execution is deliberately not part of this scenario.
func TestFirstApplyModelFail2BanRepair(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "first-apply-saymer3.json"))
	if err != nil { t.Fatal(err) }
	var scenario struct {
		Discovery discovery.Result `json:"discovery"`
		ConfigRaw json.RawMessage  `json:"config"`
	}
	if err := json.Unmarshal(raw, &scenario); err != nil { t.Fatal(err) }
	cfg, err := pipeline.ParseConfig(scenario.ConfigRaw)
	if err != nil { t.Fatal(err) }

	svc := &recordingExecutor{}
	o, _ := newOrchestrator(t, []discovery.Result{scenario.Discovery}, apply.Registry{
		ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: svc},
	}, nil)
	p := o.Prepare(cfg, rootOn())

	if !p.Ready {
		t.Fatalf("first-apply plan must be ready, blockers=%v", p.Blockers)
	}
	if len(p.Plan.Actions) != 1 {
		t.Fatalf("expected exactly one action, got %#v", p.Plan.Actions)
	}
	a := p.Plan.Actions[0]
	if a.Kind != state.ActionService {
		t.Fatalf("kind=%s, want SERVICE", a.Kind)
	}
	if a.Resource != "service.fail2ban.service" {
		t.Fatalf("resource=%q", a.Resource)
	}
	if a.Spec == nil || a.Spec.Service == nil {
		t.Fatalf("missing service spec: %#v", a.Spec)
	}
	if a.Spec.Service.Name != "fail2ban.service" || a.Spec.Service.Operation != "restart" || a.Spec.Service.ExpectedState != "active" {
		t.Fatalf("unexpected spec: %#v", a.Spec.Service)
	}
	if a.Ownership != state.Owned {
		t.Fatalf("ownership=%q, want OWNED", a.Ownership)
	}

	// Nothing outside the repair target may be touched.
	for _, act := range p.Plan.Actions {
		switch act.Kind {
		case state.ActionSSH, state.ActionSSHFinalize, state.ActionFirewall, state.ActionRouting, state.ActionReboot, state.ActionInstaller:
			t.Fatalf("plan must not contain %s actions", act.Kind)
		}
		if act.Resource != "service.fail2ban.service" {
			t.Fatalf("unexpected resource %q", act.Resource)
		}
	}

	// The planning pipeline never mutates: the executor must have recorded
	// zero calls and the confirmation must be required for execution.
	if len(svc.calls) != 0 { t.Fatalf("planning performed mutations: %v", svc.calls) }
	if err := o.Confirm(p, Confirmation{}); err == nil {
		t.Fatal("empty confirmation must be rejected")
	}
}
