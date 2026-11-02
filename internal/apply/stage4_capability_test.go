package apply

// Stage 4/B capability-derivation tests (ZAI-132): the C3 plan mapper,
// its compiled-policy bound, and the cross-consistency pin between the
// capability package's unit validation and the executor boundary's shared
// identity validation. Synthetic plans only.

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func stage4ServiceAction(unit, op string) state.Action {
	return state.Action{ID: "svc1", Resource: "service." + unit, Kind: state.ActionService, Ownership: state.Owned,
		Spec: &state.ActionSpec{Service: &state.ServiceActionSpec{Name: unit, Operation: op, ExpectedState: "active"}}}
}

// The pinned production experiment derives exactly one capability: the
// per-unit service-restart authority. Deterministic.
func TestStage4RequiredCapabilitiesPinnedExperiment(t *testing.T) {
	for i := 0; i < 3; i++ {
		set, err := RequiredCapabilities(state.Plan{Actions: []state.Action{stage4ServiceAction("fail2ban.service", "restart")}})
		if err != nil {
			t.Fatal(err)
		}
		ids := set.IDs()
		if len(ids) != 1 || ids[0] != capability.CapabilityID("muvg.service.restart.v1;unit=fail2ban.service") {
			t.Fatalf("pinned experiment must derive exactly the fail2ban restart capability, got %v", ids)
		}
	}
}

// The derivation is bound to the compiled Stage-1 policy: a unit outside it
// can never produce a capability requirement.
func TestStage4RequiredCapabilitiesRefuseUnitsOutsidePolicy(t *testing.T) {
	for _, unit := range []string{"nginx.service", "ssh.service", "docker.service"} {
		_, err := RequiredCapabilities(state.Plan{Actions: []state.Action{stage4ServiceAction(unit, "restart")}})
		if err == nil || !strings.Contains(err.Error(), "compiled Stage 1 service policy") {
			t.Fatalf("unit %q must be refused by the compiled policy bound, got %v", unit, err)
		}
	}
}

// The operation is part of the derivation bound: an operation the executor
// policy does not permit on the unit can never produce a capability.
func TestStage4RequiredCapabilitiesRefuseNonPermittedOperations(t *testing.T) {
	for _, op := range []string{"start", "stop", "reload", "enable", "disable", "enable-start", "disable-stop"} {
		_, err := RequiredCapabilities(state.Plan{Actions: []state.Action{stage4ServiceAction("fail2ban.service", op)}})
		if err == nil || !strings.Contains(err.Error(), "not permitted") {
			t.Fatalf("operation %q on fail2ban.service must be refused, got %v", op, err)
		}
	}
}

// Every mutating action kind without a compiled derivation fails closed —
// the mapper never implies an authority it does not have.
func TestStage4RequiredCapabilitiesFailClosedOnUnsupportedKinds(t *testing.T) {
	kinds := []state.ActionKind{
		state.ActionCreateFile, state.ActionUpdateFile, state.ActionDeleteOwnedFile,
		state.ActionSSH, state.ActionInstaller, state.ActionReboot,
		state.ActionFirewall, state.ActionRouting,
	}
	for _, kind := range kinds {
		a := state.Action{ID: "x", Resource: "r", Kind: kind, Ownership: state.Owned}
		_, err := RequiredCapabilities(state.Plan{Actions: []state.Action{a}})
		if err == nil || !strings.Contains(err.Error(), "no compiled capability derivation") {
			t.Fatalf("kind %q must fail closed, got %v", kind, err)
		}
	}
}

// A SERVICE action without its typed spec fails closed (never derives).
func TestStage4RequiredCapabilitiesRefuseSpeclessServiceAction(t *testing.T) {
	a := stage4ServiceAction("fail2ban.service", "restart")
	a.Spec = nil
	_, err := RequiredCapabilities(state.Plan{Actions: []state.Action{a}})
	if err == nil || !strings.Contains(err.Error(), "without a typed service spec") {
		t.Fatalf("specless SERVICE action must fail closed, got %v", err)
	}
}

// Read-only VALIDATE actions carry no capability requirement; an empty plan
// derives the empty set.
func TestStage4RequiredCapabilitiesSkipReadOnlyAndEmpty(t *testing.T) {
	set, err := RequiredCapabilities(state.Plan{Actions: []state.Action{
		{ID: "v", Resource: "external.thing", Kind: state.ActionValidate, Ownership: state.External},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !set.IsZero() {
		t.Fatalf("read-only actions must derive no capability, got %v", set.IDs())
	}
	empty, err := RequiredCapabilities(state.Plan{})
	if err != nil || !empty.IsZero() {
		t.Fatalf("an empty plan must derive the empty set: %v %v", empty.IDs(), err)
	}
}

// Cross-consistency pin: the capability package's unit validation mirrors
// the executor boundary's shared identity validation rule for rule. The
// duplication exists because the capability package must stay PURE (no
// repository-internal imports); this test is what keeps the mirror honest.
func TestStage4CapabilityUnitNameMatchesExecutorValidation(t *testing.T) {
	names := []string{
		"fail2ban.service", "ssh.service", "ssh.socket", "demo.service",
		"nginx.service", "a.service", "z-t_x9.service", "tpl@instance.service",
		"-lead.service", "trail-.service", "a.b.c.service", "x.timer",
		"x.mount.service", ".hidden.service", "..up.service", "sp ace.service",
		"uniкод.service", "", strings.Repeat("a", 256) + ".service",
		"sl/ash.service",
	}
	for _, name := range names {
		capErr := capability.ValidUnitName(name)
		idErr := identity.ValidUnitName(name)
		if (capErr == nil) != (idErr == nil) {
			t.Fatalf("unit %q: capability validation (%v) and executor identity validation (%v) disagree", name, capErr, idErr)
		}
	}
}
