package pipeline

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

func healthyDiscovery() discovery.Result {
	no := false
	return discovery.Result{
		SchemaVersion: discovery.SchemaVersion, DiscoveryVersion: "0.2.0", Status: "OK",
		Host: discovery.Host{Hostname: "gw1"},
		System: discovery.System{OS: discovery.OS{ID: "ubuntu", Name: "Ubuntu", VersionID: "24.04"}, Kernel: discovery.Kernel{Release: "6.8.0", Architecture: "x86_64"}},
		Network: discovery.Network{ExternalInterface: "eth0", DefaultGateway: "203.0.113.1", IPv4: true},
		Firewall: discovery.Firewall{Layers: []string{"ufw"}},
		Capabilities: discovery.Capabilities{Systemd: true},
		SSH: discovery.SSH{Installed: true, Architecture: "service", EffectivePorts: []int{2222}, PasswordAuthentication: &no},
	}
}

func TestAssembleWithoutConfigProducesEmptyPlan(t *testing.T) {
	res := Assemble(healthyDiscovery(), nil, rootOn())
	if len(res.Plan.Actions) != 0 { t.Fatalf("unspecified desired state must not produce actions: %#v", res.Plan.Actions) }
	if res.Plan.Blocked { t.Fatalf("plan blocked: %v", res.Plan.BlockReasons) }
	if res.Model.Status != state.StatusOK { t.Fatalf("model status=%s", res.Model.Status) }
}

func TestAssembleMatchingDesiredPortIsNoChange(t *testing.T) {
	cfg := &Config{
		Desired:   &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2222)}},
		Ownership: map[string]state.Ownership{"ssh": state.Owned},
	}
	res := Assemble(healthyDiscovery(), cfg, rootOn())
	if len(res.Plan.Actions) != 0 { t.Fatalf("expected no actions, got %#v", res.Plan.Actions) }
	if !res.Ready() { t.Fatalf("ready=%v preflight=%#v plan=%#v", res.Ready(), res.Preflight, res.Plan) }
}

func TestAssembleUnknownOwnershipBlocksSSHChange(t *testing.T) {
	cfg := &Config{Desired: &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}}}
	res := Assemble(healthyDiscovery(), cfg, rootOn())
	if !res.Plan.Blocked { t.Fatalf("plan must block on unknown SSH ownership: %#v", res.Plan) }
	if res.Ready() { t.Fatal("pipeline must not be ready while plan is blocked") }
}

func TestAssembleOwnedSSHChangeProducesStagedAction(t *testing.T) {
	cfg := &Config{
		Desired:   &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}},
		Ownership: map[string]state.Ownership{"ssh": state.Owned},
	}
	res := Assemble(healthyDiscovery(), cfg, rootOn())
	if res.Plan.Blocked { t.Fatalf("plan blocked: %v", res.Plan.BlockReasons) }
	if len(res.Plan.Actions) != 1 || res.Plan.Actions[0].Kind != state.ActionSSH { t.Fatalf("actions=%#v", res.Plan.Actions) }
	spec := res.Plan.Actions[0].Spec.SSH
	if spec == nil || spec.NewPort != 2200 || spec.OldPort != 2222 || spec.ConfigPath == "" {
		t.Fatalf("ssh spec=%#v", spec)
	}
}

func TestAssembleConflictDiscoveryBlocksPlan(t *testing.T) {
	r := healthyDiscovery()
	r.Status = "CONFLICT"
	r.Conflicts = []discovery.Observation{{Code: "PORT_CONFLICT", Component: "ssh", Message: "port occupied"}}
	res := Assemble(r, nil, rootOn())
	if res.Model.Status != state.StatusConflict { t.Fatalf("model status=%s", res.Model.Status) }
}

func TestParseConfigDesiredAndOwnership(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{
		"desired": {"ssh": {"port": 2200, "password_authentication": false}},
		"ownership": {"ssh": "OWNED", "mihomo.integration": "OWNED"}
	}`))
	if err != nil { t.Fatal(err) }
	if cfg.Desired == nil || cfg.Desired.SSH == nil || cfg.Desired.SSH.Port == nil || *cfg.Desired.SSH.Port != 2200 {
		t.Fatalf("desired=%#v", cfg.Desired)
	}
	if cfg.Ownership["ssh"] != state.Owned { t.Fatalf("ownership=%#v", cfg.Ownership) }

	empty, err := ParseConfig(nil)
	if err != nil { t.Fatal(err) }
	if empty.Desired != nil || empty.Ownership != nil { t.Fatalf("empty config=%#v", empty) }

	if _, err := ParseConfig([]byte("{broken")); err == nil { t.Fatal("expected parse error") }
}

func TestSummaryRender(t *testing.T) {
	cfg := &Config{
		Desired:   &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2222)}},
		Ownership: map[string]state.Ownership{"ssh": state.Owned},
	}
	out := Summary(Assemble(healthyDiscovery(), cfg, rootOn()))
	for _, want := range []string{"DISCOVERY", "STATE MODEL", "OWNERSHIP", "CONFLICTS", "PLAN", "PREFLIGHT", "APPLY", "skipped (dry-run)", "READY"} {
		if !strings.Contains(out, want) { t.Fatalf("summary missing %q:\n%s", want, out) }
	}

	blocked := Summary(Assemble(healthyDiscovery(), &Config{Desired: &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}}}, rootOn()))
	if !strings.Contains(blocked, "BLOCKED") { t.Fatalf("blocked summary:\n%s", blocked) }
}

func TestResultJSONRoundTrip(t *testing.T) {
	res := Assemble(healthyDiscovery(), nil, rootOn())
	b, err := json.Marshal(res)
	if err != nil { t.Fatal(err) }
	var back Result
	if err := json.Unmarshal(b, &back); err != nil { t.Fatal(err) }
	if back.Plan.Blocked != res.Plan.Blocked || back.Preflight.Status != res.Preflight.Status {
		t.Fatalf("round trip mismatch")
	}
}

func intPtr(n int) *int { return &n }

// rootOn makes preflight deterministic: tests must not depend on the euid
// of the process running them.
func rootOn() Options { t := true; return Options{Root: &t} }

func persistedState(ownership map[string]state.Ownership) *state.Model {
	return &state.Model{SchemaVersion: state.SchemaVersion, Ownership: ownership, Status: state.StatusOK}
}

func TestAssembleUsesPersistedOwnershipAsFallback(t *testing.T) {
	cfg := &Config{Desired: &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}}}
	opts := rootOn()
	opts.State = persistedState(map[string]state.Ownership{"ssh": state.Owned})
	res := Assemble(healthyDiscovery(), cfg, opts)
	if res.OwnershipSource != "state" { t.Fatalf("source=%q", res.OwnershipSource) }
	if res.Plan.Blocked { t.Fatalf("persisted ownership must unblock the plan: %v", res.Plan.BlockReasons) }
	if len(res.Plan.Actions) != 1 { t.Fatalf("actions=%#v", res.Plan.Actions) }
}

func TestAssembleConfigOverridesPersistedState(t *testing.T) {
	cfg := &Config{
		Desired:   &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}},
		Ownership: map[string]state.Ownership{"ssh": state.External},
	}
	opts := rootOn()
	opts.State = persistedState(map[string]state.Ownership{"ssh": state.Owned})
	res := Assemble(healthyDiscovery(), cfg, opts)
	if res.OwnershipSource != "config" { t.Fatalf("source=%q", res.OwnershipSource) }
	if !res.Plan.Blocked {
		t.Fatal("explicit config ownership must win over persisted state and block non-owned mutation")
	}
}

func TestAssembleNoOwnershipAnywhereBlocksSSHChange(t *testing.T) {
	cfg := &Config{Desired: &state.Desired{SSH: &state.SSHDesired{Port: intPtr(2200)}}}
	opts := rootOn()
	opts.State = persistedState(nil)
	res := Assemble(healthyDiscovery(), cfg, opts)
	if res.OwnershipSource != "" { t.Fatalf("source=%q", res.OwnershipSource) }
	if !res.Plan.Blocked { t.Fatal("no ownership declared anywhere must block") }
}

// Persisted state is a fallback for ownership/desired only. The actual state
// always comes from live discovery; a stale persisted Actual must never leak
// into the assembled model.
func TestAssemblePersistedStateDoesNotOverrideLiveDiscovery(t *testing.T) {
	stale := persistedState(map[string]state.Ownership{"ssh": state.Owned})
	stale.Actual = state.Actual{
		System:  state.SystemActual{OS: "debian", Kernel: "3.2.0", Architecture: "i386"},
		Network: state.NetworkActual{ExternalInterface: "eth9", DefaultGateway: "198.51.100.1"},
		Security: state.SecurityActual{SSHPorts: []int{22}},
	}
	opts := rootOn()
	opts.State = stale
	res := Assemble(healthyDiscovery(), nil, opts)
	if res.Model.Actual.System.OS != "ubuntu" || res.Model.Actual.System.Architecture != "x86_64" {
		t.Fatalf("live discovery overridden by persisted actual: %#v", res.Model.Actual.System)
	}
	if res.Model.Actual.Network.ExternalInterface != "eth0" || res.Model.Actual.Network.DefaultGateway != "203.0.113.1" {
		t.Fatalf("network overridden by persisted actual: %#v", res.Model.Actual.Network)
	}
	if len(res.Model.Actual.Security.SSHPorts) != 1 || res.Model.Actual.Security.SSHPorts[0] != 2222 {
		t.Fatalf("security overridden by persisted actual: %#v", res.Model.Actual.Security)
	}
}

// Unset desired state is not permission to modify: even with ownership
// explicitly declared, nothing may change unless something is desired.
func TestAssembleUnsetDesiredWithDeclaredOwnershipProducesNoActions(t *testing.T) {
	cfg := &Config{Ownership: map[string]state.Ownership{"ssh": state.Owned, "mihomo.integration": state.Owned}}
	res := Assemble(healthyDiscovery(), cfg, rootOn())
	if len(res.Plan.Actions) != 0 { t.Fatalf("declared ownership without desired state must not produce actions: %#v", res.Plan.Actions) }
	if res.Plan.Blocked { t.Fatalf("plan blocked: %v", res.Plan.BlockReasons) }
}
