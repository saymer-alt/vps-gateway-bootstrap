package validate

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

func healthyResult() discovery.Result {
	no := false
	return discovery.Result{
		SchemaVersion: discovery.SchemaVersion, DiscoveryVersion: "0.2.0", Status: "OK",
		Host: discovery.Host{Hostname: "gw1"},
		System: discovery.System{
			OS:     discovery.OS{ID: "ubuntu", Name: "Ubuntu", VersionID: "24.04"},
			Kernel: discovery.Kernel{Release: "6.8.0", Architecture: "x86_64"},
			Memory: discovery.Memory{TotalMB: 2048, AvailableMB: 1536},
			RootFS: discovery.Filesystem{Mountpoint: "/", AvailableBytes: 20 * gib},
		},
		Network: discovery.Network{
			ExternalInterface: "eth0", DefaultGateway: "203.0.113.1", IPv4: true, IPv6: true,
			DNS: discovery.DNS{Resolvers: []string{"1.1.1.1"}, Source: "resolvconf"},
		},
		Routing:      discovery.Routing{DefaultRoutes: []discovery.Route{{Device: "eth0"}}},
		Firewall:     discovery.Firewall{Layers: []string{"ufw"}},
		Capabilities: discovery.Capabilities{Systemd: true, UFW: true},
		SSH: discovery.SSH{
			Installed: true, Architecture: "service", EffectivePorts: []int{2222},
			PasswordAuthentication: &no,
		},
	}
}

func finding(t *testing.T, rep Report, component string) Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Component == component { return f }
	}
	t.Fatalf("finding %q not found in %#v", component, rep.Findings)
	return Finding{}
}

func TestValidateHealthyMachinePasses(t *testing.T) {
	rep := FromDiscovery(healthyResult(), Options{})
	if rep.Status != StatusPass { t.Fatalf("status=%s findings=%#v", rep.Status, rep.Findings) }
	for _, want := range []string{"DISCOVERY", "SSH", "SSH-HARDENING", "NETWORK", "ROUTING", "SYSTEMD", "FIREWALL"} {
		if f := finding(t, rep, want); f.Status != StatusPass { t.Fatalf("%s = %#v", want, f) }
	}
}

func TestValidateConflictFails(t *testing.T) {
	r := healthyResult()
	r.Status = "CONFLICT"
	r.Conflicts = []discovery.Observation{{Code: "PORT_CONFLICT", Component: "ssh", Message: "port occupied"}}
	rep := FromDiscovery(r, Options{})
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if f := finding(t, rep, "DISCOVERY"); f.Status != StatusFail { t.Fatalf("discovery=%#v", f) }
}

func TestValidateFailsClosedOnUnknownSSHState(t *testing.T) {
	r := healthyResult()
	r.SSH.PasswordAuthentication = nil
	rep := FromDiscovery(r, Options{})
	if rep.Status != StatusFail { t.Fatalf("unknown SSH hardening must fail: status=%s", rep.Status) }
	if f := finding(t, rep, "SSH-HARDENING"); f.Status != StatusFail { t.Fatalf("ssh hardening=%#v", f) }
}

func TestValidatePasswordAuthEnabledFails(t *testing.T) {
	r := healthyResult()
	yes := true
	r.SSH.PasswordAuthentication = &yes
	rep := FromDiscovery(r, Options{})
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if f := finding(t, rep, "SSH-HARDENING"); f.Status != StatusFail { t.Fatalf("ssh hardening=%#v", f) }
}

func TestValidateRequiresFirewallAndNetwork(t *testing.T) {
	r := healthyResult()
	r.Firewall.Layers = nil
	rep := FromDiscovery(r, Options{})
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if f := finding(t, rep, "FIREWALL"); f.Status != StatusFail { t.Fatalf("firewall=%#v", f) }

	r2 := healthyResult()
	r2.Network.DefaultGateway = ""
	rep2 := FromDiscovery(r2, Options{})
	if rep2.Status != StatusFail { t.Fatalf("status=%s", rep2.Status) }
	if f := finding(t, rep2, "NETWORK"); f.Status != StatusFail { t.Fatalf("network=%#v", f) }
}

func TestValidateProductionGate(t *testing.T) {
	r := healthyResult()
	rep := FromDiscovery(r, Options{Production: true})
	if rep.Status != StatusPass { t.Fatalf("status=%s findings=%#v", rep.Status, rep.Findings) }
	for _, want := range []string{"IPV4", "DNS", "MEMORY", "DISK", "STATE"} {
		if f := finding(t, rep, want); f.Status != StatusPass { t.Fatalf("%s = %#v", want, f) }
	}

	r2 := healthyResult()
	r2.System.Memory.TotalMB = 768
	rep2 := FromDiscovery(r2, Options{Production: true})
	if rep2.Status != StatusFail { t.Fatalf("production must fail below 1 GiB: status=%s", rep2.Status) }

	r3 := healthyResult()
	r3.Unknowns = []discovery.Observation{{Code: "FIREWALL_UNKNOWN", Component: "firewall", Message: "undetected"}}
	rep3 := FromDiscovery(r3, Options{Production: true})
	if rep3.Status != StatusFail { t.Fatalf("production must fail with unknowns: status=%s", rep3.Status) }

	rep4 := FromDiscovery(r3, Options{})
	if rep4.Status != StatusPass { t.Fatalf("base gate ignores unknowns: status=%s", rep4.Status) }
}

func TestValidateRenderAndJSON(t *testing.T) {
	rep := FromDiscovery(healthyResult(), Options{Production: true})
	out := Render(rep)
	for _, want := range []string{"vps-gateway validate — host: gw1", "PASS", "Result: PASS"} {
		if !strings.Contains(out, want) { t.Fatalf("rendered missing %q:\n%s", want, out) }
	}
	b, err := json.Marshal(rep)
	if err != nil { t.Fatal(err) }
	var back Report
	if err := json.Unmarshal(b, &back); err != nil { t.Fatal(err) }
	if back.Status != rep.Status || len(back.Findings) != len(rep.Findings) { t.Fatalf("round trip mismatch") }
}
