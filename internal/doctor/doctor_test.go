package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

func healthyResult() discovery.Result {
	yes, no := true, false
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
		Routing:  discovery.Routing{DefaultRoutes: []discovery.Route{{Device: "eth0"}}, Rules: []discovery.Rule{{Priority: 100}}},
		Firewall: discovery.Firewall{Layers: []string{"ufw", "iptables"}},
		SSH: discovery.SSH{
			Installed: true, Architecture: "service", EffectivePorts: []int{2222},
			PasswordAuthentication: &no, PubkeyAuthentication: &yes,
		},
		Services: []discovery.Service{{Name: "ssh.service", Exists: true, Enabled: true, Active: true, SubState: "running"}},
	}
}

func findCheck(t *testing.T, rep Report, component string) Check {
	t.Helper()
	var found []Check
	for _, c := range rep.Checks {
		if c.Component == component { found = append(found, c) }
	}
	if len(found) == 0 { t.Fatalf("check %q not found in %#v", component, rep.Checks) }
	return found[len(found)-1]
}

func TestDoctorHealthyMachine(t *testing.T) {
	rep := FromDiscovery(healthyResult())
	if rep.Status != StatusOK { t.Fatalf("status=%s", rep.Status) }
	if rep.Host != "gw1" { t.Fatalf("host=%q", rep.Host) }
	for _, want := range []string{"SYSTEM", "MEMORY", "DISK", "NETWORK", "DNS", "ROUTING", "FIREWALL", "SSH"} {
		c := findCheck(t, rep, want)
		if c.Status == StatusFail { t.Fatalf("%s unexpectedly failed: %#v", want, c) }
	}
	if c := findCheck(t, rep, "SSH"); c.Detail != "password authentication disabled" {
		t.Fatalf("ssh hardening check = %#v", c)
	}
}

func TestDoctorFlagsMissingGateway(t *testing.T) {
	r := healthyResult()
	r.Network.ExternalInterface = ""
	r.Network.DefaultGateway = ""
	rep := FromDiscovery(r)
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if c := findCheck(t, rep, "NETWORK"); c.Status != StatusFail { t.Fatalf("network check=%#v", c) }
}

func TestDoctorFlagsPasswordAuthentication(t *testing.T) {
	r := healthyResult()
	yes := true
	r.SSH.PasswordAuthentication = &yes
	rep := FromDiscovery(r)
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if c := findCheck(t, rep, "SSH"); c.Status != StatusFail { t.Fatalf("ssh check=%#v", c) }
}

func TestDoctorWarningsFromUnknowns(t *testing.T) {
	r := healthyResult()
	r.Unknowns = []discovery.Observation{{Code: "FIREWALL_UNKNOWN", Component: "firewall", Message: "no supported firewall frontend detected"}}
	rep := FromDiscovery(r)
	if rep.Status != StatusWarn { t.Fatalf("status=%s", rep.Status) }
	found := false
	for _, c := range rep.Checks {
		if c.Component == "UNKNOWN" && c.Status == StatusWarn { found = true }
	}
	if !found { t.Fatalf("unknown finding missing: %#v", rep.Checks) }
}

func TestDoctorConflictsFailReport(t *testing.T) {
	r := healthyResult()
	r.Conflicts = []discovery.Observation{{Code: "PORT_CONFLICT", Component: "ssh", Message: "port 2200 occupied by unknown service"}}
	rep := FromDiscovery(r)
	if rep.Status != StatusFail { t.Fatalf("status=%s", rep.Status) }
	if len(rep.Conflicts) != 1 || rep.Conflicts[0].Code != "PORT_CONFLICT" { t.Fatalf("conflicts=%#v", rep.Conflicts) }
}

func TestDoctorSmallMachineWarnsOrFails(t *testing.T) {
	r := healthyResult()
	r.System.Memory.TotalMB = 400
	rep := FromDiscovery(r)
	if c := findCheck(t, rep, "MEMORY"); c.Status != StatusFail { t.Fatalf("memory check=%#v", c) }

	r2 := healthyResult()
	r2.System.Memory.TotalMB = 768
	rep2 := FromDiscovery(r2)
	if c := findCheck(t, rep2, "MEMORY"); c.Status != StatusWarn { t.Fatalf("memory check=%#v", c) }
}

func TestDoctorInactiveKnownServiceWarns(t *testing.T) {
	r := healthyResult()
	r.Services = append(r.Services, discovery.Service{Name: "mihomo.service", Exists: true, Active: false, SubState: "dead"})
	rep := FromDiscovery(r)
	found := false
	for _, c := range rep.Checks {
		if c.Component == "SERVICE" && strings.Contains(c.Detail, "mihomo.service inactive (dead)") && c.Status == StatusWarn { found = true }
	}
	if !found { t.Fatalf("inactive service finding missing: %#v", rep.Checks) }
}

func TestRenderHumanReadable(t *testing.T) {
	r := healthyResult()
	r.Conflicts = []discovery.Observation{{Code: "PORT_CONFLICT", Component: "ssh", Message: "port 2200 occupied by unknown service"}}
	out := Render(FromDiscovery(r))
	for _, want := range []string{"vps-gateway doctor — host: gw1", "Discovery: OK", "SSH", "Conflicts:", "[PORT_CONFLICT] ssh: port 2200 occupied by unknown service", "Diagnosis: FAIL"} {
		if !strings.Contains(out, want) { t.Fatalf("rendered output missing %q:\n%s", want, out) }
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	rep := FromDiscovery(healthyResult())
	b, err := json.Marshal(rep)
	if err != nil { t.Fatal(err) }
	var back Report
	if err := json.Unmarshal(b, &back); err != nil { t.Fatal(err) }
	if back.Status != rep.Status || back.Host != rep.Host || len(back.Checks) != len(rep.Checks) {
		t.Fatalf("round trip mismatch: %#v vs %#v", back, rep)
	}
}
