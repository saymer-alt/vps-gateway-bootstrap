package netdiag

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

func healthyResult() discovery.Result {
	r := discovery.Result{Status: "OK"}
	r.Host.Hostname = "gw1"
	r.Network.InterfacesStatus = discovery.InterfacesComplete
	r.Network.Interfaces = []discovery.Interface{{Name: "eth0"}, {Name: "lo"}}
	r.Network.ExternalInterface = "eth0"
	r.Network.DefaultGateway = "203.0.113.1"
	r.Routing.RulesStatus = identity.FieldStatusPresent
	r.Routing.RoutesStatus = identity.FieldStatusPresent
	r.Routing.DefaultRoutes = []discovery.Route{{Destination: "default", Device: "eth0", Gateway: "203.0.113.1", Table: "main"}}
	r.Routing.Rules = []discovery.Rule{{Priority: 0, From: "all", Table: 0, TableRaw: "local", Status: identity.FieldStatusPresent}}
	r.Routing.Tables = []discovery.RouteTable{{ID: 254, Name: "main", Routes: []discovery.Route{{Destination: "default", Device: "eth0"}}}}
	r.Ports = []discovery.Listener{{Address: "0.0.0.0", Port: 22, Protocol: "tcp", Process: "sshd"}}
	r.Firewall.Layers = []string{"ufw", "iptables"}
	r.Firewall.UFW = discovery.ToolState{Installed: true, Active: true}
	r.Firewall.IPTables = discovery.ToolState{Installed: true, Active: true}
	r.Firewall.Effective = map[string]string{"ufw.input_policy": "DROP", "ufw.output_policy": "ACCEPT", "ufw.forward_policy": "DROP"}
	r.Firewall.IPTablesRules = discovery.IPTablesRuleInventory{Status: identity.FieldStatusPresent, Table: "filter", Chains: []discovery.IPTablesChain{{Name: "INPUT", Policy: "DROP", Rules: []discovery.IPTablesRule{{Raw: "-A INPUT -j DROP", Supported: true, Spec: &discovery.IPTablesRuleSpec{Verdict: "DROP"}}}}}}
	r.Firewall.IPTablesMangleRules = discovery.IPTablesRuleInventory{Status: identity.FieldStatusPresent, Table: "mangle", Chains: []discovery.IPTablesChain{{Name: "FORWARD", Rules: []discovery.IPTablesRule{{Raw: "-A FORWARD -j DROP", Supported: true, Spec: &discovery.IPTablesRuleSpec{Verdict: "DROP", Comment: "guard-test"}}}}}}
	r.Docker.Installed = true
	r.Docker.Active = true
	r.Docker.Version = "29.1.3"
	return r
}

func healthyExtras() Extras {
	return Extras{
		DNS: discovery.DNSConfigEvidence{
			Status: discovery.FactStatusOK, EvidenceLevel: string(EvidenceConfigInferred),
			FileKind: discovery.DNSFileRegular, Nameservers: []string{"1.1.1.1", "8.8.8.8"},
			Resolved: discovery.ResolvedEvidence{Status: discovery.FactStatusOK, ActiveState: "active", SubState: "running"},
		},
		IPv6: discovery.IPv6Evidence{
			Status: discovery.FactStatusOK, InterfacesStatus: discovery.InterfacesComplete, Inventoried: 2,
			Forwarding: []sysctl.RuntimeObservation{
				{Key: "net.ipv6.conf.all.forwarding", Value: 0, Status: sysctl.RuntimePresent},
				{Key: "net.ipv6.conf.default.forwarding", Value: 0, Status: sysctl.RuntimePresent},
			},
		},
		Services: discovery.ServiceHealthEvidence{
			Status: discovery.FactStatusOK, SystemctlAvailable: true,
			Units: []discovery.UnitHealth{
				{Unit: "docker.service", LoadState: "loaded", ActiveState: "active", SubState: "running", Classification: discovery.UnitActive},
				{Unit: "ssh.socket", LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Classification: discovery.UnitInactive},
			},
		},
		Handshakes: discovery.AWGHandshakeEvidence{Status: discovery.FactStatusSkipped,
			Unknowns: []string{"no awg/wg inspection binary in PATH; handshake ages not observable (binary-optional)"}},
	}
}

func factByID(t *testing.T, doc Document, id string) Fact {
	t.Helper()
	for _, f := range doc.Facts {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("fact %q not found in %d facts", id, len(doc.Facts))
	return Fact{}
}

func TestHealthyBaselineAllAreasOK(t *testing.T) {
	doc := Assemble(healthyResult(), healthyExtras(), Options{})
	if doc.Schema != Schema {
		t.Fatalf("schema = %s", doc.Schema)
	}
	if doc.Summary.Overall != StatusOK {
		for _, f := range doc.Facts {
			t.Logf("%s %s %s", f.ID, f.Status, f.Detail)
		}
		t.Fatalf("overall = %s", doc.Summary.Overall)
	}
	if len(doc.Hypotheses) != 0 {
		t.Fatalf("hypotheses must stay empty in v1: %v", doc.Hypotheses)
	}
	// No FAIL anywhere; every area resolved OK or SKIPPED-only.
	for _, f := range doc.Facts {
		if f.Status == StatusFail || f.Status == StatusInconclusive {
			t.Fatalf("healthy baseline produced %s on %s", f.Status, f.ID)
		}
	}
	// Expectation facts report NOT-REQUESTED on the CLI path.
	for _, id := range []string{"routing.expected_policy", "firewall.expected_guard", "listeners.expected"} {
		f := factByID(t, doc, id)
		if f.Status != StatusSkipped || f.EvidenceLevel != EvidenceNotRequested {
			t.Fatalf("%s = %+v", id, f)
		}
	}
	// Mihomo config evidence stays explicitly not collected, never absent.
	f := factByID(t, doc, "gateway.mihomo_tun_config")
	if f.Status != StatusSkipped || f.EvidenceLevel != EvidenceNotRequested {
		t.Fatalf("mihomo config fact = %+v", f)
	}
	// No Test-topology value appears anywhere in the document.
	blob, _ := json.Marshal(doc)
	for _, banned := range []string{"2030", "10.30.0.0", "mitun0", "ZAI85", "5000: "} {
		if strings.Contains(string(blob), banned) {
			t.Fatalf("document leaks topology value %q", banned)
		}
	}
}

func TestFactsSortedAndDocumentDeterministic(t *testing.T) {
	a, _ := json.Marshal(Assemble(healthyResult(), healthyExtras(), Options{}))
	b, _ := json.Marshal(Assemble(healthyResult(), healthyExtras(), Options{}))
	if string(a) != string(b) {
		t.Fatal("identical inputs produced different documents")
	}
	var doc Document
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(doc.Facts); i++ {
		if doc.Facts[i-1].ID >= doc.Facts[i].ID {
			t.Fatalf("facts not strictly ordered at %d: %s >= %s", i, doc.Facts[i-1].ID, doc.Facts[i].ID)
		}
	}
}

func TestMissingExpectedListenerUnderExplicitExpectation(t *testing.T) {
	res := healthyResult()
	opts := Options{ExpectedListeners: []ExpectedListener{{Protocol: "tcp", Port: 22}}}
	if f := listenersExpectedFact(res, opts); f.Status != StatusOK {
		t.Fatalf("present expected listener = %+v", f)
	}
	opts.ExpectedListeners = append(opts.ExpectedListeners, ExpectedListener{Protocol: "udp", Port: 51820})
	if f := listenersExpectedFact(res, opts); f.Status != StatusFail || !strings.Contains(f.Detail, "udp/51820") {
		t.Fatalf("missing expected listener = %+v", f)
	}
	// Inventory unknown → INCONCLUSIVE, never FAIL.
	res.Unknowns = append(res.Unknowns, discovery.Observation{Code: "PORTS_UNKNOWN", Component: "ports", Message: "ss failed"})
	if f := listenersExpectedFact(res, opts); f.Status != StatusInconclusive {
		t.Fatalf("unknown inventory = %+v", f)
	}
	// Invalid expectation → INCONCLUSIVE.
	if f := listenersExpectedFact(res, Options{ExpectedListeners: []ExpectedListener{{Protocol: "sctp", Port: 1}}}); f.Status != StatusInconclusive {
		t.Fatalf("invalid expectation = %+v", f)
	}
}

func TestListenerCommandFailureIsInconclusive(t *testing.T) {
	res := healthyResult()
	res.Unknowns = append(res.Unknowns,
		discovery.Observation{Code: "PORTS_UNKNOWN", Component: "ports", Message: "ports: exit status 1"},
		discovery.Observation{Code: "PORTS_UDP_UNKNOWN", Component: "ports", Message: "ports: exit status 1"})
	doc := Assemble(res, healthyExtras(), Options{})
	for _, id := range []string{"listeners.tcp", "listeners.udp"} {
		f := factByID(t, doc, id)
		if f.Status != StatusInconclusive || len(f.Unknowns) == 0 {
			t.Fatalf("%s = %+v", id, f)
		}
	}
	if doc.Summary.Overall != StatusInconclusive {
		t.Fatalf("overall = %s", doc.Summary.Overall)
	}
}

func TestExpectedRoutingPolicyEvaluation(t *testing.T) {
	res := healthyResult()
	res.Routing.Rules = append(res.Routing.Rules,
		discovery.Rule{Priority: 5000, From: "10.99.0.0/24", Table: 99, TableRaw: "99", Status: identity.FieldStatusPresent})
	res.Routing.Tables = append(res.Routing.Tables, discovery.RouteTable{ID: 99, Name: "99", Routes: []discovery.Route{
		{Destination: "default", Device: "tun99"},
		{Destination: "default", Type: "unreachable", Metric: 42760},
	}})
	prio := 5000
	opts := Options{ExpectedRouting: &ExpectedRouting{From: "10.99.0.0/24", Table: 99, Priority: &prio, FallbackUnreachable: true}}
	if f := routingExpectedPolicyFact(res, opts); f.Status != StatusOK || !strings.Contains(f.Detail, "unreachable") {
		t.Fatalf("matched expectation = %+v", f)
	}
	// Rule missing → FAIL.
	opts2 := Options{ExpectedRouting: &ExpectedRouting{From: "10.99.0.0/24", Table: 100}}
	if f := routingExpectedPolicyFact(res, opts2); f.Status != StatusFail {
		t.Fatalf("missing rule = %+v", f)
	}
	// Fallback missing → FAIL with the precise half.
	opts3 := Options{ExpectedRouting: &ExpectedRouting{From: "10.99.0.0/24", Table: 99, FallbackUnreachable: true}}
	res3 := res
	res3.Routing.Tables = res.Routing.Tables[:1]
	if f := routingExpectedPolicyFact(res3, opts3); f.Status != StatusFail || !strings.Contains(f.Detail, "fallback") {
		t.Fatalf("missing fallback = %+v", f)
	}
	// Rule inventory unknown → INCONCLUSIVE.
	res4 := healthyResult()
	res4.Routing.RulesStatus = identity.FieldStatusUnknownPermission
	opts4 := Options{ExpectedRouting: &ExpectedRouting{From: "all", Table: 99}}
	if f := routingExpectedPolicyFact(res4, opts4); f.Status != StatusInconclusive {
		t.Fatalf("unknown inventory = %+v", f)
	}
	// Invalid expectation → INCONCLUSIVE.
	opts5 := Options{ExpectedRouting: &ExpectedRouting{From: "not-a-prefix", Table: 99}}
	if f := routingExpectedPolicyFact(res, opts5); f.Status != StatusInconclusive {
		t.Fatalf("invalid expectation = %+v", f)
	}
}

func TestExpectedFailClosedGuardEvaluation(t *testing.T) {
	res := healthyResult()
	opts := Options{ExpectedGuard: &ExpectedGuard{MangleComment: "guard-test"}}
	if f := firewallExpectedGuardFact(res, opts); f.Status != StatusOK {
		t.Fatalf("present guard = %+v", f)
	}
	if f := firewallExpectedGuardFact(res, Options{ExpectedGuard: &ExpectedGuard{MangleComment: "other"}}); f.Status != StatusFail {
		t.Fatalf("missing guard = %+v", f)
	}
	res.Firewall.IPTablesMangleRules.Status = identity.FieldStatusUnknownPermission
	if f := firewallExpectedGuardFact(res, opts); f.Status != StatusInconclusive {
		t.Fatalf("unknown mangle inventory = %+v", f)
	}
}

func TestAmbiguousFirewallOutputIsInconclusive(t *testing.T) {
	res := healthyResult()
	res.Unknowns = append(res.Unknowns, discovery.Observation{
		Code: "FIREWALL_NFTABLES_UNKNOWN", Component: "firewall",
		Message: "multiple base chains for hook forward disagree (accept, drop); the effective policy is not a single value",
	})
	doc := Assemble(res, healthyExtras(), Options{})
	f := factByID(t, doc, "firewall.rule_inventories")
	if f.Status != StatusInconclusive || len(f.Unknowns) == 0 {
		t.Fatalf("ambiguous firewall = %+v", f)
	}
}

func TestIPv6ForwardingUnderExplicitExpectations(t *testing.T) {
	extras := healthyExtras()
	extras.IPv6.Forwarding[0].Value = 1 // all=1
	// No policy: observed fact, never a universal failure.
	if f := ipv6ForwardingFact(extras, Options{}); f.Status != StatusOK || !strings.Contains(f.Detail, "observation only") {
		t.Fatalf("no-policy forwarding = %+v", f)
	}
	// Explicit no-forwarding policy + forwarding on → FAIL.
	if f := ipv6ForwardingFact(extras, Options{IPv6ForwardingForbidden: true}); f.Status != StatusFail {
		t.Fatalf("policy violation = %+v", f)
	}
	// Policy + forwarding off → OK.
	extras.IPv6.Forwarding[0].Value = 0
	if f := ipv6ForwardingFact(extras, Options{IPv6ForwardingForbidden: true}); f.Status != StatusOK || !strings.Contains(f.Detail, "complies") {
		t.Fatalf("policy compliance = %+v", f)
	}
	// Sysctl read failed → INCONCLUSIVE.
	extras.IPv6.Forwarding[0].Status = sysctl.RuntimeUnknownPermission
	if f := ipv6ForwardingFact(extras, Options{}); f.Status != StatusInconclusive || len(f.Unknowns) != 1 {
		t.Fatalf("unreadable forwarding = %+v", f)
	}
}

func TestServiceFactsDistinguishStates(t *testing.T) {
	extras := Extras{
		Services: discovery.ServiceHealthEvidence{Status: discovery.FactStatusOK, SystemctlAvailable: true, Units: []discovery.UnitHealth{
			{Unit: "docker.service", LoadState: "loaded", ActiveState: "active", SubState: "running", Classification: discovery.UnitActive},
			{Unit: "ssh.socket", LoadState: "loaded", ActiveState: "inactive", SubState: "dead", Classification: discovery.UnitInactive},
			{Unit: "fail2ban.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed", Classification: discovery.UnitFailed},
			{Unit: "mita.service", LoadState: "not-found", ActiveState: "inactive", SubState: "dead", Classification: discovery.UnitAbsent},
			{Unit: "ufw.service", LoadState: "masked", ActiveState: "inactive", SubState: "dead", Classification: discovery.UnitMasked},
			{Unit: "weird.service", LoadState: "error", ActiveState: "failed", SubState: "failed", Classification: discovery.UnitUnclassified},
		}},
	}
	doc := Assemble(healthyResult(), extras, Options{})
	cases := map[string]Status{
		"services.docker.service":   StatusOK,
		"services.ssh.socket":       StatusOK, // inactive ssh.socket on a service host is normal
		"services.fail2ban.service": StatusFail,
		"services.mita.service":     StatusSkipped,
		"services.ufw.service":      StatusSkipped,
		"services.weird.service":    StatusInconclusive,
	}
	for id, want := range cases {
		if f := factByID(t, doc, id); f.Status != want {
			t.Fatalf("%s = %s, want %s (%s)", id, f.Status, want, f.Detail)
		}
	}
	if doc.Summary.Overall != StatusFail {
		// A failed unit (FAIL) dominates the area and the document; the
		// unclassifiable unit stays visible as an INCONCLUSIVE fact.
		t.Fatalf("overall = %s", doc.Summary.Overall)
	}
}

func TestDNSFactsCoverFileVariants(t *testing.T) {
	extras := Extras{DNS: discovery.DNSConfigEvidence{
		Status: discovery.FactStatusFail, EvidenceLevel: string(EvidenceObserved),
		FileKind: discovery.DNSFileBroken, SymlinkTarget: "/run/systemd/resolve/stub-resolv.conf",
		Resolved: discovery.ResolvedEvidence{Status: discovery.FactStatusSkipped, LoadState: "not-found"},
	}}
	doc := Assemble(healthyResult(), extras, Options{})
	f := factByID(t, doc, "dns.resolv_conf")
	if f.Status != StatusFail || !strings.Contains(f.Detail, "dangling symlink") {
		t.Fatalf("broken resolv.conf fact = %+v", f)
	}
	r := factByID(t, doc, "dns.resolved")
	if r.Status != StatusSkipped {
		t.Fatalf("resolved fact = %+v", r)
	}
}

func TestSecretRedactionSweep(t *testing.T) {
	extras := healthyExtras()
	hex := strings.Repeat("a1b2c3d4", 8) // 64 hex chars
	b64 := "bUspa3qSahtktFvMcwx7hLcLsTRDdVJ6V+FnLa8IU2c="
	extras.DNS.Unknowns = append(extras.DNS.Unknowns, "read failed: token "+hex+" and "+b64)
	doc := Assemble(healthyResult(), extras, Options{})
	blob, _ := json.Marshal(doc)
	if strings.Contains(string(blob), hex) || strings.Contains(string(blob), b64) {
		t.Fatal("credential-shaped token survived redaction")
	}
	if !strings.Contains(string(blob), "[REDACTED]") {
		t.Fatal("redaction marker missing")
	}
}

func TestProducerVocabulariesMatchDocumentContract(t *testing.T) {
	if string(StatusOK) != discovery.FactStatusOK || string(StatusFail) != discovery.FactStatusFail ||
		string(StatusSkipped) != discovery.FactStatusSkipped || string(StatusInconclusive) != discovery.FactStatusInconclusive {
		t.Fatal("producer status vocabulary drifted from the document contract")
	}
	// factStatus fail-closes unknown producer statuses.
	if factStatus("MAYBE") != StatusInconclusive || factStatus("") != StatusInconclusive {
		t.Fatal("factStatus must fail closed")
	}
	if factEvidence("NOT-REQUESTED") != EvidenceNotRequested || factEvidence("bogus") != EvidenceObserved {
		t.Fatal("factEvidence classification wrong")
	}
}

func TestAllZeroExtrasNeverFabricate(t *testing.T) {
	doc := Assemble(healthyResult(), Extras{}, Options{})
	for _, id := range []string{"dns.resolv_conf", "dns.resolved", "ipv6.forwarding", "services.units", "gateway.wireguard_handshakes"} {
		f := factByID(t, doc, id)
		if f.Status != StatusSkipped && f.Status != StatusInconclusive {
			t.Fatalf("%s fabricated state: %s (%s)", id, f.Status, f.Detail)
		}
	}
	if doc.Summary.Overall != StatusInconclusive {
		t.Fatalf("overall with no extras = %s, want INCONCLUSIVE", doc.Summary.Overall)
	}
}
