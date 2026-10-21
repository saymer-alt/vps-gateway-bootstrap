package doctor

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/identity"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/netdiag"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/sysctl"
)

// enrichedHealthyResult upgrades the doctor fixture to a fully-observed
// discovery result (inventories PRESENT/COMPLETE) so the assembled
// document contains no INCONCLUSIVE facts: this isolates the two
// regression properties below (clean machine stays OK; one incomplete
// diagnostic warns).
func enrichedHealthyResult() discovery.Result {
	r := healthyResult()
	r.Network.InterfacesStatus = discovery.InterfacesComplete
	r.Routing.RulesStatus = identity.FieldStatusPresent
	r.Routing.RoutesStatus = identity.FieldStatusPresent
	r.Firewall.Effective = map[string]string{"ufw.input_policy": "DROP", "ufw.output_policy": "ACCEPT"}
	r.Firewall.IPTablesRules = discovery.IPTablesRuleInventory{
		Status: identity.FieldStatusPresent, Table: "filter",
		Chains: []discovery.IPTablesChain{{Name: "INPUT", Policy: "DROP"}},
	}
	return r
}

func netdiagHealthyDoc(t *testing.T) netdiag.Document {
	t.Helper()
	return netdiag.Assemble(enrichedHealthyResult(), healthyNetdiagExtras(), netdiag.Options{})
}

// healthyNetdiagExtras provides hand-built extras so this test stays
// independent of the discovery producers.
func healthyNetdiagExtras() netdiag.Extras {
	return netdiag.Extras{
		DNS: discovery.DNSConfigEvidence{
			Status: discovery.FactStatusOK, EvidenceLevel: "CONFIG-INFERRED",
			FileKind: discovery.DNSFileRegular, Nameservers: []string{"1.1.1.1"},
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
			Units: []discovery.UnitHealth{{Unit: "docker.service", LoadState: "loaded", ActiveState: "active", SubState: "running", Classification: discovery.UnitActive}},
		},
		Handshakes: discovery.AWGHandshakeEvidence{Status: discovery.FactStatusSkipped},
	}
}

func TestAppendNetworkFindingsIsAdditiveAndLabelled(t *testing.T) {
	rep := FromDiscovery(enrichedHealthyResult())
	before := len(rep.Checks)
	beforeStatus := rep.Status
	doc := netdiagHealthyDoc(t)
	AppendNetworkFindings(&rep, doc)

	if len(rep.Checks) <= before {
		t.Fatal("no network findings appended")
	}
	for _, c := range rep.Checks[:before] {
		if c.Component == "NETDIAG" {
			t.Fatal("pre-existing checks were replaced")
		}
	}
	for _, c := range rep.Checks[before:] {
		if c.Component != "NETDIAG" {
			t.Fatalf("appended check carries component %q", c.Component)
		}
		if !strings.Contains(c.Detail, ".") {
			t.Fatalf("appended check detail lacks the fact id: %q", c.Detail)
		}
	}
	// Fully-observed healthy machine: no WARN/FAIL appended, so the overall
	// status is unchanged — existing doctor --json consumers keep their
	// verdict and exit code.
	if rep.Status != beforeStatus {
		t.Fatalf("status changed on a fully-observed healthy machine: %s → %s", beforeStatus, rep.Status)
	}
	// SKIPPED facts are not findings and are not rendered.
	for _, c := range rep.Checks[before:] {
		if strings.Contains(c.Detail, "mihomo_tun_config") {
			t.Fatal("SKIPPED facts must stay out of the human view")
		}
	}
}

// ZAI-91A regression: the network diagnostics run AFTER Discover, so an
// incomplete diagnostic is NOT part of discovery.Result.Unknowns. Hiding
// it as INFO could let the human doctor conclude "OK — no problems
// detected" while a check never completed. INCONCLUSIVE must warn.
func TestAppendNetworkFindingsInconclusiveWarnsNotOK(t *testing.T) {
	rep := FromDiscovery(enrichedHealthyResult())
	if rep.Status != StatusOK {
		t.Fatalf("precondition: discovery-only report should be OK, got %s", rep.Status)
	}
	doc := netdiagHealthyDoc(t)
	doc.Facts = append(doc.Facts, netdiag.Fact{
		ID: "gateway.wireguard_handshakes", Area: netdiag.AreaGateway,
		Status: netdiag.StatusInconclusive, EvidenceLevel: netdiag.EvidenceObserved,
		Source: "awg/wg show all latest-handshakes", Detail: "handshake ages not observed via awg",
		Unknowns: []string{"inspection interrupted"},
	})
	AppendNetworkFindings(&rep, doc)
	if rep.Status == StatusOK {
		t.Fatal("doctor must not report OK while a network diagnostic is INCONCLUSIVE")
	}
	if rep.Status != StatusWarn {
		t.Fatalf("status = %s, want WARN", rep.Status)
	}
	found := false
	for _, c := range rep.Checks {
		if c.Component == "NETDIAG" && c.Status == StatusWarn && strings.Contains(c.Detail, "gateway.wireguard_handshakes") {
			found = true
		}
	}
	if !found {
		t.Fatal("the INCONCLUSIVE fact is not visible as a WARN line carrying its id")
	}
}

func TestAppendNetworkFindingsEscalatesOnFail(t *testing.T) {
	rep := FromDiscovery(enrichedHealthyResult())
	doc := netdiagHealthyDoc(t)
	doc.Facts = append(doc.Facts, netdiag.Fact{
		ID: "test.injected_failure", Area: netdiag.AreaRouting,
		Status: netdiag.StatusFail, EvidenceLevel: netdiag.EvidenceObserved,
		Source: "test", Detail: "injected failure",
	})
	AppendNetworkFindings(&rep, doc)
	if rep.Status != StatusFail {
		t.Fatalf("status = %s, want FAIL", rep.Status)
	}
}

// SKIPPED stays non-alarming: a skipped diagnostic alone must not turn a
// healthy report into WARN or FAIL.
func TestAppendNetworkFindingsSkippedStaysNonAlarming(t *testing.T) {
	rep := FromDiscovery(enrichedHealthyResult())
	doc := netdiagHealthyDoc(t)
	doc.Facts = append(doc.Facts, netdiag.Fact{
		ID: "test.injected_skip", Area: netdiag.AreaGateway,
		Status: netdiag.StatusSkipped, EvidenceLevel: netdiag.EvidenceNotRequested,
		Source: "test", Detail: "injected skip",
	})
	AppendNetworkFindings(&rep, doc)
	if rep.Status != StatusOK {
		t.Fatalf("status = %s, want OK (SKIPPED is not a fault)", rep.Status)
	}
}
