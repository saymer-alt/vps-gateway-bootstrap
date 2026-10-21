package doctor

import (
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/netdiag"
)

func netdiagHealthyDoc(t *testing.T) netdiag.Document {
	t.Helper()
	return netdiag.Assemble(healthyResult(), healthyNetdiagExtras(), netdiag.Options{})
}

// netdiagHealthyDoc needs a discovery.Result compatible with the doctor
// fixture; the extras are hand-built so this test stays independent of the
// discovery producers.
func healthyNetdiagExtras() netdiag.Extras {
	return netdiag.Extras{
		DNS: discovery.DNSConfigEvidence{
			Status: discovery.FactStatusOK, EvidenceLevel: "CONFIG-INFERRED",
			FileKind: discovery.DNSFileRegular, Nameservers: []string{"1.1.1.1"},
			Resolved: discovery.ResolvedEvidence{Status: discovery.FactStatusOK, ActiveState: "active", SubState: "running"},
		},
		IPv6: discovery.IPv6Evidence{Status: discovery.FactStatusOK, InterfacesStatus: discovery.InterfacesComplete, Inventoried: 2},
		Services: discovery.ServiceHealthEvidence{
			Status: discovery.FactStatusOK, SystemctlAvailable: true,
			Units: []discovery.UnitHealth{{Unit: "docker.service", LoadState: "loaded", ActiveState: "active", SubState: "running", Classification: discovery.UnitActive}},
		},
		Handshakes: discovery.AWGHandshakeEvidence{Status: discovery.FactStatusSkipped},
	}
}

func TestAppendNetworkFindingsIsAdditiveAndLabelled(t *testing.T) {
	rep := FromDiscovery(healthyResult())
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
	// Healthy machine: no FAIL was appended, so the overall status is
	// unchanged — existing doctor --json consumers keep their verdict.
	if rep.Status != beforeStatus {
		t.Fatalf("status changed on a healthy machine: %s → %s", beforeStatus, rep.Status)
	}
	// SKIPPED facts are not findings and are not rendered.
	for _, c := range rep.Checks[before:] {
		if strings.Contains(c.Detail, "mihomo_tun_config") {
			t.Fatal("SKIPPED facts must stay out of the human view")
		}
	}
}

func TestAppendNetworkFindingsEscalatesOnFail(t *testing.T) {
	rep := FromDiscovery(healthyResult())
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
