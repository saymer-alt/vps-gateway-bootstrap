package netdiag

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// Issue #31 isolation pin: the versioned network-diagnostics/v1 document
// never carried Docker container identifiers — the gateway.docker fact is
// counts-only and discovery unknowns do not flow into the document. The
// short-form rendering at the discovery site must not change that: no
// full identifier, and not even the short form, belongs in the document.
func TestNetworkJSONDockerIDIsolation(t *testing.T) {
	id := strings.Repeat("1", 63) + "1"
	short := strings.Repeat("1", 12) + "…"
	r := healthyResult()
	r.Docker.Networks = []discovery.DockerNetwork{{
		Name:              "awgnet",
		AttachmentsStatus: discovery.AttachmentsObserved,
		Containers: []discovery.DockerNetworkContainer{{
			ContainerID: id, Name: "awg", IPv4Address: "172.18.0.2/16",
		}},
	}}
	r.Unknowns = []discovery.Observation{{
		Code: "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY", Component: "docker",
		Message: `network "awgnet": attached container ` + short + ` is absent from the container listing`,
	}}
	doc := Assemble(r, healthyExtras(), Options{})
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), id) {
		t.Fatalf("network-diagnostics/v1 must never carry the full container identifier")
	}
	if strings.Contains(string(blob), short) {
		t.Fatalf("network-diagnostics/v1 must not carry even the short container form: %s", blob)
	}
	var sawDockerFact bool
	for _, f := range doc.Facts {
		if f.ID == "gateway.docker" {
			sawDockerFact = true
			if f.Status != StatusOK || !strings.Contains(f.Detail, "1 network(s), 0 container(s)") {
				t.Fatalf("gateway.docker fact must stay counts-only: %#v", f)
			}
		}
	}
	if !sawDockerFact {
		t.Fatal("gateway.docker fact missing from the document")
	}
}
