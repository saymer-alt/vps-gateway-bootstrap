package doctor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// Issue #31 compatibility pin: the doctor layer renders the Docker
// inventory-mismatch unknown verbatim from discovery — the short
// 12-character form with a truncation marker appears, no full
// 64-character identifier is introduced by rendering, and the
// doctor --json structure (top-level key set) is unchanged.
func TestDoctorDockerIDShortFormStructureStable(t *testing.T) {
	short := strings.Repeat("a", 12) + "…"
	full := strings.Repeat("a", 64)
	r := healthyResult()
	r.Unknowns = []discovery.Observation{{
		Code: "DOCKER_ATTACHMENT_ID_NOT_IN_INVENTORY", Component: "docker",
		Message: `network "awgnet": attached container ` + short + ` is absent from the container listing`,
	}}
	rep := FromDiscovery(r)
	human := Render(rep)
	if !strings.Contains(human, short) {
		t.Fatalf("human output must carry the short container form: %q", human)
	}
	if strings.Contains(human, full) {
		t.Fatalf("a full 64-character identifier must never appear in human output")
	}
	blob, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(blob, &keys); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"checks", "discovery_status", "discovery_version", "generated_at", "host", "status", "unknowns"}
	if len(keys) != len(want) {
		t.Fatalf("doctor --json top-level key set changed: got %d keys", len(keys))
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			t.Fatalf("doctor --json key %q missing (structure contract)", k)
		}
	}
	if !strings.Contains(string(blob), short) {
		t.Fatalf("json unknowns must carry the short container form: %s", blob)
	}
	if strings.Contains(string(blob), full) {
		t.Fatalf("a full 64-character identifier must never appear in doctor --json")
	}
}
