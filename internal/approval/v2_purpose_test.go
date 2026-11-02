package approval

// The closed purpose vocabulary separates authority domains (ZAI-132):
// the service-restart class and the muvg.* integration class are distinct
// purposes, and an artifact issued for one is never interpretable in the
// other (docs/security-model.md §6).

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

func TestPurposesAreDistinctAndClosed(t *testing.T) {
	if PurposeMUVGIntegrationV1 == PurposeServiceExperimentV1 {
		t.Fatal("the service and integration authority domains must be distinct purposes")
	}
	if !PurposeMUVGIntegrationV1.Valid() || !PurposeServiceExperimentV1.Valid() {
		t.Fatal("both documented purposes must be valid")
	}
	for _, p := range []Purpose{"", "MUVG_INTEGRATION_V2", "SERVICE", "service_experiment_v1"} {
		if p.Valid() {
			t.Fatalf("purpose %q must be denied", p)
		}
	}
}

// A v2 artifact bound to the service-experiment purpose verifies under that
// purpose and is refused under the integration purpose — the domain split
// is enforced at verification, not merely documented.
func TestV2PurposeBindingSplitsDomains(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{TrustAnchor: pub, HostIdentity: "machine-id:" + strings.Repeat("a", 32)}
	payload := PayloadV2{
		SchemaVersion:   SchemaVersionV2,
		Purpose:         string(PurposeServiceExperimentV1),
		PlanFingerprint: "fp-test",
		HostIdentity:    "machine-id:" + strings.Repeat("a", 32),
		ExpiresAt:       time.Now().Add(time.Hour).UTC(),
		Capabilities:    []string{"muvg.service.restart.v1;unit=fail2ban.service"},
	}
	art, err := SignPayloadV2(payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyV2(art, "fp-test", PurposeServiceExperimentV1); err != nil {
		t.Fatalf("the artifact must verify under its own purpose: %v", err)
	}
	if err := v.VerifyV2(art, "fp-test", PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("an artifact issued for the service domain must be refused under the integration purpose")
	}
	// The granted capabilities reconstruct canonically for the C4 layer.
	grant, err := GrantedCapabilities(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(grant.IDs()) != 1 || grant.IDs()[0] != capability.CapabilityID("muvg.service.restart.v1;unit=fail2ban.service") {
		t.Fatalf("unexpected granted set: %v", grant.IDs())
	}
}
