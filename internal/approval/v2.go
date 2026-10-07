// Signed approval v2 — the EXACT AUTHORITY contract (ZAI-54, PATH A):
// the generalized signed approval that grants exactly the intended
// operation class (purpose), plan, capabilities, host and validity window
// — with production mutation authority unchanged (no wiring, no executor,
// no enablement; the v1 contract remains the legacy authority domain).
//
// v1 → v2 delta, derived from the architecture (§4/§6/§7):
//
//   - Purpose (NEW, signed): a CLOSED authority-domain vocabulary. The
//     signature grants authority for one operation class only; an
//     artifact issued for one domain is never interpretable in another.
//     v1 had no purpose — any signed v1 artifact was interpretable by any
//     v1 consumer regardless of the signer's intent. The initial
//     vocabulary contains exactly one value justified by current
//     architecture: MUVG_INTEGRATION_V1, the authority domain of the
//     entire compiled muvg.* capability vocabulary (projectfile, sysctl,
//     routing, firewall-tagged, firewall-mssclamp). Unknown or empty
//     purposes DENY; extending the enum is a deliberate code change.
//   - Capabilities (NOW canonical at the payload boundary): v1 carried
//     capabilities as inert signed strings; v2 requires a canonical grant
//     at signing AND verification — non-empty, every member a valid
//     canonical capability, strictly ascending order, no duplicates. The
//     AUTHORITY semantics stay at the plan layer: the typed Plan derives
//     its required set, the signed artifact carries the granted set, and
//     capability.VerifyCapabilityGrant (C4) enforces EXACT-SET equality —
//     required ⊆ signed and signed ⊆ required are both mismatches
//     (over-granting is itself an authorization mismatch). This verifier
//     does not derive or compare requirement sets.
//   - Replay semantics (§7, NOT changed): purpose + plan fingerprint +
//     host + expiry form the authority coordinate; an approval for
//     coordinate A is not reinterpretable as coordinate B. Same-approval
//     replay within TTL remains allowed — that is still the repository
//     policy; no single-use state, replay database or nonce was invented.
//     A transaction/nonce binding is recorded as a future schema
//     prerequisite if the owner requires single-use semantics.
//
// Schema/domain separation (§8/§15): v1 and v2 are separate verifier
// entry points — the caller chooses which authority schema it expects,
// and no verifier accepts both. The schema version is inside the signed
// canonical bytes, and the canonical re-encode check rejects any field-set
// reinterpretation: a v2 payload parsed as v1 loses the purpose field and
// fails the canonical comparison; a v1 payload fails the v2 schema check.
//
// Everything else is inherited unchanged from v1 (§12/§13/§14): exact
// PlanFingerprint binding (whole-plan approval), canonical machine-id
// HostIdentity binding (hostname never an identity), signed expiry.
//
// Trust model unchanged: the operator's private key never appears in any
// verification path and never on the VPS; SignPayloadV2 exists for
// offline workstation tooling and tests; no production command signs
// approvals. G4 remains OPEN until the operator provisions a real trust
// anchor.
package approval

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// SchemaVersionV2 is the approval payload schema version this file
// implements. It is inside the signed canonical bytes, so v1 and v2
// artifacts are cryptographically distinguishable.
const SchemaVersionV2 = 2

// Purpose is the closed authority-domain vocabulary (§6): the signed
// answer to "what class of authorization is this signature granting?".
type Purpose string

// PurposeMUVGIntegrationV1 is the authority domain of the compiled
// muvg.* capability vocabulary — the only operation class currently
// modeled by the repository (project files, sysctl, routing, tagged
// firewall rules, the MSS clamp).
const PurposeMUVGIntegrationV1 Purpose = "MUVG_INTEGRATION_V1"

// Valid reports whether p is a member of the closed purpose vocabulary.
// Empty and unknown purposes DENY (§6/§19); there is no generic fallback.
func (p Purpose) Valid() bool {
	switch p {
	case PurposeMUVGIntegrationV1:
		return true
	}
	return false
}

// PayloadV2 is the canonical, signed content of an approval v2: the same
// binding set as v1 plus the authority-domain purpose. The signed bytes
// are the deterministic JSON encoding of this struct — fixed field order,
// no maps, no optional fields (an empty grant is a signing error, never
// an omission).
type PayloadV2 struct {
	SchemaVersion   int       `json:"schema_version"`
	Purpose         string    `json:"purpose"`
	PlanFingerprint string    `json:"plan_fingerprint"`
	HostIdentity    string    `json:"host_identity"`
	ExpiresAt       time.Time `json:"expires_at"`
	Capabilities    []string  `json:"capabilities"`
}

// CanonicalV2 returns the deterministic serialization of a v2 payload —
// the only bytes this package signs or verifies for v2.
func CanonicalV2(p PayloadV2) ([]byte, error) {
	return json.Marshal(p)
}

// validateV2 is the shared structural gate for signing and verification:
// schema, closed purpose, non-empty plan fingerprint, canonical host
// identity, non-zero expiry, and a CANONICAL capability grant (non-empty;
// every member a valid canonical capability; strictly ascending order —
// unsorted or duplicated grants are rejected, never normalized into
// acceptance).
func validateV2(p PayloadV2) error {
	if p.SchemaVersion != SchemaVersionV2 {
		return fmt.Errorf("approval payload schema version %d is unsupported (want %d)", p.SchemaVersion, SchemaVersionV2)
	}
	if !Purpose(p.Purpose).Valid() {
		return fmt.Errorf("approval purpose %q is not in the closed authority vocabulary", p.Purpose)
	}
	if strings.TrimSpace(p.PlanFingerprint) == "" {
		return errors.New("approval does not bind a plan fingerprint")
	}
	if _, err := parseHostIdentity(p.HostIdentity); err != nil {
		return fmt.Errorf("approval host identity: %w", err)
	}
	if p.ExpiresAt.IsZero() {
		return errors.New("approval has no expiry (a non-expiring grant is not signable)")
	}
	if len(p.Capabilities) == 0 {
		return errors.New("approval grants no capabilities (an empty grant is not signable)")
	}
	for i, c := range p.Capabilities {
		if _, err := capability.ParseCapability(c); err != nil {
			return fmt.Errorf("approval capability %d: %w", i, err)
		}
		if i > 0 && p.Capabilities[i-1] >= c {
			return fmt.Errorf("approval capabilities must be strictly ascending with no duplicates (position %d: %q after %q)", i, c, p.Capabilities[i-1])
		}
	}
	return nil
}

// SignPayloadV2 produces a signed v2 Artifact. The payload is validated
// in full BEFORE any bytes are signed — operator tooling can never sign a
// noncanonical grant, an unknown purpose, or an unbound host. The key
// belongs to offline workstation tooling; nothing on the VPS signs
// approvals.
func SignPayloadV2(p PayloadV2, priv ed25519.PrivateKey) (Artifact, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Artifact{}, errors.New("invalid ed25519 private key")
	}
	if err := validateV2(p); err != nil {
		return Artifact{}, err
	}
	b, err := CanonicalV2(p)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{Payload: b, Signature: ed25519.Sign(priv, b)}, nil
}

// VerifyV2 verifies one v2 artifact against the pinned trust anchor, the
// expected target host, the exact plan fingerprint, and the CALLER'S
// expected authority purpose (§8: the caller chooses which authority
// schema and domain it expects; a v2-required caller presented with a v1
// artifact fails the schema check, and a purpose mismatch fails the
// binding check).
//
// Capability authority is deliberately NOT decided here (§11): this
// function validates that the signed grant is structurally canonical; the
// EXACT-SET match between the typed Plan's required capabilities and the
// signed grant belongs to capability.VerifyCapabilityGrant at the layer
// that holds both sets.
func (v Verifier) VerifyV2(a Artifact, planFingerprint string, purpose Purpose) error {
	if len(v.TrustAnchor) != ed25519.PublicKeySize {
		return errors.New("trust anchor is not a valid ed25519 public key")
	}
	if v.HostIdentity == "" {
		return errors.New("host identity is not configured: target-host binding requires the machine-id namespace (machine-id:<value>)")
	}
	wantHost, err := parseHostIdentity(v.HostIdentity)
	if err != nil {
		return fmt.Errorf("configured host identity is invalid: %w", err)
	}
	if !purpose.Valid() {
		return fmt.Errorf("expected purpose %q is not in the closed authority vocabulary", purpose)
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return errors.New("approval signature has wrong size")
	}
	if !ed25519.Verify(v.TrustAnchor, a.Payload, a.Signature) {
		return errors.New("approval signature is invalid for the pinned trust anchor")
	}
	var p PayloadV2
	if err := json.Unmarshal(a.Payload, &p); err != nil {
		return fmt.Errorf("approval payload is not valid JSON: %w", err)
	}
	again, err := CanonicalV2(p)
	if err != nil || string(again) != string(a.Payload) {
		return errors.New("approval payload is not in canonical form")
	}
	if err := validateV2(p); err != nil {
		return fmt.Errorf("approval payload is invalid: %w", err)
	}
	if Purpose(p.Purpose) != purpose {
		return fmt.Errorf("approval grants purpose %q, want %q", p.Purpose, purpose)
	}
	if p.PlanFingerprint != planFingerprint {
		return errors.New("approval does not bind this plan fingerprint")
	}
	gotHost, err := parseHostIdentity(p.HostIdentity)
	if err != nil {
		return fmt.Errorf("approval host identity is invalid: %w", err)
	}
	if gotHost != wantHost {
		return errors.New("approval binds a different host identity")
	}
	if !v.now().Before(p.ExpiresAt) {
		return errors.New("approval has expired")
	}
	return nil
}

// GrantedCapabilities returns the signed grant as a canonical capability
// set — the typed input for capability.VerifyCapabilityGrant at the plan
// layer. The set is rebuilt through NewCapabilitySet, so any signature-
// level canonicality gap fails closed here as well.
func GrantedCapabilities(p PayloadV2) (capability.CapabilitySet, error) {
	ids := make([]capability.CapabilityID, 0, len(p.Capabilities))
	for i, c := range p.Capabilities {
		id, err := capability.ParseCapability(c)
		if err != nil {
			return capability.CapabilitySet{}, fmt.Errorf("approval capability %d: %w", i, err)
		}
		ids = append(ids, id)
	}
	return capability.NewCapabilitySet(ids)
}
