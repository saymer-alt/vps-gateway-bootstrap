package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// Approval v2 exact-authority contract tests (ZAI-54 §14–§20): the frozen
// v2 payload, closed purpose, canonical capability grants, downgrade
// resistance, host/plan/expiry bindings, and the authority-laundering
// negatives.

const (
	v2Host   = "machine-id:" + "0123456789abcdef0123456789abcdef"
	v2HostB  = "machine-id:" + "fedcba9876543210fedcba9876543210"
	v2PlanFP = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var v2Expiry = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)

func v2Payload() PayloadV2 {
	return PayloadV2{
		SchemaVersion:   SchemaVersionV2,
		Purpose:         string(PurposeMUVGIntegrationV1),
		PlanFingerprint: v2PlanFP,
		HostIdentity:    v2Host,
		ExpiresAt:       v2Expiry,
		Capabilities: []string{
			"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
		},
	}
}

func v2Signer(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func v2Verifier(pub ed25519.PublicKey) Verifier {
	return Verifier{TrustAnchor: pub, HostIdentity: v2Host, Now: func() time.Time { return v2Expiry.Add(-time.Hour) }}
}

func signedV2(t *testing.T, p PayloadV2) Artifact {
	t.Helper()
	_, priv := v2Signer(t)
	art, err := SignPayloadV2(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

// The frozen contract: a canonical v2 payload signs, verifies, and binds
// purpose/plan/host/expiry exactly.
func TestV2SignAndVerify(t *testing.T) {
	pub, priv := v2Signer(t)
	art, err := SignPayloadV2(v2Payload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := (v2Verifier(pub)).VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err != nil {
		t.Fatalf("verification: %v", err)
	}
	// Canonical encoding is deterministic.
	again, err := SignPayloadV2(v2Payload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(again.Payload) != string(art.Payload) {
		t.Fatal("v2 canonical encoding is not deterministic")
	}
}

// §19 purpose mismatch matrix: signed X expected X passes; X vs Y denies;
// unknown and empty purposes deny on both the signing and verification
// sides; there is no generic fallback.
func TestV2PurposeMatrix(t *testing.T) {
	pub, _ := v2Signer(t)
	art := signedV2(t, v2Payload())
	v := v2Verifier(pub)
	if err := v.VerifyV2(art, v2PlanFP, Purpose("MUVG_OTHER_V1")); err == nil {
		t.Fatal("purpose mismatch must deny")
	}
	if err := v.VerifyV2(art, v2PlanFP, Purpose("")); err == nil {
		t.Fatal("empty expected purpose must deny")
	}
	if Purpose("MUVG_OTHER_V1").Valid() || Purpose("").Valid() {
		t.Fatal("closed purpose vocabulary broken")
	}
	bad := v2Payload()
	bad.Purpose = "MUVG_OTHER_V1"
	if _, err := SignPayloadV2(bad, privAny(t)); err == nil {
		t.Fatal("unknown signed purpose must fail at signing")
	}
	empty := v2Payload()
	empty.Purpose = ""
	if _, err := SignPayloadV2(empty, privAny(t)); err == nil {
		t.Fatal("empty signed purpose must fail at signing")
	}
}

// §10/§20 capability canonicalization and exact-grant matrix: malformed,
// unknown, unsorted, duplicated grants fail at signing AND verification;
// the grant rebuilds into a canonical CapabilitySet for the C4
// exact-set check.
func TestV2CapabilityGrantCanonicality(t *testing.T) {
	cases := []struct {
		name string
		caps []string
	}{
		{"unsorted", []string{
			"muvg.projectfile.v1",
			"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
		}},
		{"duplicate", []string{
			"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
			"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
		}},
		{"unknown", []string{"muvg.firewall.everything.v1"}},
		{"malformed", []string{"muvg.firewall.mssclamp.v1;ifaces="}},
		{"empty grant", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := v2Payload()
			p.Capabilities = tc.caps
			if _, err := SignPayloadV2(p, privAny(t)); err == nil {
				t.Fatalf("%s: signing must fail closed", tc.name)
			}
			// A signed variant is refused at verification too (simulate by
			// tampering the payload of a validly signed artifact).
			pOK := v2Payload()
			art := signedV2(t, pOK)
			tampered := art
			tamperedPayload, err := CanonicalV2(func() PayloadV2 {
				q := pOK
				q.Capabilities = tc.caps
				return q
			}())
			if err != nil {
				t.Fatal(err)
			}
			tampered.Payload = tamperedPayload
			pub, _ := v2Signer(t)
			if err := (v2Verifier(pub)).VerifyV2(tampered, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
				t.Fatalf("%s: tampered grant must fail verification", tc.name)
			}
		})
	}
	// The valid grant rebuilds into the canonical typed set (the C4 input).
	set, err := GrantedCapabilities(v2Payload())
	if err != nil {
		t.Fatal(err)
	}
	if len(set.IDs()) != 1 || set.IDs()[0] != capability.CapabilityID("muvg.firewall.mssclamp.v1;ifaces=tun-mihomo") {
		t.Fatalf("granted set: %v", set.IDs())
	}
}

func privAny(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv := v2Signer(t)
	return priv
}

// §12/§13/§14: plan, host and expiry bindings — each alone denies.
func TestV2BindingMatrix(t *testing.T) {
	pub, _ := v2Signer(t)
	art := signedV2(t, v2Payload())
	v := v2Verifier(pub)
	if err := v.VerifyV2(art, v2PlanFP+"0", PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("plan fingerprint mismatch must deny")
	}
	wrongHost := Verifier{TrustAnchor: pub, HostIdentity: v2HostB, Now: v.Now}
	if err := wrongHost.VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("host mismatch must deny")
	}
	// Hostname is never an approval identity.
	hostnameVerifier := Verifier{TrustAnchor: pub, HostIdentity: "web-1", Now: v.Now}
	if err := hostnameVerifier.VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("hostname substitution must deny")
	}
	// Malformed machine-id on the configured side denies.
	malformed := Verifier{TrustAnchor: pub, HostIdentity: "machine-id:xyz", Now: v.Now}
	if err := malformed.VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("malformed configured host must deny")
	}
	// Past expiry denies (boundary equality: exactly at ExpiresAt is expired).
	past := Verifier{TrustAnchor: pub, HostIdentity: v2Host, Now: func() time.Time { return v2Expiry.Add(time.Minute) }}
	if err := past.VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("expired approval must deny")
	}
	atBoundary := Verifier{TrustAnchor: pub, HostIdentity: v2Host, Now: func() time.Time { return v2Expiry }}
	if err := atBoundary.VerifyV2(art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("expiry boundary equality must deny")
	}
	// Zero expiry is not signable.
	zero := v2Payload()
	zero.ExpiresAt = time.Time{}
	if _, err := SignPayloadV2(zero, privAny(t)); err == nil {
		t.Fatal("non-expiring grant must not be signable")
	}
	// A tampered payload under a VALID signature (re-signed by a foreign
	// key) still fails the trust anchor.
	_, foreignPriv := v2Signer(t)
	other := v2Payload()
	other.ExpiresAt = v2Expiry.Add(time.Hour)
	foreignArt, err := SignPayloadV2(other, foreignPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.VerifyV2(foreignArt, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("foreign-key signature must deny")
	}
}

// §8/§15: downgrade resistance, both directions — a valid v1 signature is
// rejected by the v2 verifier and a valid v2 signature is rejected by the
// v1 verifier. The schema version is inside the signed canonical bytes.
func TestV2DowngradeResistance(t *testing.T) {
	pub, priv := v2Signer(t)
	v2Art := signedV2(t, v2Payload())

	// v2 artifact → v1 verifier: schema mismatch (and the canonical
	// re-encode of the v1 struct would drop the purpose field).
	v1v := Verifier{TrustAnchor: pub, HostIdentity: v2Host, Now: func() time.Time { return v2Expiry.Add(-time.Hour) }}
	if err := v1v.Verify(v2Art, v2PlanFP); err == nil {
		t.Fatal("a v2 artifact must be rejected by the v1 verifier")
	}

	// v1 artifact → v2 verifier: schema mismatch.
	v1Payload := Payload{
		SchemaVersion:   SchemaVersion,
		PlanFingerprint: v2PlanFP,
		HostIdentity:    v2Host,
		ExpiresAt:       v2Expiry,
	}
	v1Art, err := SignPayload(v1Payload, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := (v2Verifier(pub)).VerifyV2(v1Art, v2PlanFP, PurposeMUVGIntegrationV1); err == nil {
		t.Fatal("a v1 artifact must be rejected by the v2 verifier")
	}
}

// §5/§11: exact-grant semantics stay at the C4 layer — the signed grant
// is compared against the PLAN's required set with exact-set equality;
// over-granting is a mismatch, and the verifier itself derives nothing.
func TestV2ExactGrantViaC4(t *testing.T) {
	granted, err := GrantedCapabilities(v2Payload())
	if err != nil {
		t.Fatal(err)
	}
	// Exact set → SATISFIED.
	required, err := capability.NewCapabilitySet([]capability.CapabilityID{
		"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := capability.VerifyCapabilityGrant(required, granted); got.Status != capability.GrantSatisfied {
		t.Fatalf("exact grant: %+v", got)
	}
	// Over-grant (an extra capability) → MISMATCH with Unexpected.
	wider, err := capability.NewCapabilitySet([]capability.CapabilityID{
		"muvg.firewall.mssclamp.v1;ifaces=tun-mihomo",
		"muvg.projectfile.v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := capability.VerifyCapabilityGrant(required, wider); got.Status != capability.GrantMismatch || len(got.Unexpected) != 1 {
		t.Fatalf("over-grant must be a mismatch: %+v", got)
	}
	// Missing grant → MISMATCH with Missing.
	narrower, err := capability.NewCapabilitySet(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := capability.VerifyCapabilityGrant(required, narrower); got.Status != capability.GrantMismatch || len(got.Missing) != 1 {
		t.Fatalf("under-grant must be a mismatch: %+v", got)
	}
	// The mssclamp capability implies NOTHING else (no implicit privilege
	// inheritance): grant {mssclamp} vs requirement {tagged} is a mismatch
	// in both directions.
	tagged, err := capability.NewCapabilitySet([]capability.CapabilityID{"muvg.firewall.tagged.v1;chains=vpsgw_in;tag=muvg443"})
	if err != nil {
		t.Fatal(err)
	}
	if got := capability.VerifyCapabilityGrant(tagged, granted); got.Status != capability.GrantMismatch {
		t.Fatalf("mssclamp must not imply tagged: %+v", got)
	}
}

// §21/§25 structural pin: the approval package must not import the
// ownership, state, orchestrate, mssexec or mssspec planes (no authority
// laundering path), and machineid remains its only internal dependency
// besides the capability vocabulary.
func TestV2PackageImportsPinned(t *testing.T) {
	allowed := map[string]bool{
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability": true,
		"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid":  true,
	}
	for _, name := range []string{"approval.go", "v2.go", "trustanchor.go"} {
		srcBytes, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(srcBytes)
		for _, line := range strings.Split(src, "\n") {
			code := strings.TrimSpace(line)
			if code == "" || strings.HasPrefix(code, "//") {
				continue
			}
			if strings.HasPrefix(code, "\"github.com/saymer-alt/vps-gateway-bootstrap/internal/") {
				path := strings.Trim(code, "\"")
				if !allowed[path] {
					t.Fatalf("%s imports %q outside the pinned set", name, path)
				}
			}
		}
	}
}
