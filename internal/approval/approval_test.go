package approval

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// Fixed test keys (not secrets): deterministic seeds so every assertion is
// reproducible. The operator's real key never appears anywhere in tests.
var (
	seedOperator = bytes.Repeat([]byte{0xAA}, 32)
	seedOther    = bytes.Repeat([]byte{0xBB}, 32)
)

func operatorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seedOperator) }
func otherKey() ed25519.PrivateKey    { return ed25519.NewKeyFromSeed(seedOther) }

// The canonical approval target identity: the namespaced machine-id form
// (synthetic test value, not a real machine).
const testHostIdentity = "machine-id:1111222233334444aaaabbbbccccdddd"

func verifierNow() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }

func newVerifier() Verifier {
	return Verifier{
		TrustAnchor:  operatorKey().Public().(ed25519.PublicKey),
		HostIdentity: testHostIdentity,
		Now:          verifierNow,
	}
}

func testPayload(fp string) Payload {
	return Payload{
		SchemaVersion:   SchemaVersion,
		PlanFingerprint: fp,
		HostIdentity:    testHostIdentity,
		ExpiresAt:       verifierNow().Add(30 * time.Minute),
	}
}

// The canonical encoding is deterministic and pinned: any accidental format
// drift must break this test, because the signed bytes are exactly these.
func TestCanonicalIsDeterministicAndPinned(t *testing.T) {
	p := testPayload("abc123")
	first, err := Canonical(p)
	if err != nil { t.Fatal(err) }
	second, err := Canonical(p)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(first, second) { t.Fatal("canonical form is not deterministic") }
	want := `{"schema_version":1,"plan_fingerprint":"abc123","host_identity":"machine-id:1111222233334444aaaabbbbccccdddd","expires_at":"2026-09-17T12:30:00Z"}`
	if string(first) != want { t.Fatalf("canonical form drifted:\n got %s\nwant %s", first, want) }
	withCaps, err := Canonical(Payload{SchemaVersion: 1, PlanFingerprint: "abc123", HostIdentity: testHostIdentity, ExpiresAt: verifierNow().Add(30 * time.Minute), Capabilities: []string{"service-lifecycle"}})
	if err != nil { t.Fatal(err) }
	wantCaps := `{"schema_version":1,"plan_fingerprint":"abc123","host_identity":"machine-id:1111222233334444aaaabbbbccccdddd","expires_at":"2026-09-17T12:30:00Z","capabilities":["service-lifecycle"]}`
	if string(withCaps) != wantCaps { t.Fatalf("canonical capabilities form drifted: %s", withCaps) }
}

func TestSignAndVerifyHappyPath(t *testing.T) {
	art, err := SignPayload(testPayload("abc123"), operatorKey())
	if err != nil { t.Fatal(err) }
	if err := newVerifier().Verify(art, "abc123"); err != nil { t.Fatalf("valid artifact rejected: %v", err) }
}

func TestVerifyRejectsUnsignedAndMalformed(t *testing.T) {
	v := newVerifier()
	b, _ := Canonical(testPayload("abc123"))
	if err := v.Verify(Artifact{Payload: b}, "abc123"); err == nil { t.Fatal("unsigned artifact accepted") }
	if err := v.Verify(Artifact{Payload: b, Signature: []byte{1, 2, 3}}, "abc123"); err == nil { t.Fatal("short signature accepted") }
	if err := v.Verify(Artifact{Payload: []byte("not json"), Signature: make([]byte, ed25519.SignatureSize)}, "abc123"); err == nil {
		t.Fatal("garbage payload accepted")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	art, err := SignPayload(testPayload("abc123"), otherKey())
	if err != nil { t.Fatal(err) }
	if err := newVerifier().Verify(art, "abc123"); err == nil { t.Fatal("artifact signed by a different key accepted") }
}

func TestVerifyRejectsModifiedPayload(t *testing.T) {
	art, err := SignPayload(testPayload("abc123"), operatorKey())
	if err != nil { t.Fatal(err) }
	tampered := Artifact{Payload: append([]byte(nil), art.Payload...), Signature: art.Signature}
	tampered.Payload[len(tampered.Payload)-2] = 'X'
	if err := newVerifier().Verify(tampered, "abc123"); err == nil { t.Fatal("modified payload accepted") }
}

func TestVerifyRejectsWrongFingerprint(t *testing.T) {
	art, _ := SignPayload(testPayload("abc123"), operatorKey())
	if err := newVerifier().Verify(art, "different-plan"); err == nil { t.Fatal("wrong-plan approval accepted") }
}

func TestVerifyRejectsWrongHost(t *testing.T) {
	art, _ := SignPayload(testPayload("abc123"), operatorKey())
	v := newVerifier()
	v.HostIdentity = "machine-id:5555666677778888aaaabbbbccccdddd"
	if err := v.Verify(art, "abc123"); err == nil { t.Fatal("wrong-host approval accepted") }
}

func TestVerifyRejectsExpired(t *testing.T) {
	expired := testPayload("abc123")
	expired.ExpiresAt = verifierNow().Add(-time.Minute)
	art, _ := SignPayload(expired, operatorKey())
	if err := newVerifier().Verify(art, "abc123"); err == nil { t.Fatal("expired approval accepted") }

	boundary := testPayload("abc123")
	boundary.ExpiresAt = verifierNow()
	art, _ = SignPayload(boundary, operatorKey())
	if err := newVerifier().Verify(art, "abc123"); err == nil { t.Fatal("approval valid exactly at expiry instant accepted") }
}

// Host binding has no decided identity source yet: without an
// operator-configured value, verification must fail closed rather than
// silently binding to a mutable hostname.
func TestVerifyRequiresConfiguredHostIdentity(t *testing.T) {
	art, _ := SignPayload(testPayload("abc123"), operatorKey())
	v := newVerifier()
	v.HostIdentity = ""
	err := v.Verify(art, "abc123")
	if err == nil { t.Fatal("verification without host identity accepted") }
	if !bytes.Contains([]byte(err.Error()), []byte("machine-id")) {
		t.Fatalf("error must name the machine-id requirement, got: %v", err)
	}
}

func TestVerifyRejectsBadTrustAnchor(t *testing.T) {
	art, _ := SignPayload(testPayload("abc123"), operatorKey())
	v := newVerifier()
	v.TrustAnchor = ed25519.PublicKey("too-short")
	if err := v.Verify(art, "abc123"); err == nil { t.Fatal("invalid trust anchor accepted") }
}

// A payload signed over non-canonical bytes must be rejected even though
// the signature itself is valid: this is what prevents ambiguous encodings
// (reordered fields, extra fields) from ever being interpreted.
func TestVerifyRejectsNonCanonicalPayload(t *testing.T) {
	reordered := `{"expires_at":"2026-09-17T12:30:00Z","host_identity":"machine-id:1111222233334444aaaabbbbccccdddd","plan_fingerprint":"abc123","schema_version":1}`
	art := Artifact{Payload: []byte(reordered), Signature: ed25519.Sign(operatorKey(), []byte(reordered))}
	if err := newVerifier().Verify(art, "abc123"); err == nil {
		t.Fatal("non-canonical but validly signed payload accepted")
	}
}

// Capabilities are part of the signed bytes: different capability sets
// produce different canonical payloads, and the verifier does not yet
// interpret them (reserved for the capability architecture).
func TestCapabilitiesAreBoundButNotInterpreted(t *testing.T) {
	withCaps := testPayload("abc123")
	withCaps.Capabilities = []string{"service-lifecycle"}
	a, _ := Canonical(testPayload("abc123"))
	b, _ := Canonical(withCaps)
	if bytes.Equal(a, b) { t.Fatal("capability set must change the canonical bytes") }

	art, _ := SignPayload(withCaps, operatorKey())
	if err := newVerifier().Verify(art, "abc123"); err != nil {
		t.Fatalf("reserved capability set must not break verification: %v", err)
	}
}

// The binding is on the machine-id namespace: a bare hostname — mutable,
// self-reported — must never be accepted on either side of the binding.
func TestVerifyRejectsHostnameAsHostIdentity(t *testing.T) {
	art, _ := SignPayload(testPayload("abc123"), operatorKey())

	v := newVerifier()
	v.HostIdentity = "saymer3" // bare hostname as the configured identity
	if err := v.Verify(art, "abc123"); err == nil {
		t.Fatal("bare hostname accepted as configured host identity")
	}

	// An artifact whose payload carries a hostname under an otherwise valid
	// signature must also be rejected (canonical-form holds, namespace does
	// not).
	hostPayload := testPayload("abc123")
	hostPayload.HostIdentity = "saymer3"
	hostArt := Artifact{Payload: mustCanonical(t, hostPayload), Signature: ed25519.Sign(operatorKey(), mustCanonical(t, hostPayload))}
	if err := newVerifier().Verify(hostArt, "abc123"); err == nil {
		t.Fatal("signed hostname identity accepted")
	}
}

// Machine-id values are compared in canonical (lowercased) form: an
// artifact signed over the uppercase spelling binds the same identity.
func TestVerifyCanonicalizesMachineIDCase(t *testing.T) {
	upper := testPayload("abc123")
	upper.HostIdentity = "machine-id:1111222233334444AAAABBBBCCCCDDDD"
	art := Artifact{Payload: mustCanonical(t, upper), Signature: ed25519.Sign(operatorKey(), mustCanonical(t, upper))}
	if err := newVerifier().Verify(art, "abc123"); err != nil {
		t.Fatalf("uppercase machine-id must canonicalize to the same identity: %v", err)
	}
}

// A malformed machine-id value inside the payload is rejected even under a
// valid signature.
func TestVerifyRejectsMalformedMachineIDInPayload(t *testing.T) {
	bad := testPayload("abc123")
	bad.HostIdentity = "machine-id:not-a-machine-id"
	art := Artifact{Payload: mustCanonical(t, bad), Signature: ed25519.Sign(operatorKey(), mustCanonical(t, bad))}
	if err := newVerifier().Verify(art, "abc123"); err == nil {
		t.Fatal("malformed machine-id identity accepted")
	}
}

func mustCanonical(t *testing.T, p Payload) []byte {
	t.Helper()
	b, err := Canonical(p)
	if err != nil { t.Fatal(err) }
	return b
}
