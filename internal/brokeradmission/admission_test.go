package brokeradmission

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
)

const (
	syntheticFingerprint = "synthetic-plan-fingerprint-not-from-agent"
	syntheticHost = "machine-id:1111222233334444aaaabbbbccccdddd"
	pinnedGrant = "muvg.service.restart.v1;unit=fail2ban.service"
)

func signer(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func verifierFor(priv ed25519.PrivateKey) approval.Verifier {
	return approval.Verifier{
		TrustAnchor: priv.Public().(ed25519.PublicKey),
		HostIdentity: syntheticHost,
		Now: func() time.Time { return time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC) },
	}
}

func validPayload() approval.PayloadV2 {
	return approval.PayloadV2{
		SchemaVersion: approval.SchemaVersionV2,
		Purpose: string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: syntheticFingerprint,
		HostIdentity: syntheticHost,
		ExpiresAt: time.Date(2031, 1, 1, 12, 0, 0, 0, time.UTC),
		Capabilities: []string{pinnedGrant},
	}
}

func requestFromArtifact(t *testing.T, a approval.Artifact) []byte {
	t.Helper()
	wire, err := json.Marshal(brokerproto.Request{
		SchemaVersion: brokerproto.Version,
		Operation: brokerproto.RestartPinnedFail2ban,
		Payload: a.Payload,
		Signature: a.Signature,
	})
	if err != nil { t.Fatal(err) }
	return wire
}

func signedWire(t *testing.T, p approval.PayloadV2, key ed25519.PrivateKey) []byte {
	t.Helper()
	art, err := approval.SignPayloadV2(p, key)
	if err != nil { t.Fatal(err) }
	return requestFromArtifact(t, art)
}

func TestP1BValidV2IsVerifiedButNeverExecutes(t *testing.T) {
	key := signer(0x42)
	wire := signedWire(t, validPayload(), key)
	if err := VerifyPinnedRestartRequest(wire, verifierFor(key), syntheticFingerprint); err != nil {
		t.Fatalf("valid synthetic signed request rejected: %v", err)
	}
	// This package has no executor, daemon, Unix socket, journal or calls to
	// anything with root. The only positive result is a nil check error.
}

func TestP1BNoAuthorityFromBadSignedInput(t *testing.T) {
	owner := signer(0x42)
	v := verifierFor(owner)
	valid := validPayload()
	originalWire := signedWire(t, valid, owner)

	alterPayload := func(change func(*approval.PayloadV2), key ed25519.PrivateKey) []byte {
		t.Helper()
		p := valid
		p.Capabilities = append([]string(nil), valid.Capabilities...)
		change(&p)
		return signedWire(t, p, key)
	}
	alterArtifact := func(change func(*approval.Artifact)) []byte {
		t.Helper()
		art, err := approval.SignPayloadV2(valid, owner)
		if err != nil { t.Fatal(err) }
		art.Payload = append([]byte(nil), art.Payload...)
		art.Signature = append([]byte(nil), art.Signature...)
		change(&art)
		return requestFromArtifact(t, art)
	}

	cases := []struct{
		name string
		wire []byte
		verifier approval.Verifier
		fp string
	}{
		{"empty request", nil, v, syntheticFingerprint},
		{"unknown operation", []byte(`{"schema_version":1,"operation":"service.ssh.restart.v1","approval_payload":"YQ==","approval_signature":"YQ=="}`), v, syntheticFingerprint},
		{"missing plan fingerprint", originalWire, v, ""},
		{"untrusted whitespace fingerprint", originalWire, v, "   "},
		{"wrong plan", originalWire, v, syntheticFingerprint+"-other"},
		{"wrong host", alterPayload(func(p *approval.PayloadV2){p.HostIdentity="machine-id:"+strings.Repeat("b",32)},owner), v, syntheticFingerprint},
		{"wrong verifier host", originalWire, approval.Verifier{TrustAnchor:v.TrustAnchor,HostIdentity:"machine-id:"+strings.Repeat("b",32),Now:v.Now},syntheticFingerprint},
		{"expired", alterPayload(func(p *approval.PayloadV2){p.ExpiresAt=time.Date(2029,1,1,0,0,0,0,time.UTC)},owner),v,syntheticFingerprint},
		{"wrong signer", signedWire(t, valid, signer(0x55)),v,syntheticFingerprint},
		{"wrong purpose", alterPayload(func(p *approval.PayloadV2){p.Purpose=string(approval.PurposeMUVGIntegrationV1)},owner),v,syntheticFingerprint},
		{"wrong unit grant", alterPayload(func(p *approval.PayloadV2){p.Capabilities=[]string{"muvg.service.restart.v1;unit=nginx.service"}},owner),v,syntheticFingerprint},
		{"integration-only grant", alterPayload(func(p *approval.PayloadV2){p.Capabilities=[]string{"muvg.projectfile.v1"}},owner),v,syntheticFingerprint},
		{"overgranted valid signature", alterPayload(func(p *approval.PayloadV2){p.Capabilities=[]string{"muvg.projectfile.v1",pinnedGrant}},owner),v,syntheticFingerprint},
		{"tampered signature", alterArtifact(func(a *approval.Artifact){a.Signature[0]^=0x01}),v,syntheticFingerprint},
		{"tampered signed payload", alterArtifact(func(a *approval.Artifact){a.Payload[4]^=0x01}),v,syntheticFingerprint},
		{"missing trust anchor", originalWire, approval.Verifier{HostIdentity:syntheticHost,Now:v.Now},syntheticFingerprint},
		{"unknown host identity", originalWire, approval.Verifier{TrustAnchor:v.TrustAnchor,Now:v.Now},syntheticFingerprint},
	}

	// A legacy v1 signature cannot be promoted into v2 authority.
	legacy, err := approval.SignPayload(approval.Payload{
		SchemaVersion: approval.SchemaVersion,PlanFingerprint:syntheticFingerprint,
		HostIdentity:syntheticHost,ExpiresAt:valid.ExpiresAt,
		Capabilities:[]string{pinnedGrant},
	}, owner)
	if err != nil { t.Fatal(err) }
	cases = append(cases, struct{name string;wire []byte;verifier approval.Verifier;fp string}{
		"v1-to-v2 downgrade",requestFromArtifact(t, legacy),v,syntheticFingerprint,
	})

	// A correctly signed BUT noncanonical/invalid grant must not survive
	// the v2 structural gate. This case bypasses SignPayloadV2 on purpose.
	nonCanonical := valid
	nonCanonical.Capabilities = []string{pinnedGrant,pinnedGrant}
	payloadBytes, err := json.Marshal(nonCanonical)
	if err != nil { t.Fatal(err) }
	badGrant := approval.Artifact{Payload:payloadBytes, Signature:ed25519.Sign(owner,payloadBytes)}
	cases = append(cases, struct{name string;wire []byte;verifier approval.Verifier;fp string}{
		"valid ed25519 signature over invalid grant",requestFromArtifact(t,badGrant),v,syntheticFingerprint,
	})

	// The synthetic executor is only a counter controlled by the test.
	// A wrong input must not even reach this fake dispatch point.
	invocations := 0
	for _, tc := range cases {
		t.Run(tc.name,func(t *testing.T) {
			if err := VerifyPinnedRestartRequest(tc.wire,tc.verifier,tc.fp); err == nil {
				invocations++
				t.Fatal("untrusted request passed signed authority gate")
			}
			if invocations!=0 {t.Fatal("fake executor called on invalid authority")}
		})
	}
	if invocations!=0 {t.Fatalf("unexpected fake invocations: %d",invocations)}
}

func TestP1BWireCannotSupplyTrustedPlanOrAnchor(t *testing.T) {
	key:=signer(0x42)
	wire:=signedWire(t,validPayload(),key)
	var extra map[string]any
	if err:=json.Unmarshal(wire,&extra);err!=nil {t.Fatal(err)}
	for _,field:=range []string{"plan_fingerprint","trust_anchor","caller_uid","command","unit","capabilities","purpose","execute"}{
		t.Run(field,func(t *testing.T){
			extra[field]="attacker-controlled"
			bad,err:=json.Marshal(extra)
			if err!=nil {t.Fatal(err)}
			if err:=VerifyPinnedRestartRequest(bad,verifierFor(key),syntheticFingerprint);err==nil {t.Fatal("wire accepted caller authority field")}
			delete(extra,field)
		})
	}
}
