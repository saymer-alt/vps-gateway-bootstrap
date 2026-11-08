package serviceadoption

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerplan"
)

const testHost = "machine-id:1111222233334444aaaabbbbccccdddd"

func testStatement(now time.Time) Statement {
	return Statement{
		SchemaVersion: SchemaVersion,
		Purpose: Purpose,
		Resource: PinnedResource,
		Unit: PinnedUnit,
		HostIdentity: testHost,
		IssuedAt: now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
}

func signedStatement(t *testing.T, s Statement, key ed25519.PrivateKey) approval.Artifact {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil { t.Fatal(err) }
	return approval.Artifact{Payload:b, Signature:ed25519.Sign(key,b)}
}

func signRaw(t *testing.T, b []byte, key ed25519.PrivateKey) approval.Artifact {
	t.Helper()
	return approval.Artifact{Payload:b, Signature:ed25519.Sign(key,b)}
}

func TestSignedAdoptionStatementIsReviewOnlyNotStage3Admission(t *testing.T) {
	now := time.Date(2030,1,2,12,0,0,0,time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42},ed25519.SeedSize))
	a := signedStatement(t,testStatement(now),key)
	got,err := VerifyForReview(a,key.Public().(ed25519.PublicKey),testHost,now)
	if err != nil || got.Resource != PinnedResource || got.Purpose != Purpose {
		t.Fatalf("synthetic signed operator intent must be reviewable: %+v %v",got,err)
	}
	// A successfully signed adoption INTENT is not a trusted journal,
	// independently observed owner or authorization to execute.
	c := brokerplan.Candidate{Fingerprint:"synthetic-fingerprint",HostIdentity:testHost}
	if c.Snapshot().Ready {
		t.Fatal("service adoption statement silently elevated broker plan to Ready")
	}
}

func TestSignedAdoptionStatementScopeAndValidityNegativeMatrix(t *testing.T) {
	now := time.Date(2030,1,2,12,0,0,0,time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43},ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	tests := []struct{
		name string
		change func(*Statement)
	}{
		{"wrong version",func(s *Statement){s.SchemaVersion=2}},
		{"restart-purpose cannot adopt",func(s *Statement){s.Purpose=string(approval.PurposeServiceExperimentV1)}},
		{"empty purpose",func(s *Statement){s.Purpose=""}},
		{"other resource",func(s *Statement){s.Resource="service.sshd.service"}},
		{"other unit",func(s *Statement){s.Unit="sshd.service"}},
		{"empty unit",func(s *Statement){s.Unit=""}},
		{"other host",func(s *Statement){s.HostIdentity="machine-id:0000222233334444aaaabbbbccccdddd"}},
		{"hostname not machine-id",func(s *Statement){s.HostIdentity="vps.example"}},
		{"zero issue time",func(s *Statement){s.IssuedAt=time.Time{}}},
		{"zero expiry",func(s *Statement){s.ExpiresAt=time.Time{}}},
		{"expired",func(s *Statement){s.ExpiresAt=now.Add(-time.Second)}},
		{"issued in future",func(s *Statement){s.IssuedAt=now.Add(time.Minute);s.ExpiresAt=now.Add(time.Hour)}},
		{"inverted validity",func(s *Statement){s.IssuedAt=now;s.ExpiresAt=now}},
		{"excessive 25h window",func(s *Statement){s.IssuedAt=now.Add(-time.Minute);s.ExpiresAt=now.Add(25*time.Hour)}},
	}
	for _,tc := range tests {
		t.Run(tc.name,func(t *testing.T){
			s := testStatement(now);tc.change(&s)
			a := signedStatement(t,s,key)
			got,err := VerifyForReview(a,pub,testHost,now)
			if err==nil || got != (Statement{}) {
				t.Fatalf("unsafe signed statement accepted: %+v, %v",got,err)
			}
		})
	}
}

func TestAdoptionStatementSignatureAndCanonicalityNegativeMatrix(t *testing.T) {
	now := time.Date(2030,1,2,12,0,0,0,time.UTC)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44},ed25519.SeedSize))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45},ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	good := signedStatement(t,testStatement(now),key)
	checkDenied := func(t *testing.T,a approval.Artifact,anchor ed25519.PublicKey,host string,clock time.Time) {
		t.Helper()
		got,err := VerifyForReview(a,anchor,host,clock)
		if err==nil || got!=(Statement{}) {t.Fatalf("review allowed: %+v err %v",got,err)}
	}
	t.Run("bad signature",func(t *testing.T){
		a:=good;a.Signature=append([]byte(nil),good.Signature...);a.Signature[0]^=0x01
		checkDenied(t,a,pub,testHost,now)
	})
	t.Run("unsigned",func(t *testing.T){checkDenied(t,approval.Artifact{Payload:good.Payload},pub,testHost,now)})
	t.Run("untrusted signing key",func(t *testing.T){checkDenied(t,good,other.Public().(ed25519.PublicKey),testHost,now)})
	t.Run("missing trust anchor",func(t *testing.T){checkDenied(t,good,nil,testHost,now)})
	t.Run("missing time",func(t *testing.T){checkDenied(t,good,pub,testHost,time.Time{})})
	t.Run("invalid host source",func(t *testing.T){checkDenied(t,good,pub,"hostname.example",now)})
	t.Run("noncanonical expected host",func(t *testing.T){checkDenied(t,good,pub,strings.ToUpper(testHost),now)})
	t.Run("wrong expected host",func(t *testing.T){checkDenied(t,good,pub,"machine-id:0000222233334444aaaabbbbccccdddd",now)})
	t.Run("trailing JSON",func(t *testing.T){checkDenied(t,signRaw(t,append(append([]byte(nil),good.Payload...),[]byte(" {}")...),key),pub,testHost,now)})
	t.Run("unknown field",func(t *testing.T){
		b:=bytes.Replace(good.Payload,[]byte(`,"expires_at":`),[]byte(`,"agent_owned":true,"expires_at":`),1)
		checkDenied(t,signRaw(t,b,key),pub,testHost,now)
	})
	t.Run("duplicate field",func(t *testing.T){
		b:=bytes.Replace(good.Payload,[]byte(`,"resource":`),[]byte(`,"purpose":"`+Purpose+`","resource":`),1)
		checkDenied(t,signRaw(t,b,key),pub,testHost,now)
	})
	t.Run("noncanonical whitespace",func(t *testing.T){
		b:=append([]byte(" "),good.Payload...)
		checkDenied(t,signRaw(t,b,key),pub,testHost,now)
	})
	t.Run("oversized payload",func(t *testing.T){
		b:=append(append([]byte(nil),good.Payload...),bytes.Repeat([]byte(" "),MaxPayloadBytes)...)
		checkDenied(t,signRaw(t,b,key),pub,testHost,now)
	})
	t.Run("signed restart approval v2 is not adoption",func(t *testing.T){
		restart,err:=approval.SignPayloadV2(approval.PayloadV2{
			SchemaVersion:approval.SchemaVersionV2,
			Purpose:string(approval.PurposeServiceExperimentV1),
			PlanFingerprint:"synthetic-fingerprint",HostIdentity:testHost,
			ExpiresAt:now.Add(time.Hour),
			Capabilities:[]string{"muvg.service.restart.v1;unit=fail2ban.service"},
		},key)
		if err!=nil {t.Fatal(err)}
		checkDenied(t,restart,pub,testHost,now)
	})
}
