package brokergate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
)

const (
	testHost = "machine-id:1111222233334444aaaabbbbccccdddd"
	testPlan = "synthetic-trusted-plan-fingerprint"
	testGrant = "muvg.service.restart.v1;unit=fail2ban.service"
)

func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
}

func testVerifier() approval.Verifier {
	return approval.Verifier{
		TrustAnchor: testKey().Public().(ed25519.PublicKey),
		HostIdentity: testHost,
		Now: func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func testPayload() approval.PayloadV2 {
	return approval.PayloadV2{
		SchemaVersion: approval.SchemaVersionV2,
		Purpose: string(approval.PurposeServiceExperimentV1),
		PlanFingerprint: testPlan,
		HostIdentity: testHost,
		ExpiresAt: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		Capabilities: []string{testGrant},
	}
}

func testWire(t *testing.T, p approval.PayloadV2) []byte {
	t.Helper()
	art, err := approval.SignPayloadV2(p, testKey())
	if err != nil { t.Fatal(err) }
	wire, err := json.Marshal(brokerproto.Request{
		SchemaVersion: brokerproto.Version,
		Operation: brokerproto.RestartPinnedFail2ban,
		Payload: art.Payload,
		Signature: art.Signature,
	})
	if err != nil { t.Fatal(err) }
	return wire
}

func testGate() Gate {
	return Gate{
		ExpectedAgentUID: 1001,
		ExpectedAgentGID: 1001,
		ReadPeer: func() (Peer,error) { return Peer{PID: 4242, UID: 1001, GID: 1001}, nil },
		ReadPlan: func() (PlanSnapshot,error) {
			return PlanSnapshot{
				Fingerprint: testPlan, HostIdentity: testHost,
				Unit: pinnedUnit, Ready: true,
			}, nil
		},
		ReadVerifier: func() (approval.Verifier,error) { return testVerifier(), nil },
	}
}

// A nil return is not permission to mutate: the package has no executor.
func TestCheckOnlySyntheticV2Preconditions(t *testing.T) {
	if err:=testGate().CheckOnly(testWire(t,testPayload()));err!=nil{
		t.Fatalf("synthetic preconditions rejected: %v",err)
	}
}

func TestFailClosedPeerAndTrustedPlan(t *testing.T) {
	wire:=testWire(t,testPayload())
	cases:=[]struct{name string; change func(*Gate)}{
		{"UID unset",func(g *Gate){g.ExpectedAgentUID=0}},
		{"GID unset",func(g *Gate){g.ExpectedAgentGID=0}},
		{"missing peer source",func(g *Gate){g.ReadPeer=nil}},
		{"missing plan source",func(g *Gate){g.ReadPlan=nil}},
		{"missing verifier source",func(g *Gate){g.ReadVerifier=nil}},
		{"peer lookup fails",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{},errors.New("no kernel peer")}}},
		{"PID absent",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{UID:1001,GID:1001},nil}}},
		{"root UID",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{PID:1,UID:0,GID:1001},nil}}},
		{"root GID",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{PID:1,UID:1001,GID:0},nil}}},
		{"wrong UID",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{PID:1,UID:1002,GID:1001},nil}}},
		{"wrong GID",func(g *Gate){g.ReadPeer=func()(Peer,error){return Peer{PID:1,UID:1001,GID:1002},nil}}},
		{"plan unavailable",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{},errors.New("discovery UNKNOWN")}}},
		{"not ready",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{Fingerprint:testPlan,HostIdentity:testHost,Unit:pinnedUnit},nil}}},
		{"foreign unit",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{Fingerprint:testPlan,HostIdentity:testHost,Unit:"sshd.service",Ready:true},nil}}},
		{"missing fingerprint",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{HostIdentity:testHost,Unit:pinnedUnit,Ready:true},nil}}},
		{"wrong fingerprint",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{Fingerprint:"other",HostIdentity:testHost,Unit:pinnedUnit,Ready:true},nil}}},
		{"missing host",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{Fingerprint:testPlan,Unit:pinnedUnit,Ready:true},nil}}},
		{"host mismatch",func(g *Gate){g.ReadPlan=func()(PlanSnapshot,error){return PlanSnapshot{Fingerprint:testPlan,HostIdentity:"machine-id:"+strings.Repeat("b",32),Unit:pinnedUnit,Ready:true},nil}}},
		{"verifier unavailable",func(g *Gate){g.ReadVerifier=func()(approval.Verifier,error){return approval.Verifier{},errors.New("key not provisioned")}}},
		{"anchor missing",func(g *Gate){g.ReadVerifier=func()(approval.Verifier,error){return approval.Verifier{HostIdentity:testHost},nil}}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			g:=testGate()
			tc.change(&g)
			if err:=g.CheckOnly(wire);err==nil{t.Fatal("unexpected admission of invalid prerequisite")}
		})
	}
}

func TestMalformedWireDoesNotReadPlanOrKey(t *testing.T) {
	g:=testGate()
	plans,keys:=0,0
	g.ReadPlan=func()(PlanSnapshot,error){plans++;return PlanSnapshot{},errors.New("no plan")}
	g.ReadVerifier=func()(approval.Verifier,error){keys++;return approval.Verifier{},errors.New("no key")}
	for _,wire:=range [][]byte{nil,[]byte("not-json"),[]byte("{\"schema_version\":1,\"operation\":\"shell.exec\",\"approval_payload\":\"YQ==\",\"approval_signature\":\"YQ==\"}")}{
		if err:=g.CheckOnly(wire);err==nil{t.Fatal("malformed wire accepted")}
	}
	if plans!=0||keys!=0{t.Fatalf("invalid wire touched plan/key readers: %d,%d",plans,keys)}
}

func TestSignedInputRefusals(t *testing.T) {
	g:=testGate()
	cases:=[]struct{name string; change func(*approval.PayloadV2)}{
		{"foreign plan",func(p *approval.PayloadV2){p.PlanFingerprint="other"}},
		{"foreign host",func(p *approval.PayloadV2){p.HostIdentity="machine-id:"+strings.Repeat("b",32)}},
		{"wrong purpose",func(p *approval.PayloadV2){p.Purpose=string(approval.PurposeMUVGIntegrationV1)}},
		{"other service",func(p *approval.PayloadV2){p.Capabilities=[]string{"muvg.service.restart.v1;unit=nginx.service"}}},
		{"expired",func(p *approval.PayloadV2){p.ExpiresAt=time.Date(2029,1,1,0,0,0,0,time.UTC)}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			p:=testPayload()
			tc.change(&p)
			if err:=g.CheckOnly(testWire(t,p));err==nil{t.Fatal("wrong signed authority was accepted")}
		})
	}
}

func TestCallerIdentityCannotComeFromJSON(t *testing.T) {
	var fields map[string]any
	if err:=json.Unmarshal(testWire(t,testPayload()),&fields);err!=nil{t.Fatal(err)}
	fields["caller_uid"]=1001
	fields["caller_gid"]=1001
	fields["peer_pid"]=4242
	wire,err:=json.Marshal(fields)
	if err!=nil{t.Fatal(err)}
	if err:=testGate().CheckOnly(wire);err==nil{t.Fatal("caller-supplied identity accepted")}
}
