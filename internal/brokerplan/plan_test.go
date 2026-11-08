package brokerplan

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokeradmission"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerproto"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

type inertExecutor struct{ invoked int }
func (e *inertExecutor) Backup(string, string) error { e.invoked++; return errors.New("forbidden") }
func (e *inertExecutor) Apply(string, string, string) error { e.invoked++; return errors.New("forbidden") }
func (e *inertExecutor) Validate(string, string) error { e.invoked++; return errors.New("forbidden") }
func (e *inertExecutor) Rollback(string, string) error { e.invoked++; return errors.New("forbidden") }

func fixture(t *testing.T) (discovery.Result, *pipeline.Config) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "first-apply-saymer3.json"))
	if err != nil { t.Fatal(err) }
	var f struct {
		Discovery discovery.Result `json:"discovery"`
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(b, &f); err != nil { t.Fatal(err) }
	cfg, err := pipeline.ParseConfig(f.Config)
	if err != nil { t.Fatal(err) }
	return f.Discovery, cfg
}

func testOrchestrator(d discovery.Result, ex *inertExecutor) orchestrate.Orchestrator {
	return orchestrate.Orchestrator{
		Discover: func() discovery.Result { return d },
		Registry: apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionService: ex,
		}},
	}
}

func rootOptions() pipeline.Options { yes:=true; return pipeline.Options{Root:&yes} }

func TestFullPreparedOrchestratePlanStillCannotAuthorize(t *testing.T) {
	d, cfg := fixture(t)
	ex := &inertExecutor{}
	c, err := InspectPrepared(testOrchestrator(d,ex),cfg,rootOptions())
	if err != nil { t.Fatalf("synthetic first experiment must prepare: %v",err) }
	if !c.Prepared.Ready || len(c.Prepared.Plan.Actions)!=1 || ex.invoked!=0 {
		t.Fatal("real orchestrate Prepare must remain read-only and produce one action")
	}
	if c.Fingerprint != orchestrate.Fingerprint(c.Prepared.Plan) ||
		c.HostIdentity!="machine-id:1111222233334444aaaabbbbccccdddd" ||
		len(c.Prepared.Plan.Capabilities)!=1 || c.Prepared.Plan.Capabilities[0]!=pinnedGrant {
		t.Fatal("plan fingerprint/host/capabilities did not derive from full Plan")
	}
	if c.Snapshot().Ready || c.OwnershipSource!="unverified-legacy-config-assertion" {
		t.Fatal("legacy OWNED config assertion became trusted ownership")
	}
}

func TestValidSignedV2DoesNotBypassMissingStage3Evidence(t *testing.T) {
	d, cfg := fixture(t)
	c, err := InspectPrepared(testOrchestrator(d,&inertExecutor{}),cfg,rootOptions())
	if err != nil { t.Fatal(err) }
	key:=ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x39},ed25519.SeedSize))
	signed,err:=approval.SignPayloadV2(approval.PayloadV2{
		SchemaVersion: approval.SchemaVersionV2,
		Purpose: string(approval.PurposeServiceExperimentV1),
		PlanFingerprint:c.Fingerprint,HostIdentity:c.HostIdentity,
		ExpiresAt: time.Date(2031,1,1,0,0,0,0,time.UTC),
		Capabilities:[]string{pinnedGrant},
	},key)
	if err!=nil {t.Fatal(err)}
	wire,err:=json.Marshal(brokerproto.Request{
		SchemaVersion:brokerproto.Version,
		Operation:brokerproto.RestartPinnedFail2ban,
		Payload:signed.Payload,Signature:signed.Signature,
	})
	if err!=nil {t.Fatal(err)}
	v:=approval.Verifier{
		TrustAnchor:key.Public().(ed25519.PublicKey),
		HostIdentity:c.HostIdentity,
		Now:func()time.Time{return time.Date(2030,1,1,0,0,0,0,time.UTC)},
	}
	if err:=brokeradmission.VerifyPinnedRestartRequest(wire,v,c.Fingerprint);err!=nil{
		t.Fatalf("the v2 signature must be valid independently: %v",err)
	}
	g:=brokergate.Gate{
		ExpectedAgentUID:1001,ExpectedAgentGID:1001,
		ReadPeer:func()(brokergate.Peer,error){return brokergate.Peer{PID:42,UID:1001,GID:1001},nil},
		ReadPlan:func()(brokergate.PlanSnapshot,error){return c.Snapshot(),nil},
		ReadVerifier:func()(approval.Verifier,error){return v,nil},
	}
	if err:=g.CheckOnly(wire);err==nil {t.Fatal("valid signature + legacy OWNED self-claim bypassed Stage 3")}
}

func TestUntrustedOrAmbiguousPlanInputsFailClosed(t *testing.T) {
	cases:=[]struct{
		name string
		change func(*discovery.Result,*pipeline.Config,*pipeline.Options,*orchestrate.Orchestrator)
	}{
		{"missing reader",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){o.Discover=nil}},
		{"UNKNOWN discovery",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){d.Status="UNKNOWN"}},
		{"PARTIAL discovery",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){d.Status="PARTIAL"}},
		{"missing machine-id",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){d.Host.MachineID=""}},
		{"unreadable machine-id",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){d.Host.MachineIDStatus=discovery.MachineIDUnreadable}},
		{"service absent",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){d.Services=nil}},
		{"service already active",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){for i:=range d.Services{if d.Services[i].Name==pinnedUnit {d.Services[i].Active=true}}}},
		{"duplicate service",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){for _,v:=range d.Services{if v.Name==pinnedUnit{d.Services=append(d.Services,v);break}}}},
		{"missing executor",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){o.Registry.ByKind=nil}},
		{"not root in preflight",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){v:=false;opt.Root=&v}},
		{"persisted state injected",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){opt.State=&state.Model{}}},
		{"file inspector injected",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){opt.InspectFile=func(string)(state.FileActual,error){return state.FileActual{},nil}}},
		{"no owner assertion",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.Ownership=nil}},
		{"foreign owner",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.Ownership[pinnedResource]=state.External}},
		{"additional owner",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.Ownership["ssh.port"]=state.Owned}},
		{"other desired service",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.Desired.Services[0].Name="sshd.service"}},
		{"additional service",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){v:=true;c.Desired.Services=append(c.Desired.Services,state.ServiceDesired{Name:"sshd.service",Active:&v})}},
		{"SSH intent",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){n:=22;c.Desired.SSH=&state.SSHDesired{Port:&n}}},
		{"file intent",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.Desired.Files=[]state.FileDesired{{Path:"/etc/unsafe",Content:"x"}}}},
		{"MUVG intent",func(d *discovery.Result,c *pipeline.Config,opt *pipeline.Options,o *orchestrate.Orchestrator){c.MUVG=&pipeline.MUVGConfig{}}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			d,cfg:=fixture(t)
			opts:=rootOptions()
			o:=testOrchestrator(d,&inertExecutor{})
			tc.change(&d,cfg,&opts,&o)
			if o.Discover!=nil {o.Discover=func()discovery.Result{return d}}
			got,err:=InspectPrepared(o,cfg,opts)
			if err==nil || got.Fingerprint!="" {
				t.Fatalf("unsafe candidate admitted: %+v err=%v",got,err)
			}
		})
	}
}

func TestMissingIntentFailsClosed(t *testing.T) {
	d,_:=fixture(t)
	o:=testOrchestrator(d,&inertExecutor{})
	if _,err:=InspectPrepared(o,nil,rootOptions());err==nil {t.Fatal("nil config accepted")}
	if _,err:=InspectPrepared(o,&pipeline.Config{},rootOptions());err==nil {t.Fatal("missing desired accepted")}
}

func TestCallerCapabilityDeriverOverriddenByCompiledPolicy(t *testing.T) {
	d,cfg:=fixture(t)
	o:=testOrchestrator(d,&inertExecutor{})
	o.DeriveRequiredCapabilities=func(state.Plan)(capability.CapabilitySet,error){
		return capability.CapabilitySet{}, errors.New("malicious deriver")
	}
	c,err:=InspectPrepared(o,cfg,rootOptions())
	if err!=nil {t.Fatal(err)}
	if len(c.Prepared.Plan.Capabilities)!=1 || c.Prepared.Plan.Capabilities[0]!=pinnedGrant {
		t.Fatal("untrusted requirement deriver changed pinned compiled scope")
	}
}
