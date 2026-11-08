package serviceunitmeta

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerplan"
)

const fullLoaded = "Id=fail2ban.service\n" +
	"LoadState=loaded\n" +
	"FragmentPath=/lib/systemd/system/fail2ban.service\n" +
	"DropInPaths=\n" +
	"SourcePath=\n" +
	"Transient=no\n" +
	"UnitFileState=enabled\n"

func fixtureRunner(out string, calls *int) Runner {
	return func(ctx context.Context, name string, args ...string) ([]byte,error) {
		*calls = *calls + 1
		if name != "systemctl" || !reflect.DeepEqual(args,queryArgs) {
			return nil,errors.New("the only permitted query is the fixed systemctl show --all field vector")
		}
		return []byte(out),nil
	}
}

func TestExactPinnedReadOnlyCommandAndReviewClassification(t *testing.T) {
	calls:=0
	ob,err:=Inspect(context.Background(),fixtureRunner(fullLoaded,&calls))
	if err!=nil || calls!=1 { t.Fatalf("metadata inspection failed: %+v, %v, calls=%d",ob,err,calls) }
	if ob.Unit!=PinnedUnit || ob.ID!=PinnedUnit || ob.ReviewStatus!=Reviewable ||
		ob.FragmentPath!="/lib/systemd/system/fail2ban.service" ||
		len(ob.Reasons)!=1 {
		t.Fatalf("expected metadata-only review, never ownership: %+v",ob)
	}
	for _,arg:=range queryArgs {
		switch arg {
		case "start","stop","restart","reload","enable","disable","kill","daemon-reload":
			t.Fatalf("mutating verb in query: %q",arg)
		}
	}
	// The same loaded unit fields do not establish independent provenance.
	// The existing full Plan gate must stay unconditional false.
	c:=brokerplan.Candidate{Fingerprint:"synthetic",HostIdentity:"machine-id:1111222233334444aaaabbbbccccdddd"}
	if c.Snapshot().Ready {
		t.Fatal("manager-reported metadata silently authorized broker plan")
	}
}

func TestMetadataUncertainAndNonPinnedUnitFailToReview(t *testing.T) {
	cases:=[]struct{name string;change func(string)string}{
		{"not-found synthesis",func(s string)string{return strings.Replace(s,"LoadState=loaded","LoadState=not-found",1)}},
		{"failed load",func(s string)string{return strings.Replace(s,"LoadState=loaded","LoadState=error",1)}},
		{"masked",func(s string)string{return strings.Replace(s,"LoadState=loaded","LoadState=masked",1)}},
		{"unexpected ID",func(s string)string{return strings.Replace(s,"Id=fail2ban.service","Id=sshd.service",1)}},
		{"empty ID",func(s string)string{return strings.Replace(s,"Id=fail2ban.service","Id=",1)}},
		{"empty fragment",func(s string)string{return strings.Replace(s,"FragmentPath=/lib/systemd/system/fail2ban.service","FragmentPath=",1)}},
		{"relative fragment",func(s string)string{return strings.Replace(s,"FragmentPath=/lib/systemd/system/fail2ban.service","FragmentPath=./fail2ban.service",1)}},
		{"noncanonical path",func(s string)string{return strings.Replace(s,"FragmentPath=/lib/systemd/system/fail2ban.service","FragmentPath=/lib/../etc/systemd/system/fail2ban.service",1)}},
		{"null fragment",func(s string)string{return strings.Replace(s,"FragmentPath=/lib/systemd/system/fail2ban.service","FragmentPath=/dev/null",1)}},
		{"symlink-like unknown fragment path",func(s string)string{return strings.Replace(s,"FragmentPath=/lib/systemd/system/fail2ban.service","FragmentPath=/",1)}},
		{"drop-in path",func(s string)string{return strings.Replace(s,"DropInPaths=","DropInPaths=/etc/systemd/system/fail2ban.service.d/override.conf",1)}},
		{"foreign generated source",func(s string)string{return strings.Replace(s,"SourcePath=","SourcePath=/etc/init.d/fail2ban",1)}},
		{"transient",func(s string)string{return strings.Replace(s,"Transient=no","Transient=yes",1)}},
		{"missing transient flag",func(s string)string{return strings.Replace(s,"Transient=no","Transient=",1)}},
		{"linked unit",func(s string)string{return strings.Replace(s,"UnitFileState=enabled","UnitFileState=linked",1)}},
		{"enabled-runtime",func(s string)string{return strings.Replace(s,"UnitFileState=enabled","UnitFileState=enabled-runtime",1)}},
		{"generated install",func(s string)string{return strings.Replace(s,"UnitFileState=enabled","UnitFileState=generated",1)}},
		{"unknown install",func(s string)string{return strings.Replace(s,"UnitFileState=enabled","UnitFileState=some-new-state",1)}},
	}
	for _,tc:=range cases{
		t.Run(tc.name,func(t *testing.T){
			calls:=0
			ob,err:=Inspect(context.Background(),fixtureRunner(tc.change(fullLoaded),&calls))
			if err!=nil||calls!=1 {t.Fatalf("expected controlled nonfavorable metadata: %+v %v",ob,err)}
			if ob.ReviewStatus==Reviewable || len(ob.Reasons)==0 {t.Fatalf("ambiguous or changed unit metadata was reviewable: %+v",ob)}
		})
	}
}

func TestMalformedOrUnavailableManagerOutputFailsClosed(t *testing.T) {
	cases:=[]struct{name,out string}{
		{"empty",""},
		{"truncated",strings.Replace(fullLoaded,"LoadState=loaded\n","",1)},
		{"missing empty property",strings.Replace(fullLoaded,"DropInPaths=\n","",1)},
		{"duplicate matching","Id=fail2ban.service\n"+fullLoaded},
		{"duplicate contradicting","Id=sshd.service\n"+fullLoaded},
		{"unexpected key",fullLoaded+"ExecStart=/bin/sh\n"},
		{"malformed line",fullLoaded+"broken\n"},
		{"embedded CR",strings.Replace(fullLoaded,"Transient=no","Transient=n\ro",1)},
		{"invalid UTF-8",fullLoaded+string([]byte{0xff})},
		{"oversized",fullLoaded+strings.Repeat(" ",MaxOutputBytes)},
	}
	for _,tc:=range cases{
		t.Run(tc.name,func(t *testing.T){
			calls:=0
			ob,err:=Inspect(context.Background(),fixtureRunner(tc.out,&calls))
			if err==nil||!isZeroObservation(ob) {
				t.Fatalf("malformed systemd metadata accepted: %+v %v",ob,err)
			}
		})
	}
}

func TestCommandErrorsAndCancellationAreDenied(t *testing.T) {
	t.Run("nil runner",func(t *testing.T){
		ob,err:=Inspect(context.Background(),nil)
		if err==nil||!isZeroObservation(ob) {t.Fatalf("missing runner accepted: %+v %v",ob,err)}
	})
	t.Run("nil context",func(t *testing.T){
		ob,err:=Inspect(nil,func(context.Context,string,...string)([]byte,error){t.Fatal("must not run");return nil,nil})
		if err==nil||!isZeroObservation(ob) {t.Fatalf("missing context accepted: %+v %v",ob,err)}
	})
	t.Run("cancel before",func(t *testing.T){
		ctx,cancel:=context.WithCancel(context.Background());cancel()
		ob,err:=Inspect(ctx,func(context.Context,string,...string)([]byte,error){t.Fatal("must not run");return nil,nil})
		if err==nil||!isZeroObservation(ob) {t.Fatalf("cancel ignored: %+v %v",ob,err)}
	})
	t.Run("cancel after",func(t *testing.T){
		ctx,cancel:=context.WithCancel(context.Background())
		ob,err:=Inspect(ctx,func(context.Context,string,...string)([]byte,error){cancel();return []byte(fullLoaded),nil})
		if err==nil||!isZeroObservation(ob) {t.Fatalf("query result after cancellation accepted: %+v %v",ob,err)}
	})
	t.Run("runner error",func(t *testing.T){
		ob,err:=Inspect(context.Background(),func(context.Context,string,...string)([]byte,error){return nil,errors.New("systemctl timeout")})
		if err==nil||!isZeroObservation(ob) {t.Fatalf("runner failure accepted: %+v %v",ob,err)}
	})
}

func TestComparisonOnlyDetectsReportedMetadataChanges(t *testing.T) {
	calls:=0
	before,err:=Inspect(context.Background(),fixtureRunner(fullLoaded,&calls))
	if err!=nil{t.Fatal(err)}
	after,err:=Inspect(context.Background(),fixtureRunner(fullLoaded,&calls))
	if err!=nil{t.Fatal(err)}
	if Compare(before,after)!=Unchanged {t.Fatal("identical metadata must compare as metadata-only unchanged")}
	after.FragmentPath="/etc/systemd/system/fail2ban.service"
	if Compare(before,after)!=Changed {t.Fatal("manager fragment path change not detected")}
	after=before;after.UnitFileState="disabled"
	if Compare(before,after)!=Changed {t.Fatal("install state change not detected")}
	after=before;after.ReviewStatus=NeedsReview
	if Compare(before,after)!=Uncomparable {t.Fatal("unreviewable metadata must never be compared favorably")}
	after=before;after.ID="sshd.service"
	if Compare(before,after)!=Uncomparable {t.Fatal("forged unit ID must never be compared favorably")}
}

func isZeroObservation(o Observation) bool {
 return o.Unit=="" && o.ID=="" && o.LoadState=="" && o.FragmentPath=="" && o.DropInPaths=="" && o.SourcePath=="" && o.Transient=="" && o.UnitFileState=="" && o.ReviewStatus=="" && len(o.Reasons)==0
}
