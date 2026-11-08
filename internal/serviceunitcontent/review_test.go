package serviceunitcontent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokerplan"
)

const testFragment = "/lib/systemd/system/fail2ban.service"

const managerMetadata = "Id=fail2ban.service\n" +
	"LoadState=loaded\n" +
	"FragmentPath=" + testFragment + "\n" +
	"DropInPaths=\n" +
	"SourcePath=\n" +
	"Transient=no\n" +
	"UnitFileState=enabled\n"

const sampleUnit = "[Unit]\nDescription=Fail2Ban Service\n[Service]\nType=simple\nExecStart=/usr/bin/fail2ban-server -xf start\n"
const managerNoReload = "Id=fail2ban.service\nNeedDaemonReload=no\n"

var metadataArgv = []string{
	"--system", "show", "--all", PinnedUnit,
	"--property=Id", "--property=LoadState",
	"--property=FragmentPath", "--property=DropInPaths",
	"--property=SourcePath", "--property=Transient",
	"--property=UnitFileState",
}

type synthetic struct {
	metadata []string
	reloads []string
	blobs []Blob
	calls []string
	readCount int
	metaCount int
	reloadCount int
	readError error
	showError error
}

func goodFixture() *synthetic {
	blob := Blob{Path:testFragment, Data:[]byte(sampleUnit), Regular:true}
	return &synthetic{
		metadata:[]string{managerMetadata,managerMetadata},
		reloads:[]string{managerNoReload,managerNoReload},
		blobs:[]Blob{blob,blob},
	}
}

func (f *synthetic) show(ctx context.Context, binary string, args ...string) ([]byte,error) {
	if ctx.Err()!=nil {return nil,ctx.Err()}
	if binary!="systemctl" {return nil,errors.New("unexpected binary")}
	switch {
	case reflect.DeepEqual(args,metadataArgv):
		f.calls=append(f.calls,"metadata")
		i:=f.metaCount;f.metaCount++
		if f.showError!=nil {return nil,f.showError}
		if i>=len(f.metadata) {return nil,errors.New("too many metadata queries")}
		return []byte(f.metadata[i]),nil
	case reflect.DeepEqual(args,reloadArgs):
		f.calls=append(f.calls,"reload")
		i:=f.reloadCount;f.reloadCount++
		if f.showError!=nil {return nil,f.showError}
		if i>=len(f.reloads) {return nil,errors.New("too many reload queries")}
		return []byte(f.reloads[i]),nil
	default:
		return nil,errors.New("query escaped the fixed read-only systemd field vector")
	}
}

func (f *synthetic) read(ctx context.Context, p string) (Blob,error) {
	f.calls=append(f.calls,"read")
	if ctx.Err()!=nil {return Blob{},ctx.Err()}
	if p!=testFragment {return Blob{},errors.New("reader given unapproved path")}
	i:=f.readCount;f.readCount++
	if f.readError!=nil {return Blob{},f.readError}
	if i>=len(f.blobs) {return Blob{},errors.New("too many reads")}
	return f.blobs[i],nil
}

func deniedResult(t *testing.T, result Result, err error, mustError bool) {
	t.Helper()
	if mustError && err==nil {t.Fatalf("unsafe input accepted: %+v",result)}
	if !mustError && err!=nil {t.Fatalf("unexpected error: %+v, %v",result,err)}
	if result.Status==DiskStableOnly || result.SHA256!="" || result.Size!=0 {
		t.Fatalf("unsafe input yielded favorable digest or status: %+v, %v",result,err)
	}
	if err==nil && result.Status!=NeedsReview {
		t.Fatalf("unexpected review outcome: %+v",result)
	}
}

func TestDiskBytesAndManagerNoReloadRemainReviewOnly(t *testing.T) {
	f:=goodFixture()
	result,err:=Review(context.Background(),f.show,f.read)
	if err!=nil {t.Fatal(err)}
	sum:=sha256.Sum256([]byte(sampleUnit))
	if result.Status!=DiskStableOnly || result.Path!=testFragment ||
		result.SHA256!=hex.EncodeToString(sum[:]) || result.Size!=len(sampleUnit) ||
		len(result.Reasons)==0 {
		t.Fatalf("bounded content diagnostic missing: %+v",result)
	}
	if want:=[]string{"metadata","reload","read","read","reload","metadata"};!reflect.DeepEqual(f.calls,want){
		t.Fatalf("unexpected read sequence %v; want %v",f.calls,want)
	}
	// A matching disk digest, two NeedDaemonReload=no answers and
	// reviewable manager strings are still not authority to restart.
	candidate:=brokerplan.Candidate{Fingerprint:"synthetic",HostIdentity:"machine-id:1111222233334444aaaabbbbccccdddd"}
	if candidate.Snapshot().Ready {
		t.Fatal("review silently enabled broker execution")
	}
}

func TestChangedOrUnreviewableUnitMetadataFailsClosed(t *testing.T) {
	tests:=[]struct{name string;mutate func(*synthetic)}{
		{"not found",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,"LoadState=loaded","LoadState=not-found",1)}},
		{"unknown unit",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,"Id=fail2ban.service","Id=ssh.service",1)}},
		{"etc overridden unit",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,testFragment,"/etc/systemd/system/fail2ban.service",1)}},
		{"unrelated symlink target path",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,testFragment,"/tmp/fail2ban.service",1)}},
		{"drop in",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,"DropInPaths=","DropInPaths=/etc/systemd/system/fail2ban.service.d/override.conf",1)}},
		{"transient",func(f *synthetic){f.metadata[0]=strings.Replace(managerMetadata,"Transient=no","Transient=yes",1)}},
		{"fragment changed after reads",func(f *synthetic){f.metadata[1]=strings.Replace(managerMetadata,testFragment,"/usr/lib/systemd/system/fail2ban.service",1)}},
		{"install state changed",func(f *synthetic){f.metadata[1]=strings.Replace(managerMetadata,"UnitFileState=enabled","UnitFileState=disabled",1)}},
		{"later not found",func(f *synthetic){f.metadata[1]=strings.Replace(managerMetadata,"LoadState=loaded","LoadState=not-found",1)}},
	}
	for _,tc:=range tests {
		t.Run(tc.name,func(t *testing.T){
			f:=goodFixture();tc.mutate(f)
			res,err:=Review(context.Background(),f.show,f.read)
			deniedResult(t,res,err,false)
		})
	}
}

func TestNeedDaemonReloadNeverProvesLoadedByteIdentity(t *testing.T) {
	tests:=[]struct{name string;first,second string;errorExpected bool}{
		{"stale before",strings.Replace(managerNoReload,"=no","=yes",1),managerNoReload,false},
		{"stale after",managerNoReload,strings.Replace(managerNoReload,"=no","=yes",1),false},
		{"missing before","Id=fail2ban.service\n",managerNoReload,true},
		{"missing after",managerNoReload,"Id=fail2ban.service\n",true},
		{"unknown value","Id=fail2ban.service\nNeedDaemonReload=unknown\n",managerNoReload,true},
		{"wrong id",managerNoReload,"Id=sshd.service\nNeedDaemonReload=no\n",true},
		{"duplicate",managerNoReload,managerNoReload+"NeedDaemonReload=no\n",true},
		{"foreign key",managerNoReload,managerNoReload+"ExecStart=/bin/sh\n",true},
		{"missing response",managerNoReload,"",true},
		{"malformed response",managerNoReload,"badline\n",true},
		{"oversized",managerNoReload,managerNoReload+strings.Repeat("x",512),true},
	}
	for _,tc:=range tests{
		t.Run(tc.name,func(t *testing.T){
			f:=goodFixture()
			f.reloads[0],f.reloads[1]=tc.first,tc.second
			res,err:=Review(context.Background(),f.show,f.read)
			deniedResult(t,res,err,tc.errorExpected)
		})
	}
}

func TestBackingFileIdentityAndContentNegativeMatrix(t *testing.T) {
	tests:=[]struct{name string;mutate func(*synthetic);wantError bool}{
		{"disk changed",func(f *synthetic){f.blobs[1].Data=[]byte(sampleUnit+"# replaced\n")},false},
		{"path mismatched",func(f *synthetic){f.blobs[0].Path="/etc/shadow"},true},
		{"relative path",func(f *synthetic){f.blobs[0].Path="./fail2ban.service"},true},
		{"nonregular",func(f *synthetic){f.blobs[0].Regular=false},true},
		{"leaf symlink",func(f *synthetic){f.blobs[0].Symlink=true},true},
		{"second symlink",func(f *synthetic){f.blobs[1].Symlink=true},true},
		{"empty content",func(f *synthetic){f.blobs[0].Data=nil},true},
		{"oversized content",func(f *synthetic){f.blobs[0].Data=[]byte(strings.Repeat("a",MaxFileBytes+1))},true},
		{"binary NUL",func(f *synthetic){f.blobs[0].Data=[]byte("[Service]\x00ExecStart=/bin/sh")},true},
		{"non-UTF8",func(f *synthetic){f.blobs[0].Data=[]byte{0xff,0xfe}},true},
		{"reader error",func(f *synthetic){f.readError=errors.New("unknown stat")},true},
		{"manager failure",func(f *synthetic){f.showError=errors.New("systemctl unavailable")},true},
	}
	for _,tc:=range tests{
		t.Run(tc.name,func(t *testing.T){
			f:=goodFixture();tc.mutate(f)
			res,err:=Review(context.Background(),f.show,f.read)
			deniedResult(t,res,err,tc.wantError)
		})
	}
}

func TestContextAndInjectedProvidersFailClosed(t *testing.T) {
	f:=goodFixture()
	for _,tc:=range []struct{
		name string
		ctx context.Context
		show bool
		read bool
	}{
		{"nil context",nil,true,true},
		{"nil manager",context.Background(),false,true},
		{"nil file reader",context.Background(),true,false},
	}{
		t.Run(tc.name,func(t *testing.T){
			var showFn = f.show
			var readFn = f.read
			if !tc.show {showFn=nil}
			if !tc.read {readFn=nil}
			result,err:=Review(tc.ctx,showFn,readFn)
			deniedResult(t,result,err,true)
		})
	}
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	result,err:=Review(ctx,f.show,f.read)
	deniedResult(t,result,err,true)

	ctx2,cancel2:=context.WithCancel(context.Background())
	f2:=goodFixture()
	cancelAfterFirstRead:=func(ctx context.Context, p string)(Blob,error){
		blob,err:=f2.read(ctx,p)
		cancel2()
		return blob,err
	}
	result,err=Review(ctx2,f2.show,cancelAfterFirstRead)
	deniedResult(t,result,err,true)
}
