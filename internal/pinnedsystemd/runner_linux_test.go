//go:build linux

package pinnedsystemd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeInstall(t *testing.T) (string, string, uint32) {
	t.Helper()
	root:=t.TempDir()
	binDir:=filepath.Join(root,"usr","bin")
	if err:=os.MkdirAll(binDir,0755);err!=nil{t.Fatal(err)}
	exe:=filepath.Join(binDir,"systemctl")
	// Never execute the fixture file: this exists only for kernel stat
	// and symlink ownership checks on a disposable directory tree.
	if err:=os.WriteFile(exe,[]byte("not executed by tests\n"),0755);err!=nil{t.Fatal(err)}
	return root,exe,uint32(os.Getuid())
}

func TestTrustedAbsoluteBinaryPathPreflight(t *testing.T) {
	root,_,uid:=fakeInstall(t)
	if err:=verifyTrustedSystemctlPath(root,uid);err!=nil {
		t.Fatalf("trusted fixture rejected: %v",err)
	}
	if err:=verifyTrustedSystemctlPath(root,uid+1);err==nil {
		t.Fatal("wrong owner gained a trusted systemctl executable")
	}
}

func TestTrustedBinaryPathNegativeMatrix(t *testing.T) {
	cases:=[]struct{name string;mutate func(*testing.T,string,string)}{
		{"binary removed",func(t *testing.T,root,exe string){if err:=os.Remove(exe);err!=nil{t.Fatal(err)}}},
		{"binary symlink",func(t *testing.T,root,exe string){
			if err:=os.Remove(exe);err!=nil{t.Fatal(err)}
			if err:=os.Symlink("/usr/bin/true",exe);err!=nil{t.Fatal(err)}
		}},
		{"binary directory",func(t *testing.T,root,exe string){
			if err:=os.Remove(exe);err!=nil{t.Fatal(err)}
			if err:=os.Mkdir(exe,0755);err!=nil{t.Fatal(err)}
		}},
		{"binary world writable",func(t *testing.T,root,exe string){
			if err:=os.Chmod(exe,0777);err!=nil{t.Fatal(err)}
		}},
		{"binary nonexecutable",func(t *testing.T,root,exe string){
			if err:=os.Chmod(exe,0644);err!=nil{t.Fatal(err)}
		}},
		{"parent writable",func(t *testing.T,root,exe string){
			if err:=os.Chmod(filepath.Join(root,"usr"),0777);err!=nil{t.Fatal(err)}
		}},
		{"root writable",func(t *testing.T,root,exe string){
			if err:=os.Chmod(root,0777);err!=nil{t.Fatal(err)}
		}},
		{"bin symlink",func(t *testing.T,root,exe string){
			if err:=os.RemoveAll(filepath.Join(root,"usr","bin"));err!=nil{t.Fatal(err)}
			if err:=os.Symlink("/tmp",filepath.Join(root,"usr","bin"));err!=nil{t.Fatal(err)}
		}},
		{"bin missing",func(t *testing.T,root,exe string){
			if err:=os.RemoveAll(filepath.Join(root,"usr","bin"));err!=nil{t.Fatal(err)}
		}},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			root,exe,uid:=fakeInstall(t)
			tc.mutate(t,root,exe)
			if err:=verifyTrustedSystemctlPath(root,uid);err==nil{
				t.Fatal("untrusted executable path accepted")
			}
		})
	}
}

func TestReadOnlyChildRunnerBoundsAndHostileEnvironment(t *testing.T) {
	// These are harmless test-only utilities. A public Runner invocation
	// cannot select their executable or its arguments.
	if _,err:=os.Stat("/usr/bin/printf");err!=nil{t.Skip("printf unavailable")}
	got,err:=runAbsolute(context.Background(),"/usr/bin/printf",
		[]string{"%s","bounded"},maxReloadOutput)
	if err!=nil||string(got)!="bounded" {t.Fatalf("expected bounded output: %q %v",got,err)}
	got,err=runAbsolute(context.Background(),"/usr/bin/printf",
		[]string{"%s",strings.Repeat("x",513)},maxReloadOutput)
	if err==nil||len(got)!=0 {
		t.Fatalf("oversized output escaped limit: %d bytes, err=%v",len(got),err)
	}
	if _,err:=os.Stat("/usr/bin/env");err==nil{
		t.Setenv("LD_PRELOAD","/tmp/agent-preload-must-not-propagate.so")
		t.Setenv("SYSTEMD_PAGER","/tmp/agent-controlled-pager")
		t.Setenv("DBUS_SYSTEM_BUS_ADDRESS","unix:path=/tmp/agent-bus")
		got,err=runAbsolute(context.Background(),"/usr/bin/env",nil,maxDefinitionOutput)
		if err!=nil {t.Fatal(err)}
		out:=string(got)
		if strings.Contains(out,"LD_PRELOAD") ||
			strings.Contains(out,"agent-controlled-pager") ||
			strings.Contains(out,"DBUS_SYSTEM_BUS_ADDRESS") {
			t.Fatalf("hostile agent environment leaked to child: %s",out)
		}
		for _,value:=range []string{"LANG=C","LC_ALL=C","PATH=/usr/bin:/bin","SYSTEMD_COLORS=0"} {
			if !strings.Contains(out,value) {t.Fatalf("fixed child env missing %s: %s",value,out)}
		}
	}
}

func TestReadOnlyChildProcessCancelledOrFailed(t *testing.T) {
	if _,err:=os.Stat("/usr/bin/sleep");err==nil {
		ctx,cancel:=context.WithTimeout(context.Background(),40*time.Millisecond)
		defer cancel()
		start:=time.Now()
		got,err:=runAbsolute(ctx,"/usr/bin/sleep",[]string{"5"},maxReloadOutput)
		if !errors.Is(err,context.DeadlineExceeded) || len(got)!=0 {
			t.Fatalf("read-only child deadline not enforced: %q %v",got,err)
		}
		if time.Since(start)>2*time.Second {t.Fatal("timed-out subprocess hung")}
	}
	if _,err:=os.Stat("/usr/bin/false");err==nil{
		got,err:=runAbsolute(context.Background(),"/usr/bin/false",nil,maxReloadOutput)
		if err==nil||len(got)!=0 {t.Fatalf("nonzero exit accepted: %q %v",got,err)}
	}
	cancelled,cancel:=context.WithCancel(context.Background());cancel()
	got,err:=runAbsolute(cancelled,"/usr/bin/printf",[]string{"hello"},maxReloadOutput)
	if !errors.Is(err,context.Canceled)||len(got)!=0 {
		t.Fatalf("cancelled command accepted: %q %v",got,err)
	}
}

func TestBoundedOutputDoesNotMakeTruncatedResponseUsable(t *testing.T) {
	var w boundedOutput
	w.max=4
	n,err:=w.Write([]byte("abcdef"))
	if n!=4||!errors.Is(err,errExcessOutput)||!w.overflow||w.data.Len()!=4 {
		t.Fatalf("bounded output cap bypassed: n=%d err=%v stored=%d",n,err,w.data.Len())
	}
	n,err=w.Write([]byte("zz"))
	if n!=0||!errors.Is(err,errExcessOutput)||w.data.Len()!=4 {
		t.Fatalf("writer continued beyond limit: n=%d err=%v stored=%d",n,err,w.data.Len())
	}
}
