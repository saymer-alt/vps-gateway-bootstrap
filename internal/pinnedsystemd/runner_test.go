package pinnedsystemd

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOnlyTwoPinnedReadOnlyVectors(t *testing.T) {
	exactDefinition := []string{
		"--system", "show", "--all", "fail2ban.service",
		"--property=Id", "--property=LoadState",
		"--property=FragmentPath", "--property=DropInPaths",
		"--property=SourcePath", "--property=Transient",
		"--property=UnitFileState",
	}
	exactReload := []string{
		"--system", "show", "--all", "fail2ban.service",
		"--property=Id", "--property=NeedDaemonReload",
	}
	if !reflect.DeepEqual(definitionArgs[:], exactDefinition) ||
		!reflect.DeepEqual(reloadArgs[:], exactReload) {
		t.Fatal("pinned systemd reader command shape drifted from existing parsers")
	}
	if n,err:=allowedQuery("systemctl", exactDefinition);err!=nil||n!=8192 {
		t.Fatalf("fixed definition query rejected: %d %v",n,err)
	}
	if n,err:=allowedQuery("systemctl", exactReload);err!=nil||n!=512 {
		t.Fatalf("fixed reload query rejected: %d %v",n,err)
	}
}

func TestRejectAnyMutationOrCallerSelectedCommandBeforeExecution(t *testing.T) {
	base:=append([]string(nil),definitionArgs[:]...)
	reload:=append([]string(nil),reloadArgs[:]...)
	tests:=[]struct{name string;exe string;args []string}{
		{"absolute binary injected","/tmp/systemctl",base},
		{"shell binary","sh",base},
		{"alternate program","/usr/bin/systemctl",base},
		{"restart",binaryName,[]string{"--system","restart","fail2ban.service"}},
		{"stop",binaryName,[]string{"--system","stop","fail2ban.service"}},
		{"kill",binaryName,[]string{"--system","kill","fail2ban.service"}},
		{"reload",binaryName,[]string{"--system","daemon-reload"}},
		{"start",binaryName,[]string{"start","fail2ban.service"}},
		{"enable",binaryName,[]string{"enable","fail2ban.service"}},
		{"other unit",binaryName,replaceArg(base,3,"sshd.service")},
		{"unit path escape",binaryName,replaceArg(base,3,"../../etc/shadow")},
		{"extra property",binaryName,append(base,"--property=ExecStart")},
		{"property order",binaryName,swapArgs(base,4,5)},
		{"alternate manager",binaryName,replaceArg(base,0,"--user")},
		{"missing system manager",binaryName,base[1:]},
		{"extra environment flag",binaryName,append([]string{"--no-pager"},base...)},
		{"list units",binaryName,[]string{"list-units"}},
		{"drop fixed reload field",binaryName,reload[:len(reload)-1]},
		{"reload wrong unit",binaryName,replaceArg(reload,3,"ssh.service")},
		{"arbitrary property",binaryName,replaceArg(reload,5,"--property=ExecStart")},
	}
	for _,tc:=range tests {
		t.Run(tc.name,func(t *testing.T){
			if _,err:=allowedQuery(tc.exe,tc.args);err==nil {
				t.Fatalf("untrusted query accepted: %q %q",tc.exe,tc.args)
			}
			out,err:=Runner(context.Background(),tc.exe,tc.args...)
			if err==nil||len(out)!=0{
				t.Fatalf("untrusted query invoked or returned output: %q %q output=%q err=%v",tc.exe,tc.args,out,err)
			}
		})
	}
}

func replaceArg(values []string,index int,value string) []string {
	out:=append([]string(nil),values...)
	out[index]=value
	return out
}

func swapArgs(values []string,i,j int) []string {
	out:=append([]string(nil),values...)
	out[i],out[j]=out[j],out[i]
	return out
}

func TestRunnerDoesNotAcceptNilOrCancelledContext(t *testing.T) {
	out,err:=Runner(nil,binaryName,definitionArgs[:]...)
	if err==nil||len(out)!=0 {
		t.Fatalf("missing context accepted: %q %v",out,err)
	}
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	out,err=Runner(ctx,binaryName,reloadArgs[:]...)
	if err==nil||len(out)!=0 || !strings.Contains(err.Error(),"canceled") {
		t.Fatalf("canceled query accepted: %q %v",out,err)
	}
}
