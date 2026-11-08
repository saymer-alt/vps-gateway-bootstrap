//go:build linux

package pinnedunitfile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const fixtureBytes = "[Unit]\nDescription=Sandbox Fail2Ban\n[Service]\nExecStart=/usr/bin/false\n"

func sandbox(t *testing.T) (string, string, uint32) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "usr", "lib", "systemd", "system")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "fail2ban.service")
	if err := os.WriteFile(file, []byte(fixtureBytes), 0644); err != nil {
		t.Fatal(err)
	}
	return root, file, uint32(os.Getuid())
}

func TestPinnedOpenatKernelEvidence(t *testing.T) {
	root, file, uid := sandbox(t)
	out, err := collectUnderRoot(context.Background(), root, uid)
	if err != nil {
		t.Fatalf("read-only anchored kernel acquisition failed: %v", err)
	}
	sha := sha256.Sum256([]byte(fixtureBytes))
	if out.Path != CanonicalFragment || out.SHA256 != hex.EncodeToString(sha[:]) ||
		out.Size != int64(len(fixtureBytes)) || out.UID != uid ||
		out.Device == 0 || out.Inode == 0 || out.Mode&syscall.S_IFMT != syscall.S_IFREG {
		t.Fatalf("wrong disk-only evidence %+v", out)
	}
	// Read-only means input bytes remain unchanged after this observation.
	b, err := os.ReadFile(file)
	if err != nil || string(b) != fixtureBytes {
		t.Fatal("collector unexpectedly altered sandbox file")
	}
}

func TestPinnedSourceRejectsUntrustedPathBeforeFilesystem(t *testing.T) {
	for _, path := range []string{
		"", "fail2ban.service",
		"/usr/lib/systemd/system/ssh.service",
		"/usr/lib/systemd/system/../system/fail2ban.service",
		"/etc/systemd/system/fail2ban.service",
	} {
		got, err := Collect(context.Background(), path)
		if err == nil || got != (Evidence{}) {
			t.Fatalf("caller path %q gained a source: %+v, err=%v", path, got, err)
		}
	}
	if got,err:=Collect(nil,CanonicalFragment);err==nil || got!=(Evidence{}) {
		t.Fatalf("nil context accepted: %+v %v",got,err)
	}
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	if got,err:=Collect(ctx,CanonicalFragment);err==nil || got!=(Evidence{}) {
		t.Fatalf("canceled context accepted: %+v %v",got,err)
	}
}

func TestPinnedOpenatFailsClosedOnSymlinksAndTamperedTypes(t *testing.T) {
	testCases:=[]struct{
		name string
		mutate func(t *testing.T, root, file string)
	}{
		{"intermediate symlink",func(t *testing.T,root,file string){
			t.Helper()
			dir:=filepath.Join(root,"usr","lib","systemd")
			if err:=os.RemoveAll(dir);err!=nil{t.Fatal(err)}
			if err:=os.Symlink("elsewhere",dir);err!=nil{t.Fatal(err)}
		}},
		{"leaf symlink",func(t *testing.T,root,file string){
			if err:=os.Remove(file);err!=nil{t.Fatal(err)}
			if err:=os.Symlink("/etc/shadow",file);err!=nil{t.Fatal(err)}
		}},
		{"missing leaf",func(t *testing.T,root,file string){
			if err:=os.Remove(file);err!=nil{t.Fatal(err)}
		}},
		{"directory instead of file",func(t *testing.T,root,file string){
			if err:=os.Remove(file);err!=nil{t.Fatal(err)}
			if err:=os.Mkdir(file,0755);err!=nil{t.Fatal(err)}
		}},
		{"FIFO instead of file",func(t *testing.T,root,file string){
			if err:=os.Remove(file);err!=nil{t.Fatal(err)}
			if err:=syscall.Mkfifo(file,0600);err!=nil{t.Fatal(err)}
		}},
		{"world writable parent",func(t *testing.T,root,file string){
			if err:=os.Chmod(filepath.Join(root,"usr","lib"),0777);err!=nil{t.Fatal(err)}
		}},
		{"world writable leaf",func(t *testing.T,root,file string){
			if err:=os.Chmod(file,0666);err!=nil{t.Fatal(err)}
		}},
		{"group writable parent",func(t *testing.T,root,file string){
			if err:=os.Chmod(filepath.Join(root,"usr"),0775);err!=nil{t.Fatal(err)}
		}},
		{"empty file",func(t *testing.T,root,file string){
			if err:=os.WriteFile(file,nil,0600);err!=nil{t.Fatal(err)}
		}},
		{"oversized file",func(t *testing.T,root,file string){
			if err:=os.WriteFile(file,[]byte(strings.Repeat("A",MaxBytes+1)),0600);err!=nil{t.Fatal(err)}
		}},
	}
	for _,tc:=range testCases {
		t.Run(tc.name,func(t *testing.T){
			root,file,uid:=sandbox(t)
			tc.mutate(t,root,file)
			got,err:=collectUnderRoot(context.Background(),root,uid)
			if err==nil || got!=(Evidence{}) {
				t.Fatalf("unsafe fixture accepted: %+v, err=%v",got,err)
			}
		})
	}
}

func TestPinnedOpenatRejectsWrongOwnerAndCancelledObservation(t *testing.T) {
	root,_,uid:=sandbox(t)
	got,err:=collectUnderRoot(context.Background(),root,uid+1)
	if err==nil||got!=(Evidence{}) {t.Fatalf("foreign UID accepted: %+v %v",got,err)}
	ctx,cancel:=context.WithCancel(context.Background())
	cancel()
	got,err=collectUnderRoot(ctx,root,uid)
	if err==nil||got!=(Evidence{}) {t.Fatalf("cancelled observation accepted: %+v %v",got,err)}
}

func TestStableFDStatDetectsInPlaceChange(t *testing.T) {
	_,file,_:=sandbox(t)
	fd,err:=syscall.Open(file,syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,0)
	if err!=nil {t.Fatal(err)}
	defer syscall.Close(fd)
	var first,second syscall.Stat_t
	if err:=syscall.Fstat(fd,&first);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(file,[]byte(fixtureBytes+"changed on disk\n"),0644);err!=nil{t.Fatal(err)}
	if err:=syscall.Fstat(fd,&second);err!=nil{t.Fatal(err)}
	if stableStat(first,second) {
		t.Fatal("fstat identity/change comparison ignored modified disk data")
	}
}
