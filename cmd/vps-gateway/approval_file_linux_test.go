//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/approval"
)

func TestApprovalArtifactBoundedRegularFilePositive(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := approval.SignPayload(approval.Payload{
		SchemaVersion: approval.SchemaVersion,
		PlanFingerprint: strings.Repeat("a", 64),
		HostIdentity: "machine-id:" + strings.Repeat("b", 32),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second),
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "approval.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseApprovalArtifact(path)
	if err != nil {
		t.Fatalf("ordinary signed artifact refused: %v", err)
	}
	if !bytes.Equal(got.Payload, signed.Payload) || !bytes.Equal(got.Signature, signed.Signature) {
		t.Fatal("bounded artifact read changed signed bytes")
	}
}

func TestApprovalArtifactBoundedSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	for _,tc := range []struct{name string;size int;wantOK bool}{
		{"exact-limit",maxApprovalArtifactBytes,true},
		{"over-limit",maxApprovalArtifactBytes+1,false},
		{"much-larger",maxApprovalArtifactBytes*3,false},
		{"empty",0,false},
	}{
		t.Run(tc.name,func(t *testing.T){
			path := filepath.Join(dir, tc.name+".data")
			content := bytes.Repeat([]byte("x"), tc.size)
			if err:=os.WriteFile(path,content,0600);err!=nil{t.Fatal(err)}
			raw,err:=readBoundedApprovalArtifact(path)
			if tc.wantOK {
				if err!=nil || !bytes.Equal(raw,content) {
					t.Fatalf("bounded valid file rejected: len=%d err=%v",len(raw),err)
				}
			} else if err==nil || len(raw)!=0 {
				t.Fatalf("invalid size returned bytes or succeeded: len=%d err=%v",len(raw),err)
			}
		})
	}
}

func TestApprovalArtifactRejectsSymlinkFIFOAndSpecialFiles(t *testing.T) {
	root:=t.TempDir()
	real:=filepath.Join(root,"actual.json")
	if err:=os.WriteFile(real,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	link:=filepath.Join(root,"candidate-link")
	if err:=os.Symlink(real,link);err!=nil{t.Fatal(err)}
	fifo:=filepath.Join(root,"candidate-fifo")
	if err:=syscall.Mkfifo(fifo,0600);err!=nil{t.Fatal(err)}
	cases:=map[string]string{
		"symlink":link,
		"fifo":fifo,
		"directory":root,
		"missing":filepath.Join(root,"missing"),
		"device":"/dev/null",
	}
	for name,path:=range cases{
		t.Run(name,func(t *testing.T){
			begin:=time.Now()
			got,err:=readBoundedApprovalArtifact(path)
			if err==nil || len(got)!=0 {
				t.Fatalf("special artifact path accepted: %q bytes=%d err=%v",path,len(got),err)
			}
			if time.Since(begin)>2*time.Second {
				t.Fatal("special file path blocked the approval read")
			}
			artifact,err:=parseApprovalArtifact(path)
			if err==nil || len(artifact.Payload)!=0 || len(artifact.Signature)!=0 {
				t.Fatalf("parsed an invalid artifact path %q: %#v err=%v",path,artifact,err)
			}
		})
	}
}

func TestApprovalArtifactFstatChangeDetection(t *testing.T) {
	file:=filepath.Join(t.TempDir(),"approval.json")
	if err:=os.WriteFile(file,[]byte("first-approval"),0600);err!=nil{t.Fatal(err)}
	fd,err:=syscall.Open(file,syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0)
	if err!=nil{t.Fatal(err)}
	defer syscall.Close(fd)
	var before,after syscall.Stat_t
	if err:=syscall.Fstat(fd,&before);err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(file,[]byte("modified-after-read"),0600);err!=nil{t.Fatal(err)}
	if err:=syscall.Fstat(fd,&after);err!=nil{t.Fatal(err)}
	if sameApprovalFileStat(before,after) {
		t.Fatal("changed approval file passed pre/post fstat comparison")
	}
	if sameApprovalFileStat(before,before)!=true {
		t.Fatal("unchanged approval file wrongly rejected")
	}
}

func TestApprovalArtifactBoundsCannotBypassLegacyNoDowngrade(t *testing.T) {
	// Even malformed filesystem inputs must return zero-value Artifact.
	// These reader errors are never authority to choose legacy --confirm.
	file:=filepath.Join(t.TempDir(),"oversized-approval.json")
	if err:=os.WriteFile(file,bytes.Repeat([]byte("x"),maxApprovalArtifactBytes+1),0600);err!=nil{t.Fatal(err)}
	got,err:=parseApprovalArtifact(file)
	if err==nil || !errors.Is(err,syscall.EFBIG) && !strings.Contains(err.Error(),"size limit") {
		t.Fatalf("expected strict oversized artifact refusal: %+v %v",got,err)
	}
	if len(got.Payload)!=0 || len(got.Signature)!=0 {
		t.Fatalf("failed artifact returned partial material: %+v",got)
	}
}
