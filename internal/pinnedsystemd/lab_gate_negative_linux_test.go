//go:build linux

package pinnedsystemd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeLabHost = "1111222233334444aaaabbbbccccdddd"

func createLabPermitFixture(t *testing.T) (string, uint32) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(parent, "vps-gateway-p1c5h-disposable-lab.marker")
	contents := disposableLabMarkerMagic + "machine-id:" + fakeLabHost + "\n"
	if err := os.WriteFile(marker, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return marker, uint32(os.Getuid())
}

func TestDisposableSystemdLabPermitFixture(t *testing.T) {
	marker, uid := createLabPermitFixture(t)
	if err := checkLabPermit(fakeLabHost, fakeLabHost+"\n", marker, uid); err != nil {
		t.Fatalf("exact lab marker fixture rejected: %v", err)
	}
}

func TestDisposableSystemdLabPermitDenyMatrix(t *testing.T) {
	tests := []struct {
		name string
		change func(t *testing.T, marker string) (string, string, uint32)
	}{
		{"wrong expected host", func(t *testing.T, marker string)(string,string,uint32){
			return strings.Repeat("a",32), fakeLabHost, uint32(os.Getuid())
		}},
		{"wrong observed host",func(t *testing.T, marker string)(string,string,uint32){
			return fakeLabHost, strings.Repeat("b",32), uint32(os.Getuid())
		}},
		{"uppercase expected is noncanonical",func(t *testing.T, marker string)(string,string,uint32){
			return strings.ToUpper(fakeLabHost), fakeLabHost, uint32(os.Getuid())
		}},
		{"empty expected",func(t *testing.T, marker string)(string,string,uint32){
			return "", fakeLabHost, uint32(os.Getuid())
		}},
		{"invalid actual host",func(t *testing.T, marker string)(string,string,uint32){
			return fakeLabHost, "uninitialized", uint32(os.Getuid())
		}},
		{"wrong marker owner UID",func(t *testing.T, marker string)(string,string,uint32){
			return fakeLabHost, fakeLabHost, uint32(os.Getuid()+1)
		}},
		{"missing marker",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.Remove(marker);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"symlink marker",func(t *testing.T, marker string)(string,string,uint32){
			realPath:=marker+".real"
			if err:=os.Rename(marker,realPath);err!=nil{t.Fatal(err)}
			if err:=os.Symlink(realPath,marker);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"directory marker",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.Remove(marker);err!=nil{t.Fatal(err)}
			if err:=os.Mkdir(marker,0700);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"writable marker",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.Chmod(marker,0666);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"marker with group read",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.Chmod(marker,0640);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"marker wrong binding",func(t *testing.T, marker string)(string,string,uint32){
			raw:=disposableLabMarkerMagic+"machine-id:"+strings.Repeat("a",32)+"\n"
			if err:=os.WriteFile(marker,[]byte(raw),0600);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"marker length truncated",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.WriteFile(marker,[]byte("short"),0600);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"marker appended extra line",func(t *testing.T, marker string)(string,string,uint32){
			raw:=disposableLabMarkerMagic+"machine-id:"+fakeLabHost+"\nextra\n"
			if err:=os.WriteFile(marker,[]byte(raw),0600);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"parent world writable",func(t *testing.T, marker string)(string,string,uint32){
			if err:=os.Chmod(filepath.Dir(marker),0777);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
		{"parent is a symlink",func(t *testing.T, marker string)(string,string,uint32){
			parent:=filepath.Dir(marker)
			realDir:=parent+".real"
			if err:=os.Rename(parent,realDir);err!=nil{t.Fatal(err)}
			if err:=os.Symlink(realDir,parent);err!=nil{t.Fatal(err)}
			return fakeLabHost, fakeLabHost, uint32(os.Getuid())
		}},
	}
	for _,tc:=range tests {
		t.Run(tc.name,func(t *testing.T){
			marker,_:=createLabPermitFixture(t)
			expected,observed,uid:=tc.change(t,marker)
			if err:=checkLabPermit(expected,observed,marker,uid);err==nil {
				t.Fatalf("untrusted disposable lab permit accepted: %s",tc.name)
			}
		})
	}
}
