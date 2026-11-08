//go:build linux

package pinnedunitfile

import (
    "context"
    "os"
    "path/filepath"
    "syscall"
    "testing"
)

func makeUsrmerge(t *testing.T, root string, target string) {
    t.Helper()
    if err := os.Symlink(target, filepath.Join(root, "lib")); err != nil {
        t.Fatal(err)
    }
}

func TestUsrmergeExactAliasAndCanonicalKernelPath(t *testing.T) {
    root, _, uid := sandbox(t)
    makeUsrmerge(t, root, "usr/lib")
    canonical, err := collectFragmentUnderRoot(context.Background(), root, uid, CanonicalFragment)
    if err != nil { t.Fatal(err) }
    alias, err := collectFragmentUnderRoot(context.Background(), root, uid, UsrmergeFragment)
    if err != nil { t.Fatalf("known usrmerge link should be reviewable: %v", err) }
    if alias != canonical || alias.Path != CanonicalFragment {
        t.Fatalf("alias caused different physical file content/identity: canonical=%+v alias=%+v", canonical, alias)
    }
}

func TestUsrmergeRejectsEveryUnpinnedTargetAndType(t *testing.T) {
    cases := []struct{
        name string
        make func(t *testing.T, root string)
    }{
        {"missing alias",func(t *testing.T, root string){}},
        {"normal lib directory",func(t *testing.T, root string){
            if err:=os.Mkdir(filepath.Join(root,"lib"),0755);err!=nil{t.Fatal(err)}
        }},
        {"absolute target",func(t *testing.T, root string){makeUsrmerge(t,root,"/usr/lib")}},
        {"parent traversal",func(t *testing.T, root string){makeUsrmerge(t,root,"../etc")}},
        {"wrong target",func(t *testing.T, root string){makeUsrmerge(t,root,"usr/local/lib")}},
        {"same target with suffix",func(t *testing.T, root string){makeUsrmerge(t,root,"usr/lib/")}},
        {"same target with duplicate slash",func(t *testing.T, root string){makeUsrmerge(t,root,"usr//lib")}},
        {"link to private file",func(t *testing.T, root string){makeUsrmerge(t,root,"etc/shadow")}},
        {"link to self",func(t *testing.T, root string){makeUsrmerge(t,root,"lib")}},
        {"world writable root",func(t *testing.T, root string){
            makeUsrmerge(t,root,"usr/lib")
            if err:=os.Chmod(root,0777);err!=nil{t.Fatal(err)}
        }},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            root,_,uid:=sandbox(t)
            tc.make(t,root)
            got,err:=collectFragmentUnderRoot(context.Background(),root,uid,UsrmergeFragment)
            if err==nil || got!=(Evidence{}) {
                t.Fatalf("unsafe usrmerge accepted: %+v err %v",got,err)
            }
        })
    }
}

func TestUsrmergeUntrustedOwnerAndCancelledContextDenied(t *testing.T) {
    root,_,uid:=sandbox(t)
    makeUsrmerge(t,root,"usr/lib")
    got,err:=collectFragmentUnderRoot(context.Background(),root,uid+1,UsrmergeFragment)
    if err==nil||got!=(Evidence{}) {t.Fatalf("untrusted root/alias accepted: %+v %v",got,err)}
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    got,err=collectFragmentUnderRoot(ctx,root,uid,UsrmergeFragment)
    if err==nil||got!=(Evidence{}) {t.Fatalf("cancelled alias accepted: %+v %v",got,err)}
}

func TestUsrmergeIdentityChangeIsVisibleToStatComparison(t *testing.T) {
    root,_,uid:=sandbox(t)
    makeUsrmerge(t,root,"usr/lib")
    first,err:=verifiedUsrmergeLink(context.Background(),root,uid)
    if err!=nil{t.Fatal(err)}
    if err:=os.Remove(filepath.Join(root,"lib"));err!=nil{t.Fatal(err)}
    makeUsrmerge(t,root,"usr/lib")
    second,err:=verifiedUsrmergeLink(context.Background(),root,uid)
    if err!=nil{t.Fatal(err)}
    if first.Ino==second.Ino && first.Dev==second.Dev {t.Skip("filesystem recycled inode immediately; identity-change test not conclusive")}
    if stableStat(first,second) {t.Fatal("link replacement did not change kernel identity")}
    if first.Mode&syscall.S_IFMT!=syscall.S_IFLNK {t.Fatal("fixture was not a symlink")}
}
