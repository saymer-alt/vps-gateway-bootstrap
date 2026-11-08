//go:build linux

package pinnedunitfile

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"
)

const managerSample = "Id=fail2ban.service\n" +
    "LoadState=loaded\n" +
    "FragmentPath=/lib/systemd/system/fail2ban.service\n" +
    "DropInPaths=\n" +
    "SourcePath=\n" +
    "Transient=no\n" +
    "UnitFileState=enabled\n"
const reloadSample = "Id=fail2ban.service\nNeedDaemonReload=no\n"

var managerQuery = []string{
    "--system", "show", "--all", "fail2ban.service",
    "--property=Id", "--property=LoadState", "--property=FragmentPath",
    "--property=DropInPaths", "--property=SourcePath", "--property=Transient",
    "--property=UnitFileState",
}

type reportedFixture struct {
    metadata [2]string
    reload [2]string
    metaQueries int
    reloadQueries int
    commands []string
    forcedErr error
}

func defaultReported() *reportedFixture {
    return &reportedFixture{
        metadata: [2]string{managerSample,managerSample},
        reload: [2]string{reloadSample,reloadSample},
    }
}

func (f *reportedFixture) run(ctx context.Context, exe string, args ...string) ([]byte,error) {
    if err:=ctx.Err();err!=nil{return nil,err}
    if exe!="systemctl" {
        return nil,errors.New("not the pinned systemctl binary")
    }
    if f.forcedErr!=nil{return nil,f.forcedErr}
    switch {
    case reflect.DeepEqual(args,managerQuery):
        f.commands=append(f.commands,"metadata")
        n:=f.metaQueries
        f.metaQueries++
        if n>1{return nil,errors.New("unexpected extra manager metadata query")}
        return []byte(f.metadata[n]),nil
    case reflect.DeepEqual(args,reloadManagerArgs):
        f.commands=append(f.commands,"reload")
        n:=f.reloadQueries
        f.reloadQueries++
        if n>1{return nil,errors.New("unexpected extra reload query")}
        return []byte(f.reload[n]),nil
    default:
        return nil,errors.New("unpinned manager command or properties")
    }
}

func TestReportedUsrmergeLinksToActualKernelFDObjectOnly(t *testing.T) {
    root,_,uid:=sandbox(t)
    makeUsrmerge(t,root,"usr/lib")
    report:=defaultReported()
    diskReads:=0
    acquire:=func(ctx context.Context, path string)(Evidence,error){
        diskReads++
        return collectFragmentUnderRoot(ctx,root,uid,path)
    }
    got,err:=matchManagerDisk(context.Background(),report.run,acquire,uid)
    if err!=nil{t.Fatal(err)}
    if got.Status!=MatchedMetadataDiskOnly ||
        got.ReportedFragment!=UsrmergeFragment ||
        got.Disk.Path!=CanonicalFragment || got.Disk.Inode==0 ||
        got.Disk.SHA256=="" || len(got.Reasons)==0 {
        t.Fatalf("manager-reported path was not correlated to kernel FD: %+v",got)
    }
    if diskReads!=2 || report.metaQueries!=2 || report.reloadQueries!=2 ||
        !reflect.DeepEqual(report.commands,[]string{"metadata","reload","reload","metadata"}) {
        t.Fatalf("not exactly the fixed two-sided observation: %+v reads=%d",report,diskReads)
    }
}

func TestManagerCanonicalSourceWithoutAlias(t *testing.T) {
    root,_,uid:=sandbox(t)
    report:=defaultReported()
    for i:=range report.metadata {
        report.metadata[i]=strings.ReplaceAll(report.metadata[i],UsrmergeFragment,CanonicalFragment)
    }
    got,err:=matchManagerDisk(context.Background(),report.run,
        func(ctx context.Context,path string)(Evidence,error){return collectFragmentUnderRoot(ctx,root,uid,path)},uid)
    if err!=nil||got.Status!=MatchedMetadataDiskOnly||got.Disk.Path!=CanonicalFragment {
        t.Fatalf("canonical manager path incorrectly failed: %+v %v",got,err)
    }
}

func TestUnreviewableOrChangingManagerMetadataDeniesBeforeAuthority(t *testing.T) {
    cases:=[]struct{
        name string
        mutate func(*reportedFixture)
    }{
        {"missing unit",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"LoadState=loaded","LoadState=not-found",1)}},
        {"alias id",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"Id=fail2ban.service","Id=ssh.service",1)}},
        {"foreign fragment",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,UsrmergeFragment,"/etc/systemd/system/fail2ban.service",1)}},
        {"drop in",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"DropInPaths=","DropInPaths=/etc/systemd/system/fail2ban.service.d/override.conf",1)}},
        {"generated source",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"SourcePath=","SourcePath=/etc/init.d/fail2ban",1)}},
        {"transient",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"Transient=no","Transient=yes",1)}},
        {"linked",func(f *reportedFixture){f.metadata[0]=strings.Replace(managerSample,"UnitFileState=enabled","UnitFileState=linked",1)}},
        {"changed fragment after read",func(f *reportedFixture){f.metadata[1]=strings.Replace(managerSample,UsrmergeFragment,CanonicalFragment,1)}},
        {"different unit state",func(f *reportedFixture){f.metadata[1]=strings.Replace(managerSample,"LoadState=loaded","LoadState=not-found",1)}},
        {"different install state",func(f *reportedFixture){f.metadata[1]=strings.Replace(managerSample,"UnitFileState=enabled","UnitFileState=disabled",1)}},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            root,_,uid:=sandbox(t)
            makeUsrmerge(t,root,"usr/lib")
            f:=defaultReported()
            tc.mutate(f)
            got,err:=matchManagerDisk(context.Background(),f.run,
                func(ctx context.Context,path string)(Evidence,error){return collectFragmentUnderRoot(ctx,root,uid,path)},uid)
            if err!=nil || got.Status!=ManagerDiskNeedsReview || got.Disk!=(Evidence{}) {
                t.Fatalf("unsafe manager input reached favorable disk status: %+v %v",got,err)
            }
        })
    }
}

func TestReloadSignalUnknownOrStaleDenies(t *testing.T) {
    cases:=[]struct{name string;before,after string;mustError bool}{
        {"stale before",strings.Replace(reloadSample,"=no","=yes",1),reloadSample,false},
        {"stale after",reloadSample,strings.Replace(reloadSample,"=no","=yes",1),false},
        {"unknown after",reloadSample,"Id=fail2ban.service\nNeedDaemonReload=unknown\n",true},
        {"missing after",reloadSample,"Id=fail2ban.service\n",true},
        {"duplicate after",reloadSample,reloadSample+"NeedDaemonReload=no\n",true},
        {"wrong unit after",reloadSample,"Id=ssh.service\nNeedDaemonReload=no\n",true},
        {"unlisted key after",reloadSample,reloadSample+"ExecStart=/bin/sh\n",true},
        {"malformed after",reloadSample,"garbage\n",true},
        {"oversized after",reloadSample,reloadSample+strings.Repeat("x",512),true},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            root,_,uid:=sandbox(t);makeUsrmerge(t,root,"usr/lib")
            f:=defaultReported();f.reload[0],f.reload[1]=tc.before,tc.after
            got,err:=matchManagerDisk(context.Background(),f.run,
                func(ctx context.Context,path string)(Evidence,error){return collectFragmentUnderRoot(ctx,root,uid,path)},uid)
            if tc.mustError {
                if err==nil || !emptyManagerDiskReview(got) {
                    t.Fatalf("malformed manager status accepted: %+v %v",got,err)
                }
            } else if err!=nil || got.Status!=ManagerDiskNeedsReview || got.Disk!=(Evidence{}) {
                t.Fatalf("systemd stale reload signal incorrectly handled: %+v %v",got,err)
            }
        })
    }
}

func TestKernelFileOrUsrmergeChangeBetweenObservationsDenies(t *testing.T) {
    t.Run("disk content replaced",func(t *testing.T){
        root,file,uid:=sandbox(t);makeUsrmerge(t,root,"usr/lib")
        f:=defaultReported();reads:=0
        acquire:=func(ctx context.Context,p string)(Evidence,error){
            evidence,err:=collectFragmentUnderRoot(ctx,root,uid,p)
            reads++
            if reads==1 {
                if werr:=os.WriteFile(file,[]byte(fixtureBytes+"# changed\n"),0644);werr!=nil{t.Fatal(werr)}
            }
            return evidence,err
        }
        got,err:=matchManagerDisk(context.Background(),f.run,acquire,uid)
        if err!=nil||got.Status!=ManagerDiskNeedsReview||got.Disk!=(Evidence{}) {
            t.Fatalf("two different kernel file digests compared favorably: %+v %v",got,err)
        }
    })
    t.Run("alias swapped after first read",func(t *testing.T){
        root,_,uid:=sandbox(t);makeUsrmerge(t,root,"usr/lib")
        f:=defaultReported();reads:=0
        acquire:=func(ctx context.Context,p string)(Evidence,error){
            disk,err:=collectFragmentUnderRoot(ctx,root,uid,p)
            reads++
            if reads==1 {
                if e:=os.Remove(filepath.Join(root,"lib"));e!=nil{t.Fatal(e)}
                makeUsrmerge(t,root,"etc")
            }
            return disk,err
        }
        got,err:=matchManagerDisk(context.Background(),f.run,acquire,uid)
        if err==nil || !emptyManagerDiskReview(got) {
            t.Fatalf("changed usrmerge alias accepted: %+v %v",got,err)
        }
    })
    t.Run("no alias on manager-reported /lib",func(t *testing.T){
        root,_,uid:=sandbox(t)
        f:=defaultReported()
        got,err:=matchManagerDisk(context.Background(),f.run,
            func(ctx context.Context,p string)(Evidence,error){return collectFragmentUnderRoot(ctx,root,uid,p)},uid)
        if err==nil || !emptyManagerDiskReview(got) {
            t.Fatalf("unsupported /lib mapping accepted: %+v %v",got,err)
        }
    })
}

func TestMalformedDiskFactsAndCancellationFailClosed(t *testing.T) {
    root,_,uid:=sandbox(t);makeUsrmerge(t,root,"usr/lib")
    t.Run("fake digest",func(t *testing.T){
        f:=defaultReported()
        acquire:=func(ctx context.Context,p string)(Evidence,error){
            ev,err:=collectFragmentUnderRoot(ctx,root,uid,p)
            ev.SHA256="not-a-sha256"
            return ev,err
        }
        got,err:=matchManagerDisk(context.Background(),f.run,acquire,uid)
        if err!=nil||got.Status!=ManagerDiskNeedsReview||got.Disk!=(Evidence{}) {
            t.Fatalf("synthetic altered digest was reviewable: %+v %v",got,err)
        }
    })
    t.Run("nil and pre-cancelled",func(t *testing.T){
        f:=defaultReported()
        for _,ctx:=range []context.Context{nil} {
            got,err:=matchManagerDisk(ctx,f.run,func(ctx context.Context,p string)(Evidence,error){t.Fatal("unexpected read");return Evidence{},nil},uid)
            if err==nil||!emptyManagerDiskReview(got) {t.Fatalf("missing context accepted: %+v %v",got,err)}
        }
        ctx,cancel:=context.WithCancel(context.Background());cancel()
        got,err:=matchManagerDisk(ctx,f.run,nil,uid)
        if err==nil||!emptyManagerDiskReview(got) {t.Fatalf("cancelled reader accepted: %+v %v",got,err)}
    })
    t.Run("cancel after file read",func(t *testing.T){
        f:=defaultReported();ctx,cancel:=context.WithCancel(context.Background())
        acquire:=func(ctx context.Context,p string)(Evidence,error){
            disk,err:=collectFragmentUnderRoot(ctx,root,uid,p)
            cancel()
            return disk,err
        }
        got,err:=matchManagerDisk(ctx,f.run,acquire,uid)
        if err==nil||!emptyManagerDiskReview(got) {t.Fatalf("context cancellation ignored: %+v %v",got,err)}
    })
}

func emptyManagerDiskReview(r ManagerDiskReview) bool {
    return r.Status=="" && r.ReportedFragment=="" && r.Disk==(Evidence{}) && len(r.Reasons)==0
}
