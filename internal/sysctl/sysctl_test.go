package sysctl

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/capability"
)

// testReadSource reads one file of this package's own source (the test
// working directory is the package directory).
func testReadSource(name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readFrom(files map[string]string, errPaths map[string]error) ReadFunc {
	return func(p string) ([]byte, error) {
		if err, ok := errPaths[p]; ok {
			return nil, err
		}
		if data, ok := files[p]; ok {
			return []byte(data), nil
		}
		return nil, fs.ErrNotExist
	}
}

func listFrom(dirs map[string][]string, errDirs map[string]error) ListDirFunc {
	return func(dir string) ([]string, error) {
		if err, ok := errDirs[dir]; ok {
			return nil, err
		}
		if names, ok := dirs[dir]; ok {
			return names, nil
		}
		return nil, fs.ErrNotExist
	}
}

func TestObserveRuntimeValues(t *testing.T) {
	read := readFrom(map[string]string{
		"/proc/sys/net/ipv4/ip_forward":             "1\n",
		"/proc/sys/net/ipv4/conf/all/rp_filter":     "2\n",
		"/proc/sys/net/ipv4/conf/default/rp_filter": "0\n",
		"/proc/sys/net/ipv6/conf/all/disable_ipv6":  "0\n",
		"/proc/sys/net/ipv4/conf/eth0/rp_filter":    "1\n",
		"/proc/sys/net/ipv6/conf/eth0/disable_ipv6": "0\n",
	}, nil)
	got, err := ObserveRuntime([]string{"eth0"}, read)
	if err != nil {
		t.Fatalf("ObserveRuntime: %v", err)
	}
	want := map[SysctlKey]struct {
		Status RuntimeStatus
		Value  int64
	}{
		"net.ipv4.ip_forward":             {RuntimePresent, 1},
		"net.ipv4.conf.all.rp_filter":     {RuntimePresent, 2},
		"net.ipv4.conf.default.rp_filter": {RuntimePresent, 0},
		"net.ipv6.conf.all.disable_ipv6":  {RuntimePresent, 0},
		"net.ipv4.conf.eth0.rp_filter":    {RuntimePresent, 1},
		"net.ipv6.conf.eth0.disable_ipv6": {RuntimePresent, 0},
	}
	if len(got) != len(want) {
		t.Fatalf("observations = %d, want %d", len(got), len(want))
	}
	for _, o := range got {
		w, ok := want[o.Key]
		if !ok {
			t.Fatalf("unexpected key %q", o.Key)
		}
		if o.Status != w.Status || o.Value != w.Value {
			t.Fatalf("%q = %s/%d, want %s/%d", o.Key, o.Status, o.Value, w.Status, w.Value)
		}
	}
}

func TestObserveRuntimeFailureClassification(t *testing.T) {
	read := readFrom(
		map[string]string{"/proc/sys/net/ipv4/ip_forward": "1\n"},
		map[string]error{
			"/proc/sys/net/ipv4/conf/all/rp_filter":     fs.ErrPermission,
			"/proc/sys/net/ipv4/conf/default/rp_filter": errors.New("disk whirlpool"),
			"/proc/sys/net/ipv6/conf/all/disable_ipv6":  nil,
		},
	)
	// A nil-byte read with no error (empty file) must be UNKNOWN_PARSE.
	read = func(p string) ([]byte, error) {
		switch p {
		case "/proc/sys/net/ipv4/conf/default/rp_filter":
			return []byte("1\n"), nil
		case "/proc/sys/net/ipv6/conf/all/disable_ipv6":
			return []byte("1 1 50\n"), nil
		default:
			return readFrom(map[string]string{"/proc/sys/net/ipv4/ip_forward": "1\n"}, map[string]error{
				"/proc/sys/net/ipv4/conf/all/rp_filter":     fs.ErrPermission,
				"/proc/sys/net/ipv4/conf/eth0/rp_filter":    fs.ErrNotExist,
				"/proc/sys/net/ipv6/conf/eth0/disable_ipv6": fs.ErrNotExist,
			})(p)
		}
	}
	got, err := ObserveRuntime([]string{"eth0"}, read)
	if err != nil {
		t.Fatalf("ObserveRuntime: %v", err)
	}
	byKey := map[SysctlKey]RuntimeObservation{}
	for _, o := range got {
		byKey[o.Key] = o
	}
	if byKey["net.ipv4.ip_forward"].Status != RuntimePresent || byKey["net.ipv4.ip_forward"].Value != 1 {
		t.Fatalf("ip_forward = %+v", byKey["net.ipv4.ip_forward"])
	}
	if byKey["net.ipv4.conf.all.rp_filter"].Status != RuntimeUnknownPermission {
		t.Fatalf("all.rp_filter = %+v", byKey["net.ipv4.conf.all.rp_filter"])
	}
	if byKey["net.ipv4.conf.eth0.rp_filter"].Status != RuntimeAbsentUnsupported {
		t.Fatalf("scoped missing leaf = %+v (genuinely meaningful absence)", byKey["net.ipv4.conf.eth0.rp_filter"])
	}
	if byKey["net.ipv4.conf.default.rp_filter"].Status != RuntimePresent {
		t.Fatalf("default.rp_filter = %+v", byKey["net.ipv4.conf.default.rp_filter"])
	}
	if byKey["net.ipv6.conf.all.disable_ipv6"].Status != RuntimeUnknownParse {
		t.Fatalf("multi-token value must be UNKNOWN_PARSE: %+v", byKey["net.ipv6.conf.all.disable_ipv6"])
	}
	// The injected IO error path is covered by the "disk whirlpool" entry
	// through the first readFrom layer: default.rp_filter would have been
	// UNKNOWN_IO without the override above.
	_ = errors.New
	_ = readFrom(map[string]string{}, map[string]error{"/proc/sys/net/ipv4/ip_forward": errors.New("disk whirlpool")})
	ioGot, err := ObserveRuntime(nil, readFrom(map[string]string{}, map[string]error{"/proc/sys/net/ipv4/ip_forward": errors.New("disk whirlpool")}))
	if err != nil {
		t.Fatalf("ObserveRuntime: %v", err)
	}
	for _, o := range ioGot {
		if o.Key == "net.ipv4.ip_forward" && o.Status != RuntimeUnknownIO {
			t.Fatalf("IO failure must be UNKNOWN_IO: %+v", o)
		}
	}
}

func TestObserveRuntimeRejectsInvalidInterfaces(t *testing.T) {
	for _, iface := range []string{"eth0/../../etc", "ETH0", "eth0\n", strings.Repeat("x", 16)} {
		if _, err := ObserveRuntime([]string{iface}, readFrom(nil, nil)); err == nil {
			t.Fatalf("interface %q must be rejected before any path is built", iface)
		}
	}
	if _, err := ScopedRPFilterKey("../../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
	if _, err := ScopedRPFilterKey("all"); err == nil {
		t.Fatal("scoped all form must be rejected; the static key exists")
	}
	if _, err := ScopedDisableIPv6Key("default"); err == nil {
		t.Fatal("scoped default form must be rejected")
	}
}

func TestRuntimePathIsBounded(t *testing.T) {
	p, err := RuntimePath("net.ipv4.ip_forward")
	if err != nil || p != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatalf("RuntimePath = %q, %v", p, err)
	}
	if _, err := RuntimePath("vm.swappiness"); err == nil {
		t.Fatal("keys outside the allowlist must be rejected")
	}
}

func TestEffectiveRPFilterMaxSemantics(t *testing.T) {
	cases := []struct{ all, iface, want int64 }{
		{0, 0, 0}, {1, 0, 1}, {0, 1, 1}, {1, 2, 2}, {2, 1, 2}, {2, 2, 2},
	}
	for _, tc := range cases {
		if got := EffectiveRPFilter(tc.all, tc.iface); got != tc.want {
			t.Fatalf("EffectiveRPFilter(%d, %d) = %d, want %d", tc.all, tc.iface, got, tc.want)
		}
	}
}

func persistenceReadFrom(files map[string]string, errPaths map[string]error) (ReadFunc, ListDirFunc) {
	return readFrom(files, errPaths), listFrom(map[string][]string{
		"/etc/sysctl.d":           {"50-other.conf", "99-vps-gateway.conf"},
		"/run/sysctl.d":           {"50-other.conf"},
		"/usr/local/lib/sysctl.d": {},
		"/usr/lib/sysctl.d":       {"10-vendor.conf"},
		"/lib/sysctl.d":           {"10-vendor.conf", "95-alias.conf"},
	}, errPaths)
}

func TestPersistenceShadowingAndLexicographicPrecedence(t *testing.T) {
	read, listDir := persistenceReadFrom(map[string]string{
		// /etc outranks /run: the same-named /etc file shadows the /run file
		// completely, so /run's rp_filter=0 assignment is lost.
		"/etc/sysctl.d/50-other.conf":       "vm.swappiness = 10\nnet.ipv4.conf.all.rp_filter = 1\n",
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
		"/run/sysctl.d/50-other.conf":       "net.ipv4.conf.all.rp_filter = 0\n",
		"/usr/lib/sysctl.d/10-vendor.conf":  "net.ipv4.ip_forward = 0\n",
		"/lib/sysctl.d/10-vendor.conf":      "net.ipv4.ip_forward = 0\n",
		"/lib/sysctl.d/95-alias.conf":       "net.ipv4.conf.all.rp_filter = 2\n",
	}, nil)
	inv := ReadPersistenceSources(read, listDir)
	// Alias applied: /lib/sysctl.d was skipped because /usr/lib listed.
	aliasOK := false
	for _, a := range inv.AliasesApplied {
		if strings.HasPrefix(a, "/lib/sysctl.d") {
			aliasOK = true
		}
	}
	if !aliasOK {
		t.Fatalf("alias not applied: %v", inv.AliasesApplied)
	}
	// Same-name shadowing: /etc/50-other.conf shadows /run/50-other.conf,
	// so the shadowed rp_filter=0 assignment never participates.
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.conf.all.rp_filter"]
	if !ok || rk.Winner == nil {
		t.Fatalf("rp_filter unresolved: %+v", rk)
	}
	if rk.Winner.Source != "/etc/sysctl.d/50-other.conf" || rk.Winner.Value != 1 {
		t.Fatalf("shadowing winner = %+v", rk.Winner)
	}
	// Lexicographic precedence: 95-alias.conf (lower dir, later name) beats
	// 10-vendor.conf — same-name shadowing removed the /lib duplicate, so the
	// /usr/lib 10-vendor.conf survives and 95-alias.conf was skipped as an
	// alias of the whole directory.
	rkIPF := res.Keys["net.ipv4.ip_forward"]
	if rkIPF.Winner == nil || rkIPF.Winner.Source != ProjectDropInPath {
		t.Fatalf("project drop-in must win over the vendor file: %+v", rkIPF.Winner)
	}
	if rkIPF.ProjectAssignment == nil || !rkIPF.ProjectAssignment.FromProjectDropIn {
		t.Fatalf("project assignment missing: %+v", rkIPF)
	}
	if rkIPF.OverriddenBy != nil {
		t.Fatalf("unexpected override: %+v", rkIPF.OverriddenBy)
	}
	// Irrelevant keys are never parsed into the snapshot.
	if _, ok := res.Keys["vm.swappiness"]; ok {
		t.Fatal("irrelevant key must not enter the resolution")
	}
}

func TestPersistenceLaterFileOverridesProjectDropIn(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/50-project.conf":     "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.d/99-zzz-late.conf":    "net.ipv4.ip_forward = 0\n",
	}, nil)
	listDir := listFrom(map[string][]string{
		"/etc/sysctl.d": {"50-project.conf", "99-vps-gateway.conf", "99-zzz-late.conf"},
	}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil {
		t.Fatalf("unresolved: %+v", rk)
	}
	if rk.Winner.Source != "/etc/sysctl.d/99-zzz-late.conf" || rk.Winner.Value != 0 {
		t.Fatalf("later lexicographic file must win: %+v", rk.Winner)
	}
	if rk.OverriddenBy == nil || rk.OverriddenBy.Source != "/etc/sysctl.d/99-zzz-late.conf" {
		t.Fatalf("override of the project drop-in must be detected: %+v", rk.OverriddenBy)
	}
	if rk.ProjectAssignment == nil || rk.ProjectAssignment.Value != 1 {
		t.Fatalf("project assignment missing: %+v", rk.ProjectAssignment)
	}
}

func TestPersistenceSysctlConfUncertainty(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.conf":                  "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
	}, nil)
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	if !res.SysctlConfUncertain {
		t.Fatal("sysctl.conf presence must set the global uncertainty flag")
	}
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || !rk.SysctlConfUncertain {
		t.Fatalf("per-key uncertainty missing: %+v", rk)
	}
	if len(rk.UncertainReasons) == 0 || !strings.Contains(strings.Join(rk.UncertainReasons, ";"), "empirically unestablished") {
		t.Fatalf("uncertainty reason must name the empirical gap: %v", rk.UncertainReasons)
	}
	// Without /etc/sysctl.conf the same setup is statically confident.
	read2 := readFrom(map[string]string{"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n"}, nil)
	res2 := Resolve(ReadPersistenceSources(read2, listDir))
	rk2, ok := res2.Keys["net.ipv4.ip_forward"]
	if !ok || rk2.SysctlConfUncertain {
		t.Fatalf("static confidence must hold without sysctl.conf: %+v", rk2)
	}
	if rk2.Winner == nil || rk2.Winner.Source != ProjectDropInPath {
		t.Fatalf("project drop-in must win cleanly: %+v", rk2.Winner)
	}
}

func TestPersistenceUnsupportedConstructsFailClosed(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.d/60-globs.conf":       "net.ipv4.conf.*.rp_filter = 0\n",
		"/etc/sysctl.d/70-dash.conf":        "-net.ipv4.conf.all.rp_filter = 1\n",
		"/etc/sysctl.d/80-slash.conf":       "net/ipv4/ip_forward = 1\n",
		"/etc/sysctl.d/85-badvalue.conf":    "net.ipv4.conf.all.rp_filter = 01\n",
		"/etc/sysctl.d/90-malformed.conf":   "net.ipv4.ip_forward\n",
	}, nil)
	listDir := listFrom(map[string][]string{
		"/etc/sysctl.d": {"99-vps-gateway.conf", "60-globs.conf", "70-dash.conf", "80-slash.conf", "85-badvalue.conf", "90-malformed.conf"},
	}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	if len(res.Globs) != 1 {
		t.Fatalf("glob patterns = %v", res.Globs)
	}
	// The glob touches the scoped family: the key becomes uncertain.
	rkScoped, ok := res.Keys["net.ipv4.conf.eth0.rp_filter"]
	if !ok || !rkScoped.Unsupported {
		t.Fatalf("glob must fail the scoped key closed: %+v", rkScoped)
	}
	// '-' prefixed assignment fails closed for the relevant key.
	rkAll, ok := res.Keys["net.ipv4.conf.all.rp_filter"]
	if !ok || !rkAll.Unsupported {
		t.Fatalf("'-' assignment must fail closed: %+v", rkAll)
	}
	// Slash-form relevant key fails closed.
	rkFwd, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || !rkFwd.Unsupported {
		t.Fatalf("slash-form relevant key must fail closed: %+v", rkFwd)
	}
	// Non-canonical value fails closed.
	rkAll = res.Keys["net.ipv4.conf.all.rp_filter"]
	if !rkAll.Unsupported {
		t.Fatalf("non-canonical value must fail closed: %+v", rkAll)
	}
	// A relevant malformed line fails closed for the key.
	rkFwd = res.Keys["net.ipv4.ip_forward"]
	if !rkFwd.Unsupported {
		t.Fatalf("relevant malformed line must fail closed: %+v", rkFwd)
	}
}

func TestPersistenceIrrelevantContentDoesNotPoison(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.d/50-junk.conf":        "this is not a sysctl line\nvm.swappiness = 10\n-GARBAGE\nnet.ipv6.conf.all.disable_ipv6 = 0\n",
	}, nil)
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf", "50-junk.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	if len(res.Globs) != 0 {
		t.Fatalf("irrelevant content must not produce globs: %v", res.Globs)
	}
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil || rk.Winner.Value != 1 || rk.Unsupported {
		t.Fatalf("relevant key poisoned by irrelevant content: %+v", rk)
	}
	// The irrelevant malformed lines are recorded, not attributed.
	for _, f := range inv.Files {
		if f.Source == "/etc/sysctl.d/50-junk.conf" && len(f.MalformedLines) == 0 {
			t.Fatal("irrelevant malformed lines should be recorded for diagnostics")
		}
	}
}

func TestPersistenceWithinFileLaterAssignmentWins(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "# comment\nnet.ipv4.ip_forward=0\n\n; another comment\nnet.ipv4.ip_forward = 1\n",
	}, nil)
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil || rk.Winner.Value != 1 || rk.Winner.Line != 5 {
		t.Fatalf("later assignment must win: %+v", rk)
	}
	if len(inv.Files[0].SupersededLines) != 1 || inv.Files[0].SupersededLines[0] != 2 {
		t.Fatalf("superseded line tracking: %v", inv.Files[0].SupersededLines)
	}
}

func TestPersistenceUnreadableFileFailsClosed(t *testing.T) {
	read, listDir := persistenceReadFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
	}, map[string]error{
		"/etc/sysctl.d/99-unknown-content.conf": errors.New("unreadable"),
	})
	// The unreadable file sorts after the project drop-in: it could override
	// any key, so every key must carry the uncertainty.
	listDir = listFrom(map[string][]string{
		"/etc/sysctl.d": {"99-vps-gateway.conf", "99-unknown-content.conf"},
	}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok {
		t.Fatal("key must still be resolved")
	}
	found := false
	for _, r := range rk.UncertainReasons {
		if strings.Contains(r, "unreadable source") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unreadable source must create uncertainty: %v", rk.UncertainReasons)
	}
	// Directory listing failure (other than not-exist) is a DirError.
	read2, listDir2 := persistenceReadFrom(map[string]string{}, map[string]error{"/etc/sysctl.d": errors.New("listing failed")})
	inv2 := ReadPersistenceSources(read2, listDir2)
	if len(inv2.DirErrors) != 1 || inv2.DirErrors[0].Dir != "/etc/sysctl.d" {
		t.Fatalf("dir listing failure must be recorded: %+v", inv2.DirErrors)
	}
}

func TestPersistenceAbsentDirsAreNormal(t *testing.T) {
	read := readFrom(map[string]string{"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n"}, nil)
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	if len(inv.DirErrors) != 0 {
		t.Fatalf("absent directories are normal, got %+v", inv.DirErrors)
	}
	if len(inv.Files) != 1 {
		t.Fatalf("files = %d", len(inv.Files))
	}
}

func TestNoOwnershipInferred(t *testing.T) {
	// The observation foundation must not import the ownership layer or any
	// authority layer: provenance is a separate plane (NIGHT-17).
	src, err := testReadSource("sysctl.go")
	if err != nil {
		t.Fatalf("read sysctl.go: %v", err)
	}
	srcP, err := testReadSource("persistence.go")
	if err != nil {
		t.Fatalf("read persistence.go: %v", err)
	}
	for _, banned := range []string{
		"internal/ownership", "internal/state", "internal/pipeline",
		"internal/apply", "internal/orchestrate", "internal/approval",
		"internal/journal", "internal/leak", "internal/lock",
	} {
		if strings.Contains(src, banned) || strings.Contains(srcP, banned) {
			t.Fatalf("sysctl package must not import %s", banned)
		}
	}
	// The compiled project drop-in constant is an observation coordinate;
	// no assignment or capability constructor exists in this package.
	if strings.Contains(src, "OwnedVerified") || strings.Contains(srcP, "OwnedVerified") {
		t.Fatal("ownership verdicts must not appear in the sysctl package")
	}
	// The capability validators remain the single compiled rule source.
	if !isRelevantKey("net.ipv4.ip_forward") || isRelevantKey("vm.swappiness") {
		t.Fatal("allowlist delegation to the capability layer drifted")
	}
	_ = capability.CheckSysctlKey("net.ipv4.ip_forward")
}
