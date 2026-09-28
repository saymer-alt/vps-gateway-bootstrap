package sysctl

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// Uncertainty-propagation regressions (ZAI-06): inventory-level uncertainty
// (directory listing failures, unreadable /etc/sysctl.conf, relevant
// unsupported constructs in /etc/sysctl.conf) must reach the per-key
// resolution instead of silently producing confident winners. These tests
// fail against the pre-ZAI-06 Resolve, which consumed neither DirErrors nor
// the sysctl.conf unsupported/read-failure classes.

func hasReason(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}

// T1 (ZAI-06 §13): a higher-precedence persistence directory cannot be
// inventoried while a lower-precedence assignment exists. The lower-ranked
// winner must not resolve with false confidence: the failed directory could
// contain a same-named shadowing file or a lexicographically later file for
// the same key.
func TestResolveDirErrorMakesWinnerUncertain(t *testing.T) {
	read := readFrom(map[string]string{
		"/usr/lib/sysctl.d/50-vendor.conf": "net.ipv4.ip_forward = 1\n",
	}, nil)
	listDir := listFrom(map[string][]string{
		"/usr/lib/sysctl.d": {"50-vendor.conf"},
	}, map[string]error{
		"/etc/sysctl.d": errors.New("permission denied"),
	})
	inv := ReadPersistenceSources(read, listDir)
	if len(inv.DirErrors) != 1 || inv.DirErrors[0].Dir != "/etc/sysctl.d" {
		t.Fatalf("inventory must record the failed directory: %+v", inv.DirErrors)
	}
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil {
		t.Fatalf("winner must still be observed for diagnosis: %+v", rk)
	}
	if !rk.DirUncertain {
		t.Fatalf("failed higher-precedence directory must flag the key uncertain: %+v", rk)
	}
	if !hasReason(rk.UncertainReasons, "/etc/sysctl.d could not be inventoried") {
		t.Fatalf("uncertainty reason must name the failed directory: %v", rk.UncertainReasons)
	}
	if len(res.DirErrors) != 1 || res.DirErrors[0].Dir != "/etc/sysctl.d" {
		t.Fatalf("resolution must carry the directory failure: %+v", res.DirErrors)
	}
}

// T2 (ZAI-06 §13): a directory listing failure cannot be proven irrelevant
// for ANY key — its filenames are unknown, so it could shadow (same name,
// higher rank) or outrank (lexicographically later filename) any surviving
// file, whatever the key. Every represented key therefore carries the
// uncertainty; conservative all-key uncertainty is the documented correct
// behavior here, unlike key-scoped unsupported constructs.
func TestResolveDirErrorAffectsEveryRepresentedKey(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf":  "net.ipv4.ip_forward = 1\n",
		"/usr/lib/sysctl.d/40-ipv6.conf":     "net.ipv6.conf.all.disable_ipv6 = 0\n",
	}, nil)
	listDir := listFrom(map[string][]string{
		"/etc/sysctl.d":     {"99-vps-gateway.conf"},
		"/usr/lib/sysctl.d": {"40-ipv6.conf"},
	}, map[string]error{
		"/run/sysctl.d": errors.New("listing failed"),
	})
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	for _, key := range []SysctlKey{"net.ipv4.ip_forward", "net.ipv6.conf.all.disable_ipv6"} {
		rk, ok := res.Keys[key]
		if !ok {
			t.Fatalf("%s must be resolved", key)
		}
		if !rk.DirUncertain || !hasReason(rk.UncertainReasons, "/run/sysctl.d could not be inventoried") {
			t.Fatalf("%s must carry the failed-directory uncertainty: %+v", key, rk)
		}
	}
}

// T3 (ZAI-06 §13): relevant unsupported constructs inside /etc/sysctl.conf
// must fail the affected keys closed, exactly like the same constructs in a
// ranked sysctl.d file — the conf file's ordering position is empirically
// unestablished, so its globs and '-'-prefixed assignments are at least as
// significant.
func TestResolveConfUnsupportedConstructsFailClosed(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
		"/etc/sysctl.conf":                  "-net.ipv4.ip_forward = 1\nnet.ipv4.conf.*.rp_filter = 0\n",
	}, nil)
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil {
		t.Fatalf("drop-in winner must still be observed: %+v", rk)
	}
	if !rk.Unsupported {
		t.Fatalf("conf '-'-prefixed assignment must fail the key closed: %+v", rk)
	}
	if !hasReason(rk.UncertainReasons, "/etc/sysctl.conf carries an unsupported construct") {
		t.Fatalf("reason must name the conf source: %v", rk.UncertainReasons)
	}
	rkScoped, ok := res.Keys["net.ipv4.conf.eth0.rp_filter"]
	if !ok || !rkScoped.Unsupported || !hasReason(rkScoped.UncertainReasons, "/etc/sysctl.conf") {
		t.Fatalf("conf glob must fail the scoped family representative closed: %+v", rkScoped)
	}
	if !res.SysctlConfUncertain {
		t.Fatal("conf-originated unsupported constructs must set the global conf-uncertainty flag")
	}
	if len(res.Globs) != 1 || res.Globs[0] != "net.ipv4.conf.*.rp_filter" {
		t.Fatalf("conf glob patterns must be recorded: %v", res.Globs)
	}
}

// T5b (ZAI-06 §13): an unreadable /etc/sysctl.conf could assign or override
// any relevant key (ordering empirically unestablished), so every
// represented key must carry per-key uncertainty — the resolution-level flag
// alone is not consumable by per-key resolution logic.
func TestResolveUnreadableConfUncertaintyPerKey(t *testing.T) {
	read := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
	}, map[string]error{
		"/etc/sysctl.conf": fs.ErrPermission,
	})
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	inv := ReadPersistenceSources(read, listDir)
	res := Resolve(inv)
	rk, ok := res.Keys["net.ipv4.ip_forward"]
	if !ok || rk.Winner == nil {
		t.Fatalf("drop-in winner must still be observed: %+v", rk)
	}
	if !rk.SysctlConfUncertain {
		t.Fatalf("unreadable conf must flag per-key uncertainty: %+v", rk)
	}
	if !hasReason(rk.UncertainReasons, "/etc/sysctl.conf could not be read") {
		t.Fatalf("reason must name the unreadable conf: %v", rk.UncertainReasons)
	}
	// A genuinely absent conf file is meaningful absence, not uncertainty.
	read2 := readFrom(map[string]string{"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n"}, nil)
	res2 := Resolve(ReadPersistenceSources(read2, listDir))
	rk2 := res2.Keys["net.ipv4.ip_forward"]
	if rk2.SysctlConfUncertain || !hasReason(rk2.UncertainReasons, "sysctl.conf") && len(rk2.UncertainReasons) != 0 {
		t.Fatalf("absent conf must not create uncertainty: %+v", rk2)
	}
}

// T7 (ZAI-06 §13): runtime and persistence remain separate planes — a known
// runtime value never hides persistence uncertainty, and the two facts
// coexist in their distinct structures without conflation.
func TestRuntimePresenceDoesNotHidePersistenceUncertainty(t *testing.T) {
	runtimeRead := readFrom(map[string]string{"/proc/sys/net/ipv4/ip_forward": "1\n"}, nil)
	obs, err := ObserveRuntime(nil, runtimeRead)
	if err != nil {
		t.Fatalf("ObserveRuntime: %v", err)
	}
	persistRead := readFrom(map[string]string{
		"/etc/sysctl.d/99-vps-gateway.conf": "net.ipv4.ip_forward = 1\n",
	}, map[string]error{"/etc/sysctl.conf": fs.ErrPermission})
	listDir := listFrom(map[string][]string{"/etc/sysctl.d": {"99-vps-gateway.conf"}}, nil)
	res := Resolve(ReadPersistenceSources(persistRead, listDir))

	var present *RuntimeObservation
	for i := range obs {
		if obs[i].Key == "net.ipv4.ip_forward" {
			present = &obs[i]
		}
	}
	if present == nil || present.Status != RuntimePresent || present.Value != 1 {
		t.Fatalf("runtime fact must stay PRESENT: %+v", present)
	}
	rk := res.Keys["net.ipv4.ip_forward"]
	if !rk.SysctlConfUncertain {
		t.Fatalf("runtime presence must not hide persistence uncertainty: %+v", rk)
	}
}
