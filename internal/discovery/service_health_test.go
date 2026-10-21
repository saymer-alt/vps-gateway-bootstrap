package discovery

import (
	"context"
	"strings"
	"testing"
)

func systemctlOut(unit, load, active, sub string) []byte {
	return []byte("LoadState=" + load + "\nActiveState=" + active + "\nSubState=" + sub + "\n")
}

func healthRunner(states map[string][3]string) fakeRunner {
	outputs := map[string][]byte{}
	for unit, s := range states {
		outputs["systemctl show -p LoadState -p ActiveState -p SubState "+unit] = systemctlOut(unit, s[0], s[1], s[2])
	}
	return fakeRunner{outputs: outputs}
}

func TestCollectServiceHealthClassifications(t *testing.T) {
	c := &Collector{Run: healthRunner(map[string][3]string{
		"docker.service":    {"loaded", "active", "running"},
		"ssh.service":       {"loaded", "active", "running"},
		"ssh.socket":        {"loaded", "inactive", "dead"},
		"mihomo.service":    {"loaded", "failed", "failed"},
		"mita.service":      {"not-found", "inactive", "dead"},
		"ufw.service":       {"masked", "inactive", "dead"},
		"fail2ban.service":  {"loaded", "activating", "start-pre"},
		"containerd.service": {"loaded", "active", "running"},
		"systemd-resolved.service": {"loaded", "active", "running"},
	})}
	ev := c.CollectServiceHealth(context.Background())
	if ev.Status != FactStatusInconclusive {
		// failed unit AND transitional unit present: INCONCLUSIVE wins over
		// FAIL in the aggregate (inconclusive evidence must not be masked).
		t.Fatalf("aggregate status = %s", ev.Status)
	}
	if !ev.SystemctlAvailable || len(ev.Units) != len(ServiceHealthUnits) {
		t.Fatalf("units = %d, want %d", len(ev.Units), len(ServiceHealthUnits))
	}
	byUnit := map[string]UnitHealth{}
	for _, u := range ev.Units {
		byUnit[u.Unit] = u
	}
	if byUnit["docker.service"].Classification != UnitActive {
		t.Fatalf("docker = %+v", byUnit["docker.service"])
	}
	if byUnit["ssh.socket"].Classification != UnitInactive {
		t.Fatalf("ssh.socket must be observed inactive, never failed: %+v", byUnit["ssh.socket"])
	}
	if byUnit["mihomo.service"].Classification != UnitFailed {
		t.Fatalf("mihomo = %+v", byUnit["mihomo.service"])
	}
	if byUnit["mita.service"].Classification != UnitAbsent {
		t.Fatalf("mita = %+v", byUnit["mita.service"])
	}
	if byUnit["ufw.service"].Classification != UnitMasked {
		t.Fatalf("ufw = %+v", byUnit["ufw.service"])
	}
	if byUnit["fail2ban.service"].Classification != UnitTransitional {
		t.Fatalf("fail2ban = %+v", byUnit["fail2ban.service"])
	}
}

func TestCollectServiceHealthHealthyBaselineOK(t *testing.T) {
	c := &Collector{Run: healthRunner(map[string][3]string{
		"docker.service":    {"loaded", "active", "running"},
		"ssh.service":       {"loaded", "active", "running"},
		"ssh.socket":        {"not-found", "inactive", "dead"},
		"mihomo.service":    {"not-found", "inactive", "dead"},
		"mita.service":      {"not-found", "inactive", "dead"},
		"ufw.service":       {"loaded", "active", "exited"},
		"fail2ban.service":  {"not-found", "inactive", "dead"},
		"containerd.service": {"loaded", "active", "running"},
		"systemd-resolved.service": {"loaded", "active", "running"},
	})}
	ev := c.CollectServiceHealth(context.Background())
	if ev.Status != FactStatusOK {
		t.Fatalf("healthy baseline status = %s", ev.Status)
	}
}

func TestCollectServiceHealthCommandFailureAndMissingSystemctl(t *testing.T) {
	// systemctl answers exist for only some units: the rest fail → INCONCLUSIVE.
	c := &Collector{Run: healthRunner(map[string][3]string{
		"docker.service": {"loaded", "active", "running"},
	})}
	ev := c.CollectServiceHealth(context.Background())
	if ev.Status != FactStatusInconclusive {
		t.Fatalf("status = %s", ev.Status)
	}
	for _, u := range ev.Units {
		if u.Unit == "docker.service" {
			continue
		}
		if u.Classification != UnitCommandFail || len(u.Unknowns) == 0 {
			t.Fatalf("unit %s = %+v", u.Unit, u)
		}
	}

	// systemctl absent from PATH: whole fact SKIPPED, no per-unit failures.
	c = &Collector{Run: fakeRunner{outputs: map[string][]byte{}}}
	ev = c.CollectServiceHealth(context.Background())
	if ev.Status != FactStatusSkipped || len(ev.Units) != 0 || !strings.Contains(ev.Unknowns[0], "systemctl not found") {
		t.Fatalf("no-systemctl evidence = %+v", ev)
	}
}

// The unit allowlist is compile-time and free of topology-specific units:
// nothing from the deleted disposable Test VPS may become a universal
// expectation.
func TestServiceHealthAllowlistIsFixedAndGeneric(t *testing.T) {
	generic := map[string]bool{
		"containerd.service": true, "docker.service": true, "fail2ban.service": true,
		"mihomo.service": true, "mita.service": true, "ssh.service": true,
		"ssh.socket": true, "systemd-resolved.service": true, "ufw.service": true,
	}
	if len(ServiceHealthUnits) != len(generic) {
		t.Fatalf("allowlist changed: %v", ServiceHealthUnits)
	}
	for _, u := range ServiceHealthUnits {
		if !generic[u] {
			t.Fatalf("unexpected allowlisted unit %q", u)
		}
	}
	for _, banned := range []string{"test-", "zai", "wg", "awg"} {
		for _, u := range ServiceHealthUnits {
			if strings.Contains(u, banned) {
				t.Fatalf("allowlist unit %q looks topology-specific", u)
			}
		}
	}
}
