package state

import "testing"

func TestBuildPreflightBlocksBadManagementState(t *testing.T) {
	m := Model{Actual: Actual{System: SystemActual{OS: "Ubuntu 24.04"}, Network: NetworkActual{ExternalInterface: "ens3", DefaultGateway: "10.0.0.1"}}}
	p := Plan{}
	pf := BuildPreflight(m, p)
	if pf.Status != PreflightBlocked { t.Fatalf("expected blocked preflight: %#v", pf) }
}

func TestBuildPreflightAcceptsCompleteModelWhenRoot(t *testing.T) {
	if testing.Short() { t.Skip("environment-dependent root check") }
	m := Model{
		Actual: Actual{
			System: SystemActual{OS: "Ubuntu 24.04", Kernel: "6.8", Architecture: "amd64"},
			Network: NetworkActual{ExternalInterface: "ens3", DefaultGateway: "10.0.0.1", IPv4: true},
			Security: SecurityActual{SSHPorts: []int{2222}},
		},
		Capabilities: Capabilities{Systemd: true},
	}
	pf := BuildPreflight(m, Plan{})
	if pf.Status != PreflightReady { t.Fatalf("expected ready preflight: %#v", pf) }
}
