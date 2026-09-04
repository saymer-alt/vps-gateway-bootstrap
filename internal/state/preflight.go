package state

import (
	"fmt"
	"net"
	"os"
)

type PreflightStatus string

const (
	PreflightReady  PreflightStatus = "READY"
	PreflightBlocked PreflightStatus = "BLOCKED"
)

type Preflight struct {
	Status       PreflightStatus `json:"status"`
	Checks       []PreflightCheck `json:"checks"`
	Blocking    []string `json:"blocking,omitempty"`
}

type PreflightCheck struct {
	Name string `json:"name"`
	OK bool `json:"ok"`
	Critical bool `json:"critical"`
	Reason string `json:"reason,omitempty"`
}

// BuildPreflight performs deterministic safety checks on the already
// discovered model. It has no side effects and intentionally does not claim
// that a remote management path is reachable: that requires a live executor.
func BuildPreflight(m Model, p Plan) Preflight {
	pf := Preflight{Status: PreflightReady}
	check := func(name string, ok, critical bool, reason string) {
		pf.Checks = append(pf.Checks, PreflightCheck{Name:name, OK:ok, Critical:critical, Reason:reason})
		if !ok && critical { pf.Status = PreflightBlocked; pf.Blocking = append(pf.Blocking, name+": "+reason) }
	}

	check("root", os.Geteuid() == 0, true, "bootstrap must run as root")
	check("supported-os", m.Actual.System.OS != "", true, "OS was not discovered")
	check("default-route", m.Actual.Network.ExternalInterface != "" && m.Actual.Network.DefaultGateway != "", true, "external interface or default gateway is unknown")
	check("ipv4", m.Actual.Network.IPv4, false, "IPv4 is not currently discovered")
	check("ssh-listener", len(m.Actual.Security.SSHPorts) > 0, true, "no effective SSH listener was discovered")
	check("plan", !p.Blocked, true, "plan is blocked")
	check("capabilities", capabilitiesForPlan(m), !p.Blocked, "required capability set cannot be established")
	check("no-blocking-constraints", !hasBlockingConstraints(m), true, "state model contains blocking constraints")
	return pf
}

func capabilitiesForPlan(m Model) bool {
	for _, d := range m.Diff {
		if d.Kind == NoChange || d.Kind == Skip || d.Kind == ExternalDiff { continue }
		switch d.Resource {
		case "ssh.port", "ssh.password_authentication":
			if !m.Capabilities.Systemd { return false }
		case "mihomo.integration", "mieru.enabled":
			if !m.Capabilities.Systemd { return false }
		}
	}
	return true
}

func hasBlockingConstraints(m Model) bool {
	for _, c := range m.Constraints { if c.Blocking { return true } }
	return false
}

// ValidateManagementEndpoint is kept separate because an executor must test
// the actual remote path; the State Model alone cannot prove it.
func ValidateManagementEndpoint(host string, port int) error {
	if host == "" || port < 1 || port > 65535 { return fmt.Errorf("invalid management endpoint") }
	_, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", host, port))
	return err
}
