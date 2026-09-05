package doctor

import (
	"strconv"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// Doctor is read-only diagnosis over the discovery layer. It never mutates
// the machine and never performs hidden Apply operations: it turns discovered
// facts into triaged findings (OK / WARN / FAIL) for humans and for status
// tooling. Planning must not depend on parsing doctor prose; findings are
// machine-readable.
type Check struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
}

type Report struct {
	Host             string                  `json:"host"`
	GeneratedAt      time.Time               `json:"generated_at"`
	DiscoveryVersion string                  `json:"discovery_version"`
	DiscoveryStatus  string                  `json:"discovery_status"`
	Status           string                  `json:"status"`
	Checks           []Check                 `json:"checks"`
	Conflicts        []discovery.Observation `json:"conflicts,omitempty"`
	Unknowns         []discovery.Observation `json:"unknowns,omitempty"`
}

const (
	StatusOK   = "OK"
	StatusWarn = "WARN"
	StatusFail = "FAIL"
)

const (
	mb  = 1024 * 1024
	gib = 1024 * mb
)

// FromDiscovery turns a discovery result into a triaged doctor report.
// Thresholds here describe viability of the machine as a network gateway
// (see docs/environment-matrix.md); they are advisory until validate gates
// become profile-aware.
func FromDiscovery(r discovery.Result) Report {
	rep := Report{
		Host:             r.Host.Hostname,
		GeneratedAt:      time.Now().UTC(),
		DiscoveryVersion: r.DiscoveryVersion,
		DiscoveryStatus:  r.Status,
		Conflicts:        r.Conflicts,
		Unknowns:         r.Unknowns,
	}

	rep.checkSystem(r)
	rep.checkNetwork(r)
	rep.checkRouting(r)
	rep.checkFirewall(r)
	rep.checkSSH(r)
	rep.checkDocker(r)
	rep.checkGateway(r)
	rep.checkServices(r)

	for _, c := range r.Conflicts {
		rep.Checks = append(rep.Checks, Check{Component: "CONFLICT", Status: StatusFail, Detail: c.Component + ": " + c.Message})
	}
	for _, u := range r.Unknowns {
		rep.Checks = append(rep.Checks, Check{Component: "UNKNOWN", Status: StatusWarn, Detail: u.Component + ": " + u.Message})
	}

	rep.Status = overallStatus(rep.Checks, len(r.Conflicts), len(r.Unknowns))
	return rep
}

func overallStatus(checks []Check, conflicts, unknowns int) string {
	fail, warn := conflicts > 0, unknowns > 0
	for _, c := range checks {
		switch c.Status {
		case StatusFail:
			fail = true
		case StatusWarn:
			warn = true
		}
	}
	switch {
	case fail:
		return StatusFail
	case warn:
		return StatusWarn
	default:
		return StatusOK
	}
}

func (rep *Report) add(component, status, detail string) {
	rep.Checks = append(rep.Checks, Check{Component: component, Status: status, Detail: detail})
}

func (rep *Report) checkSystem(r discovery.Result) {
	osID := r.System.OS.ID
	switch osID {
	case "debian", "ubuntu":
		rep.add("SYSTEM", StatusOK, r.System.OS.Name+" "+r.System.OS.VersionID+", kernel "+r.System.Kernel.Release+", "+r.System.Kernel.Architecture)
	default:
		rep.add("SYSTEM", StatusWarn, "unsupported distribution "+osID+" ("+r.System.OS.Name+")")
	}
	switch r.System.Kernel.Architecture {
	case "x86_64", "amd64", "aarch64", "arm64":
		rep.add("ARCH", StatusOK, r.System.Kernel.Architecture+" is supported")
	default:
		rep.add("ARCH", StatusWarn, "unusual architecture "+r.System.Kernel.Architecture)
	}

	switch {
	case r.System.Memory.TotalMB < 512:
		rep.add("MEMORY", StatusFail, "only "+strconv.Itoa(int(r.System.Memory.TotalMB))+" MB total, gateway stack needs at least 512 MB")
	case r.System.Memory.TotalMB < 1024:
		rep.add("MEMORY", StatusWarn, strconv.Itoa(int(r.System.Memory.TotalMB))+" MB total, "+strconv.Itoa(int(r.System.Memory.AvailableMB))+" MB available; 1 GiB is the tested minimum")
	default:
		rep.add("MEMORY", StatusOK, strconv.Itoa(int(r.System.Memory.TotalMB))+" MB total, "+strconv.Itoa(int(r.System.Memory.AvailableMB))+" MB available")
	}

	switch avail := r.System.RootFS.AvailableBytes; {
	case avail < 256*mb:
		rep.add("DISK", StatusFail, "root filesystem has less than 256 MB available")
	case avail < gib:
		rep.add("DISK", StatusWarn, "root filesystem has less than 1 GiB available")
	default:
		rep.add("DISK", StatusOK, "root filesystem "+strconv.Itoa(int(r.System.RootFS.AvailableBytes/gib))+" GiB available")
	}
}

func (rep *Report) checkNetwork(r discovery.Result) {
	if r.Network.ExternalInterface == "" || r.Network.DefaultGateway == "" {
		rep.add("NETWORK", StatusFail, "no external interface or default gateway discovered")
	} else {
		ipState := "IPv4"
		if r.Network.IPv6 { ipState += "+IPv6" }
		rep.add("NETWORK", StatusOK, "external "+r.Network.ExternalInterface+" via "+r.Network.DefaultGateway+" ("+ipState+")")
	}
	if len(r.Network.DNS.Resolvers) == 0 {
		rep.add("DNS", StatusWarn, "no DNS resolvers discovered")
	} else {
		rep.add("DNS", StatusOK, joinLimited(r.Network.DNS.Resolvers, 3)+" (source "+r.Network.DNS.Source+")")
	}
}

func (rep *Report) checkRouting(r discovery.Result) {
	rep.add("ROUTING", "INFO", strconv.Itoa(len(r.Routing.DefaultRoutes))+" default route(s), "+strconv.Itoa(len(r.Routing.Rules))+" policy rule(s), "+strconv.Itoa(len(r.Routing.Tables))+" extra table(s)")
}

func (rep *Report) checkFirewall(r discovery.Result) {
	if len(r.Firewall.Layers) == 0 {
		rep.add("FIREWALL", StatusWarn, "no supported firewall frontend detected")
		return
	}
	rep.add("FIREWALL", "INFO", "layers: "+joinLimited(r.Firewall.Layers, 4))
}

func (rep *Report) checkSSH(r discovery.Result) {
	if !r.SSH.Installed {
		rep.add("SSH", StatusWarn, "sshd not found on PATH; SSH effective config unknown")
		return
	}
	if len(r.SSH.EffectivePorts) == 0 {
		rep.add("SSH", StatusWarn, "installed but no effective ports discovered")
	} else {
		arch := r.SSH.Architecture
		if arch == "" { arch = "unknown architecture" }
		rep.add("SSH", "INFO", "listening on "+intsSummary(r.SSH.EffectivePorts)+" ("+arch+")")
	}
	switch {
	case r.SSH.PasswordAuthentication == nil:
		rep.add("SSH", StatusWarn, "password authentication state unknown (effective config not parsed)")
	case *r.SSH.PasswordAuthentication:
		rep.add("SSH", StatusFail, "password authentication is enabled; key-only hardening required")
	default:
		rep.add("SSH", StatusOK, "password authentication disabled")
	}
}

func (rep *Report) checkDocker(r discovery.Result) {
	if !r.Docker.Installed {
		rep.add("DOCKER", "INFO", "not installed")
		return
	}
	state := "present"
	if r.Docker.Active { state = "running" } else { state += ", daemon inactive" }
	rep.add("DOCKER", "INFO", state+" "+r.Docker.Version+", "+strconv.Itoa(len(r.Docker.Containers))+" container(s), "+strconv.Itoa(len(r.Docker.Networks))+" network(s)")
}

func (rep *Report) checkGateway(r discovery.Result) {
	reportComponent := func(name string, c discovery.Component) {
		if !c.Installed && !c.Active {
			return
		}
		state := "installed"
		if c.Active { state = "running" }
		if c.Version != "" { state += " " + c.Version }
		rep.add(name, "INFO", state)
	}
	reportComponent("MIHOMO", r.Gateway.Mihomo)
	reportComponent("MIERU", r.Gateway.Mieru)
	reportComponent("WIREGUARD", r.Gateway.WireGuard)
	reportComponent("AMNEZIA", r.Gateway.Amnezia)
}

func (rep *Report) checkServices(r discovery.Result) {
	for _, s := range r.Services {
		if !s.Exists { continue }
		state := "active"
		status := StatusOK
		if !s.Active {
			state = "inactive (" + s.SubState + ")"
			status = StatusWarn
		}
		if s.Enabled { state += ", enabled" } else { state += ", disabled" }
		rep.add("SERVICE", status, s.Name+" "+state)
	}
}

func intsSummary(ports []int) string {
	out := ""
	for i, p := range ports {
		if i > 0 { out += ", " }
		out += strconv.Itoa(p)
	}
	return out
}

func joinLimited(items []string, limit int) string {
	out := ""
	for i, s := range items {
		if i == limit { out += ", ..."; break }
		if i > 0 { out += ", " }
		out += s
	}
	return out
}
