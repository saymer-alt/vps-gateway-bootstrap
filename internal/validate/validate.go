package validate

import (
	"strconv"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
)

// Validate is a strict gate over effective machine state. Unlike doctor,
// which triages facts into OK/WARN/FAIL for humans, validate only knows PASS
// and FAIL: it is meant to prove readiness before and after changes, and it
// fails closed on unknown state. It never mutates the machine.
type Finding struct {
	Component string `json:"component"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
}

type Report struct {
	Host             string                  `json:"host"`
	GeneratedAt      time.Time               `json:"generated_at"`
	DiscoveryVersion string                  `json:"discovery_version"`
	Status           string                  `json:"status"`
	Findings         []Finding               `json:"findings"`
	Conflicts        []discovery.Observation `json:"conflicts,omitempty"`
	Unknowns         []discovery.Observation `json:"unknowns,omitempty"`
}

const (
	StatusPass = "PASS"
	StatusFail = "FAIL"
)

const (
	mb  = 1024 * 1024
	gib = 1024 * mb
)

// Options selects which gate level runs. Base validates effective state;
// Production adds the resource thresholds required for a gateway host.
type Options struct {
	Production bool
}

func FromDiscovery(r discovery.Result, o Options) Report {
	rep := Report{
		Host:             r.Host.Hostname,
		GeneratedAt:      time.Now().UTC(),
		DiscoveryVersion: r.DiscoveryVersion,
		Conflicts:        r.Conflicts,
		Unknowns:         r.Unknowns,
	}

	if len(r.Conflicts) > 0 {
		rep.add("DISCOVERY", StatusFail, "discovery reported "+strconv.Itoa(len(r.Conflicts))+" conflict(s)")
	} else {
		rep.add("DISCOVERY", StatusPass, "no conflicts")
	}

	if !r.SSH.Installed {
		rep.add("SSH", StatusFail, "sshd was not found")
	} else if len(r.SSH.EffectivePorts) == 0 {
		rep.add("SSH", StatusFail, "no effective SSH listener discovered")
	} else {
		rep.add("SSH", StatusPass, "listening on "+intsSummary(r.SSH.EffectivePorts))
	}
	switch {
	case r.SSH.PasswordAuthentication == nil:
		rep.add("SSH-HARDENING", StatusFail, "password authentication state unknown; effective config must be provable")
	case *r.SSH.PasswordAuthentication:
		rep.add("SSH-HARDENING", StatusFail, "password authentication is enabled")
	default:
		rep.add("SSH-HARDENING", StatusPass, "password authentication disabled")
	}

	if r.Network.ExternalInterface == "" || r.Network.DefaultGateway == "" {
		rep.add("NETWORK", StatusFail, "no external interface or default gateway")
	} else {
		rep.add("NETWORK", StatusPass, "external "+r.Network.ExternalInterface+" via "+r.Network.DefaultGateway)
	}
	if len(r.Routing.DefaultRoutes) == 0 {
		rep.add("ROUTING", StatusFail, "no default route discovered")
	} else {
		rep.add("ROUTING", StatusPass, strconv.Itoa(len(r.Routing.DefaultRoutes))+" default route(s)")
	}

	if !r.Capabilities.Systemd {
		rep.add("SYSTEMD", StatusFail, "systemd not available; managed units cannot be controlled")
	} else {
		rep.add("SYSTEMD", StatusPass, "systemd present")
	}
	if len(r.Firewall.Layers) == 0 {
		rep.add("FIREWALL", StatusFail, "no supported firewall frontend detected")
	} else {
		rep.add("FIREWALL", StatusPass, "layers: "+joinLimited(r.Firewall.Layers, 4))
	}

	if o.Production {
		if !r.Network.IPv4 {
			rep.add("IPV4", StatusFail, "IPv4 connectivity not discovered")
		} else {
			rep.add("IPV4", StatusPass, "IPv4 active")
		}
		if len(r.Network.DNS.Resolvers) == 0 {
			rep.add("DNS", StatusFail, "no DNS resolvers discovered")
		} else {
			rep.add("DNS", StatusPass, joinLimited(r.Network.DNS.Resolvers, 3))
		}
		if r.System.Memory.TotalMB < 1024 {
			rep.add("MEMORY", StatusFail, strconv.Itoa(int(r.System.Memory.TotalMB))+" MB total; production requires at least 1 GiB")
		} else {
			rep.add("MEMORY", StatusPass, strconv.Itoa(int(r.System.Memory.TotalMB))+" MB total")
		}
		if r.System.RootFS.AvailableBytes < gib {
			rep.add("DISK", StatusFail, "less than 1 GiB available on the root filesystem")
		} else {
			rep.add("DISK", StatusPass, strconv.Itoa(int(r.System.RootFS.AvailableBytes/gib))+" GiB available")
		}
		if len(r.Unknowns) > 0 {
			rep.add("STATE", StatusFail, strconv.Itoa(len(r.Unknowns))+" undiscovered area(s); production requires a fully discovered machine")
		} else {
			rep.add("STATE", StatusPass, "no unknown areas")
		}
	}

	if rep.Status == "" {
		rep.Status = overall(rep.Findings)
	}
	return rep
}

func overall(findings []Finding) string {
	for _, f := range findings {
		if f.Status == StatusFail { return StatusFail }
	}
	return StatusPass
}

func (rep *Report) add(component, status, detail string) {
	rep.Findings = append(rep.Findings, Finding{Component: component, Status: status, Detail: detail})
	rep.Status = overall(rep.Findings)
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
