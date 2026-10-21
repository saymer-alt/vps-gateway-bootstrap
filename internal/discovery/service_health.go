package discovery

// Bounded read-only unit-health producer for the network doctor (ZAI-91):
// `systemctl show -p LoadState -p ActiveState -p SubState <unit>` for a FIXED,
// reviewed unit allowlist. Read-only properties only — no is-enabled polling,
// no start/stop/restart, no daemon reload. The allowlist is compile-time:
// unit names come from this file, never from input, so the producer cannot be
// pointed at an arbitrary unit.
//
// Inert by default: nothing in discovery calls CollectServiceHealth; the CLI
// doctor is the only intended caller. States distinguish absent (not-found),
// masked, inactive, failed, transitional and unclassified system answers — a
// command failure is INCONCLUSIVE, never a failed unit.

import (
	"context"
	"errors"
	"os/exec"
	"sort"
	"strings"
)

// Network-diagnostic fact statuses shared by the ZAI-91 producers. The
// vocabulary is the network-diagnostics/v1 closed set; the document
// assembly validates it and fail-closes anything else to INCONCLUSIVE.
const (
	FactStatusOK           = "OK"
	FactStatusFail         = "FAIL"
	FactStatusSkipped      = "SKIPPED"
	FactStatusInconclusive = "INCONCLUSIVE"
)

// Evidence levels shared with the network-diagnostics/v1 document (the
// assembly validates them). Defined here because the producers classify
// their own evidence and the import direction is assembly → discovery,
// never the reverse.
const (
	netdiagEvidenceObserved       = "OBSERVED"
	netdiagEvidenceConfigInferred = "CONFIG-INFERRED"
	netdiagEvidenceNotRequested   = "NOT-REQUESTED"
)

// ServiceHealthUnits is the fixed reviewed allowlist. Sorted. Test-topology
// units (the deleted disposable VPS) are deliberately NOT listed: a unit
// that exists only on one machine must never become a universal expectation
// (ZAI-91 anti-leakage rule).
var ServiceHealthUnits = []string{
	"containerd.service",
	"docker.service",
	"fail2ban.service",
	"mihomo.service",
	"mita.service",
	"ssh.service",
	"ssh.socket",
	"systemd-resolved.service",
	"ufw.service",
}

// UnitClassification is the closed per-unit classification.
const (
	UnitActive       = "ACTIVE"
	UnitFailed       = "FAILED"
	UnitInactive     = "INACTIVE"
	UnitAbsent       = "ABSENT"
	UnitMasked       = "MASKED"
	UnitTransitional = "TRANSITIONAL"
	UnitUnclassified = "UNCLASSIFIED"
	UnitCommandFail  = "COMMAND_FAILED"
)

// UnitHealth is one allowlisted unit's read-only state snapshot.
type UnitHealth struct {
	Unit           string   `json:"unit"`
	LoadState      string   `json:"load_state,omitempty"`
	ActiveState    string   `json:"active_state,omitempty"`
	SubState       string   `json:"sub_state,omitempty"`
	Classification string   `json:"classification"`
	Unknowns       []string `json:"unknowns,omitempty"`
}

// ServiceHealthEvidence is the aggregate producer result. Units are sorted
// by name (deterministic). Status summarizes the set: any FAILED unit fails
// the fact; any command failure / transitional / unclassified answer is
// INCONCLUSIVE; ABSENT and MASKED are genuine machine answers, not failures.
type ServiceHealthEvidence struct {
	Status             string       `json:"status"`
	SystemctlAvailable bool         `json:"systemctl_available"`
	Units              []UnitHealth `json:"units,omitempty"`
	Unknowns           []string     `json:"unknowns,omitempty"`
}

// CollectServiceHealth queries every allowlisted unit. systemctl missing is
// a whole-fact SKIPPED (unsupported system state, not per-unit failure).
func (c *Collector) CollectServiceHealth(ctx context.Context) ServiceHealthEvidence {
	ev := ServiceHealthEvidence{Status: FactStatusOK}
	if _, err := c.lookPath("systemctl"); err != nil {
		ev.Status = FactStatusSkipped
		ev.Unknowns = append(ev.Unknowns, "systemctl not found in PATH; unit health is not observable")
		return ev
	}
	ev.SystemctlAvailable = true
	for _, unit := range ServiceHealthUnits {
		u := c.queryUnitHealth(ctx, unit)
		ev.Units = append(ev.Units, u)
		switch u.Classification {
		case UnitFailed:
			if ev.Status != FactStatusInconclusive {
				ev.Status = FactStatusFail
			}
		case UnitCommandFail, UnitTransitional, UnitUnclassified:
			ev.Status = FactStatusInconclusive
		}
	}
	return ev
}

// queryUnitHealth runs exactly one allowlisted-shaped `systemctl show` for
// one unit and classifies the answer. The unit must come from
// ServiceHealthUnits (or the DNS producer's fixed resolved unit) — callers
// never forward user input here.
func (c *Collector) queryUnitHealth(ctx context.Context, unit string) UnitHealth {
	u := UnitHealth{Unit: unit}
	out, err := output(c, ctx, "systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", unit)
	if err != nil {
		u.Classification = UnitCommandFail
		note := err.Error()
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.TrimSpace(string(ee.Stderr)) != "" {
			note = displayToken(string(ee.Stderr))
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			note = "query interrupted"
		}
		u.Unknowns = append(u.Unknowns, note)
		return u
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.SplitN(line, "=", 2)
		if len(p) != 2 {
			continue
		}
		props[p[0]] = strings.TrimSpace(p[1])
	}
	load, ok := props["LoadState"]
	if !ok {
		u.Classification = UnitUnclassified
		u.Unknowns = append(u.Unknowns, "systemctl answer carried no LoadState property")
		return u
	}
	u.LoadState, u.ActiveState, u.SubState = load, props["ActiveState"], props["SubState"]
	switch {
	case load == "not-found":
		u.Classification = UnitAbsent
	case load == "masked":
		u.Classification = UnitMasked
	case u.ActiveState == "failed":
		u.Classification = UnitFailed
	case u.ActiveState == "active":
		u.Classification = UnitActive
	case u.ActiveState == "inactive":
		// Activeness is role-dependent (ssh.socket on service-architecture
		// hosts is SUPPOSED to be inactive); v1 judges nothing.
		u.Classification = UnitInactive
	case load == "loaded":
		// activating, deactivating, refreshing, maintenance, ...
		u.Classification = UnitTransitional
	default:
		u.Classification = UnitUnclassified
		u.Unknowns = append(u.Unknowns, "unclassified systemd state (load="+displayToken(load)+")")
	}
	return u
}

// SortUnitHealth orders units by name (defensive determinism).
func SortUnitHealth(units []UnitHealth) {
	sort.Slice(units, func(i, j int) bool { return units[i].Unit < units[j].Unit })
}
