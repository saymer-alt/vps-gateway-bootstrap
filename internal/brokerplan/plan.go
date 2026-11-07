// Package brokerplan inspects a full plan produced by orchestrate.Prepare.
// It never grants ownership, signs approvals, or calls Execute. The existing
// pipeline's config OWNED label is not independently verified ownership.
package brokerplan

import (
	"errors"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/brokergate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

const (
	pinnedResource = "service.fail2ban.service"
	pinnedUnit = "fail2ban.service"
	pinnedGrant = "muvg.service.restart.v1;unit=fail2ban.service"
)

// Candidate is a full read-only orchestrate.Plan for inspection, not an
// admitted ownership proof or permission to mutate a service.
type Candidate struct {
	Prepared orchestrate.Plan
	Fingerprint string
	HostIdentity string
	OwnershipSource string
}

// Snapshot deliberately refuses to claim Ready. Stage 3 ownership admission
// is still UNWIRED; a legacy OWNED config label must never become authority.
func (c Candidate) Snapshot() brokergate.PlanSnapshot {
	return brokergate.PlanSnapshot{
		Fingerprint: c.Fingerprint, HostIdentity: c.HostIdentity,
		Unit: pinnedUnit, Ready: false,
	}
}

// InspectPrepared invokes the real read-only orchestrate.Prepare with
// caller-injected sources ONLY for offline tests. A future privileged caller
// must establish trusted provenance for discovery, input config and preflight
// independently, rather than accepting these inputs from an agent.
//
// Nothing returned here may become an executable Gate snapshot until an
// independently proven Stage 3 ownership admission exists.
func InspectPrepared(o orchestrate.Orchestrator, cfg *pipeline.Config, opts pipeline.Options) (Candidate, error) {
	var denied Candidate
	if o.Discover == nil || cfg == nil || cfg.Desired == nil {
		return denied, errors.New("trusted plan inputs unavailable")
	}
	if opts.State != nil || opts.InspectFile != nil {
		return denied, errors.New("persisted state or caller file inspector is not trusted")
	}
	d := cfg.Desired
	if len(d.Services) != 1 || d.Services[0].Name != pinnedUnit ||
		d.Services[0].Active == nil || !*d.Services[0].Active ||
		d.Profile != "" || d.Forwarding != nil || d.SwapPresent != nil ||
		d.BaselineSysctl != nil || d.SSH != nil || d.Firewall != nil ||
		d.Mihomo != nil || d.Mieru != nil || len(d.Files) != 0 ||
		cfg.MUVG != nil || len(cfg.Warnings) != 0 {
		return denied, errors.New("operator intent exceeds pinned fail2ban repair")
	}
	if len(cfg.Ownership) != 1 || cfg.Ownership[pinnedResource] != state.Owned {
		return denied, errors.New("legacy planner requires one pinned OWNED assertion")
	}
	if len(o.Registry.ByKind) != 1 || o.Registry.ByKind[state.ActionService] == nil {
		return denied, errors.New("executor coverage is not pinned to SERVICE")
	}
	// Compiled Stage 4 requirements only; any injected custom deriver is
	// discarded. The resulting exact grant binds the full Plan fingerprint.
	o.DeriveRequiredCapabilities = apply.RequiredCapabilities
	p := o.Prepare(cfg, opts)
	if p.Discovery.Status != "OK" || p.Model.Status != state.StatusOK ||
		p.Discovery.Host.MachineIDStatus != discovery.MachineIDPresent ||
		p.Model.Actual.System.MachineIDStatus != discovery.MachineIDPresent ||
		!p.Ready || p.Plan.Blocked || p.Preflight.Status != state.PreflightReady ||
		len(p.Model.Constraints) != 0 || len(p.Preflight.Blocking) != 0 ||
		len(p.Blockers) != 0 || len(p.Plan.BlockReasons) != 0 {
		return denied, errors.New("discovery, preflight or full plan is not ready")
	}
	for _, check := range p.Preflight.Checks {
		if check.Critical && !check.OK {
			return denied, errors.New("critical preflight check failed")
		}
	}
	host, err := machineid.HostIdentity(p.Discovery.Host.MachineID)
	if err != nil || strings.TrimSpace(host) == "" ||
		p.Model.Actual.System.MachineID != p.Discovery.Host.MachineID {
		return denied, errors.New("canonical host identity unavailable")
	}
	if len(p.Model.Diff) != 1 || p.Model.Diff[0].Resource != pinnedResource ||
		p.Model.Diff[0].Kind != state.Update ||
		p.Model.Diff[0].Ownership != state.Owned {
		return denied, errors.New("diff is not one pinned service repair")
	}
	if p.Plan.SchemaVersion != state.SchemaVersion || len(p.Plan.Actions) != 1 ||
		len(p.Plan.Capabilities) != 1 || p.Plan.Capabilities[0] != pinnedGrant {
		return denied, errors.New("plan scope or compiled required capabilities mismatch")
	}
	a := p.Plan.Actions[0]
	if a.Kind != state.ActionService || a.Resource != pinnedResource ||
		a.Ownership != state.Owned || a.Spec == nil || a.Spec.Service == nil ||
		a.Spec.File != nil || a.Spec.SSH != nil || a.Spec.MSS != nil ||
		a.Spec.Service.Name != pinnedUnit || a.Spec.Service.Operation != "restart" ||
		a.Spec.Service.ExpectedState != "active" || a.Spec.Service.RollbackOperation != "" {
		return denied, errors.New("action is not the exact typed fail2ban restart")
	}
	found := 0
	for _, svc := range p.Discovery.Services {
		if svc.Name == pinnedUnit {
			found++
			if !svc.Exists || svc.Active {
				return denied, errors.New("fail2ban is absent or already active")
			}
		}
	}
	if found != 1 {
		return denied, fmt.Errorf("service observation count %d, require exactly one", found)
	}
	fp := orchestrate.Fingerprint(p.Plan)
	if fp == "" || strings.HasPrefix(fp, "marshal-error:") {
		return denied, errors.New("full Plan fingerprint invalid")
	}
	return Candidate{
		Prepared: p, Fingerprint: fp, HostIdentity: host,
		OwnershipSource: "unverified-legacy-config-assertion",
	}, nil
}
