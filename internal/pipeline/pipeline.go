package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// Assemble runs the read-only part of the bootstrap pipeline:
//
//	discovery → state model → ownership → diff → plan → preflight
//
// It never mutates the machine. Apply is deliberately not part of this
// package: mutating the VPS stays behind the apply.Engine and explicit
// executor wiring.
type Result struct {
	Discovery discovery.Result `json:"discovery"`
	Model     state.Model      `json:"model"`
	Plan      state.Plan       `json:"plan"`
	Preflight state.Preflight  `json:"preflight"`
	// OwnershipSource records where the ownership map came from: "config",
	// "state" (persisted previous state) or "" (nothing declared).
	OwnershipSource string `json:"ownership_source,omitempty"`
}

// Config is the seed of the future persisted bootstrap configuration
// (/etc/vps-gateway): explicitly requested desired state and ownership
// declarations. Anything not listed here is treated as unspecified, and
// unspecified desired state never grants permission to change the machine.
type Config struct {
	Desired   *state.Desired             `json:"desired,omitempty"`
	Ownership map[string]state.Ownership `json:"ownership,omitempty"`
}

// ParseConfig decodes a bootstrap configuration document.
func ParseConfig(data []byte) (*Config, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Config{}, nil
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("bootstrap config: %w", err)
	}
	return &cfg, nil
}

// Options controls environment-dependent inputs. Root overrides the
// privilege fact used by the preflight root check: nil detects from the
// current process, tests and previews pass an explicit value. State carries
// the persisted previous state; per docs/state-model.md it must never
// override live discovery or explicit configuration — it only fills gaps.
type Options struct {
	Root  *bool
	State *state.Model
}

func Assemble(r discovery.Result, cfg *Config, o Options) Result {
	if cfg == nil { cfg = &Config{} }
	isRoot := os.Geteuid() == 0
	if o.Root != nil { isRoot = *o.Root }
	m := state.FromDiscovery(r)
	if cfg.Desired != nil { m.Desired = *cfg.Desired }
	source := ""
	switch {
	case cfg.Ownership != nil:
		m.Ownership = cfg.Ownership
		source = "config"
	case o.State != nil && o.State.Ownership != nil:
		m.Ownership = o.State.Ownership
		source = "state"
	}
	m.Diff = state.BuildDiff(m)
	p := state.BuildPlan(m)
	pf := state.BuildPreflightFor(m, p, isRoot)
	return Result{Discovery: r, Model: m, Plan: p, Preflight: pf, OwnershipSource: source}
}

// Ready reports whether the pipeline would proceed to apply. It is the
// single decision point shared by the dry-run summary and future callers,
// so it cannot drift from the plan and preflight it reports on.
func (res Result) Ready() bool {
	return !res.Plan.Blocked && res.Preflight.Status == state.PreflightReady
}
