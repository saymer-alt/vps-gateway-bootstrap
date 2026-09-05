// Package orchestrate is the layer between the read-only planning pipeline
// and the (future) real apply. It sequences the full apply lifecycle:
//
//	live discovery → verified state → ownership → diff → plan → preflight
//	→ executor coverage → operator confirmation → lock → Engine transaction
//	→ re-discovery → final validation → converge check → persist
//
// Phases are explicit and separated. Everything before confirmation is
// read-only. Execute refuses to mutate unless the plan is ready, a valid
// Confirmation for the exact plan fingerprint is supplied, management probe
// requirements are satisfied, and the machine-local lock is held. The
// package is deliberately NOT imported by the CLI: real apply stays
// unreachable until it is declared production-ready.
package orchestrate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/lock"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/probe"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/validate"
)

// Default paths, overridable for tests and alternate layouts.
const (
	DefaultLockPath  = "/etc/vps-gateway/apply.lock"
	DefaultStatePath = state.PersistedStatePath
)

// Orchestrator wires the dependencies of the apply lifecycle. Discover is
// injectable so tests can stage machine states; production wiring uses
// discovery.New().Discover with a timeout context.
type Orchestrator struct {
	Discover  func() discovery.Result
	Registry  apply.Registry
	LockPath  string
	StatePath string
	Now       func() time.Time
}

// Plan is the read-only planning product handed to the operator for review.
type Plan struct {
	Discovery discovery.Result
	Model     state.Model
	Plan      state.Plan
	Preflight state.Preflight
	Config    *pipeline.Config
	Ready     bool
	Blockers  []string

	// prepared marks plans produced by Prepare. Execute re-checks staleness
	// only for such plans: a re-discovery under the lock rebuilds the plan
	// and any drift between planning and execution blocks the mutation.
	// Manually built plans (e.g. programmatic finalize flows) skip the extra
	// discovery and remain the caller's responsibility.
	opts     pipeline.Options
	prepared bool
}

// Fingerprint returns the canonical identity of a plan. A Confirmation is
// only valid for the exact plan it was given for.
func Fingerprint(p state.Plan) string {
	b, err := json.Marshal(p)
	if err != nil {
		// Plans are plain data; marshalling cannot fail in practice. Hash the
		// error representation so a failure still yields a stable identity.
		return "marshal-error:" + err.Error()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Confirmation is the explicit operator approval boundary. Before it, the
// orchestrator is read-only; after it, mutation is allowed — and only for
// the exact plan fingerprint that was approved.
type Confirmation struct {
	PlanFingerprint string    `json:"plan_fingerprint"`
	ApprovedBy      string    `json:"approved_by"`
	At              time.Time `json:"at"`
}

// Confirm verifies that c approves exactly plan p. Any mismatch — different
// plan, empty approver, zero timestamp — is an error and blocks mutation.
func (o Orchestrator) Confirm(p Plan, c Confirmation) error {
	if c.ApprovedBy == "" {
		return fmt.Errorf("confirmation must name the approving operator")
	}
	if c.At.IsZero() {
		return fmt.Errorf("confirmation must carry an approval timestamp")
	}
	want := Fingerprint(p.Plan)
	if c.PlanFingerprint != want {
		return fmt.Errorf("confirmation does not match this plan (approved %s, plan %s)", short(c.PlanFingerprint), short(want))
	}
	return nil
}

func short(f string) string {
	if len(f) > 12 { return f[:12] }
	return f
}

// Prepare runs the read-only part of the lifecycle: live discovery, state,
// ownership, diff, plan, preflight and executor coverage. It never mutates
// the machine. Readiness here is necessary but not sufficient: confirmation,
// management requirements and the lock are checked at execution time.
func (o Orchestrator) Prepare(cfg *pipeline.Config, opts pipeline.Options) Plan {
	if cfg == nil { cfg = &pipeline.Config{} }
	res := pipeline.Assemble(o.Discover(), cfg, opts)
	p := Plan{
		Discovery: res.Discovery,
		Model:     res.Model,
		Plan:      res.Plan,
		Preflight: res.Preflight,
		Config:    cfg,
	}

	// Executor coverage: every planned action kind must have a registered
	// executor, otherwise the transaction would fail mid-flight after
	// earlier actions already mutated the machine.
	registered := map[state.ActionKind]bool{}
	for kind, ex := range o.Registry.ByKind {
		if ex != nil { registered[kind] = true }
	}
	missing := state.MissingExecutors(p.Plan, registered)
	ok := len(missing) == 0
	p.Preflight.Checks = append(p.Preflight.Checks, state.PreflightCheck{
		Name:     "executor-coverage",
		OK:       ok,
		Critical: true,
		Reason:   coverageReason(missing),
	})
	if !ok {
		p.Preflight.Status = state.PreflightBlocked
		p.Preflight.Blocking = append(p.Preflight.Blocking, "executor-coverage: "+coverageReason(missing))
	}

	// Executor-provided read-only preflight checks (e.g. a service config
	// test): surface configuration-level failures to the operator before any
	// confirmation is asked.
	if blockers := o.executorPreflightBlockers(&p); len(blockers) > 0 {
		p.Preflight.Status = state.PreflightBlocked
		for _, b := range blockers {
			p.Preflight.Checks = append(p.Preflight.Checks, state.PreflightCheck{Name: "executor-preflight", OK: false, Critical: true, Reason: b})
			p.Preflight.Blocking = append(p.Preflight.Blocking, b)
		}
	}

	if p.Plan.Blocked { p.Blockers = append(p.Blockers, p.Plan.BlockReasons...) }
	if p.Preflight.Status != state.PreflightReady { p.Blockers = append(p.Blockers, p.Preflight.Blocking...) }
	p.Ready = !p.Plan.Blocked && p.Preflight.Status == state.PreflightReady
	p.opts = opts
	p.prepared = true
	return p
}

func coverageReason(missing []state.ActionKind) string {
	if len(missing) == 0 { return "all planned action kinds have registered executors" }
	out := "no executor registered for action kind(s)"
	for i, k := range missing {
		if i > 0 { out += "," }
		out += " " + string(k)
	}
	return out
}

// Outcome records one execution attempt. Nil optional fields mean the stage
// was never reached; Stage names the furthest point reached.
type Outcome struct {
	Stage         string
	Blockers      []string
	Transaction   apply.Transaction
	ReDiscovery   *discovery.Result
	FinalValidate *validate.Report
	PersistedPath string
	Persisted     bool
}

// Stage names, ordered by lifecycle position.
const (
	StageBlocked               = "BLOCKED_PRE_MUTATION"
	StageFailedTransaction     = "FAILED_TRANSACTION"
	StageFailedRediscovery     = "FAILED_REDISCOVERY"
	StageFailedFinalValidation = "FAILED_FINAL_VALIDATION"
	StageFailedPersist         = "FAILED_PERSIST"
	StageCompleted             = "COMPLETED"
)

func (o Orchestrator) now() time.Time {
	if o.Now != nil { return o.Now() }
	return time.Now().UTC()
}

func (o Orchestrator) lockPath() string {
	if o.LockPath != "" { return o.LockPath }
	return DefaultLockPath
}

func (o Orchestrator) statePath() string {
	if o.StatePath != "" { return o.StatePath }
	return DefaultStatePath
}

// Execute runs the mutating part of the lifecycle. It refuses to mutate —
// returning a BLOCKED_PRE_MUTATION outcome with zero executor calls — unless
// every fail-closed condition holds:
//
//  1. the plan is ready (preflight READY, plan not blocked, executor coverage);
//  2. a Confirmation matching the exact plan fingerprint is supplied;
//  3. management requirements hold: a plan containing SSH_FINALIZE actions
//     requires a reachable external probe result for every new management
//     port (UNKNOWN/absent probe blocks);
//  4. the machine-local lock is acquired and held for the whole transaction.
//
// On any failure after mutation, the persisted state is NOT updated; the
// engine has already rolled the transaction back, and re-discovery findings
// are reported for the operator.
func (o Orchestrator) Execute(p Plan, c Confirmation, mgmt []probe.Result) (Outcome, error) {
	out := Outcome{}
	if !p.Ready {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, p.Blockers...)
		return out, nil
	}
	// Structural re-checks, independent of the caller's Ready claim: a
	// hand-built or stale Plan must not reach a mutation through Execute.
	if p.Plan.Blocked {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, "plan is blocked: "+strings.Join(p.Plan.BlockReasons, "; "))
		return out, nil
	}
	if p.Preflight.Status != state.PreflightReady {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, "preflight is not ready")
		return out, nil
	}
	registered := map[state.ActionKind]bool{}
	for kind, ex := range o.Registry.ByKind {
		if ex != nil { registered[kind] = true }
	}
	if missing := state.MissingExecutors(p.Plan, registered); len(missing) > 0 {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, "executor-coverage: "+coverageReason(missing))
		return out, nil
	}
	if err := o.Confirm(p, c); err != nil {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, "confirmation: "+err.Error())
		return out, nil
	}
	if blockers := managementBlockers(p.Plan, mgmt); len(blockers) > 0 {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, blockers...)
		return out, nil
	}

	l, err := lock.Acquire(o.lockPath())
	if err != nil {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, "lock: "+err.Error())
		return out, nil
	}
	defer l.Release()

	// Staleness gate: re-discover under the lock and rebuild the plan. If the
	// machine changed since planning, the rebuilt plan differs and the
	// mutation is refused — a stale plan must be regenerated, never applied.
	if p.prepared {
		fresh := pipeline.Assemble(o.Discover(), p.Config, p.opts)
		if Fingerprint(fresh.Plan) != Fingerprint(p.Plan) {
			out.Stage = StageBlocked
			out.Blockers = append(out.Blockers, "plan is stale: the machine changed since planning; regenerate the plan")
			return out, nil
		}
	}

	// Executor preflight checks re-run under the lock: a configuration-level
	// failure that appeared since planning blocks the mutation here.
	if blockers := o.executorPreflightBlockers(&p); len(blockers) > 0 {
		out.Stage = StageBlocked
		out.Blockers = append(out.Blockers, blockers...)
		return out, nil
	}

	// The plan is the source of truth for which actions exist. Bind it into
	// the registry AND into every kind executor that keeps its own action
	// map (ServiceExecutor, FileExecutor, ...): without the binding the
	// executor rejects every action with "no action registry configured".
	actions := map[string]state.Action{}
	for _, a := range p.Plan.Actions {
		actions[a.ID] = a
	}
	reg := o.Registry
	reg.Actions = actions
	bound := map[apply.ActionExecutor]bool{}
	for _, ex := range o.Registry.ByKind {
		if ex == nil || bound[ex] { continue }
		bound[ex] = true
		if binder, ok := ex.(apply.ActionBinder); ok {
			binder.BindActions(actions)
		}
	}

	// The engine re-checks the gate itself; belt and braces.
	tr := (apply.Engine{Executor: reg}).Apply(p.Plan, preflightGate{pf: p.Preflight})
	out.Transaction = tr
	if tr.Status != apply.StatusApplied {
		out.Stage = StageFailedTransaction
		return out, nil
	}

	// Re-discover: the machine is the only source of truth about what the
	// transaction actually did. The plan is never assumed to have worked.
	re := o.Discover()
	out.ReDiscovery = &re
	if re.Status != "OK" {
		out.Stage = StageFailedRediscovery
		out.Blockers = append(out.Blockers, "post-apply discovery status "+re.Status+"; persisted state was not updated")
		return out, nil
	}

	// Effective validation of every action, then a full machine gate.
	for _, a := range p.Plan.Actions {
		if err := reg.Validate(a.ID, a.Resource); err != nil {
			out.Stage = StageFailedFinalValidation
			out.Blockers = append(out.Blockers, a.Resource+": "+err.Error())
			return out, nil
		}
	}
	vr := validate.FromDiscovery(re, validate.Options{})
	out.FinalValidate = &vr
	if vr.Status != validate.StatusPass {
		out.Stage = StageFailedFinalValidation
		out.Blockers = append(out.Blockers, "post-apply validate: "+vr.Status)
		return out, nil
	}

	// Convergence check: rebuild the model against the re-discovered state.
	// Any remaining CREATE/UPDATE/REMOVE diff means the transaction did not
	// take effect and must not be recorded as last-known-good.
	post := pipeline.Assemble(re, p.Config, pipeline.Options{})
	for _, d := range post.Model.Diff {
		if d.Kind == state.Create || d.Kind == state.Update || d.Kind == state.Remove {
			out.Stage = StageFailedFinalValidation
			out.Blockers = append(out.Blockers, "state did not converge: "+d.Resource+" ("+string(d.Kind)+")")
			return out, nil
		}
	}

	// Persist last-known-good state. SaveModel refuses anything that is not
	// verified-good, so a failure here leaves the machine applied but the
	// state file untouched — reported, never silently swallowed.
	m := post.Model
	m.UpdatedAt = o.now()
	if err := state.SaveModel(o.statePath(), m); err != nil {
		out.Stage = StageFailedPersist
		out.Blockers = append(out.Blockers, err.Error())
		return out, nil
	}
	out.Persisted = true
	out.PersistedPath = o.statePath()
	out.Stage = StageCompleted
	return out, nil
}

// executorPreflightBlockers runs the optional read-only preflight checks the
// registered executors provide for the planned actions (e.g. a service
// configuration test) and returns blockers for every failure. Actions of
// kinds whose executors do not implement PreflightChecker pass untouched.
func (o Orchestrator) executorPreflightBlockers(p *Plan) []string {
	var blockers []string
	for _, a := range p.Plan.Actions {
		ex, ok := o.Registry.ByKind[a.Kind]
		if !ok || ex == nil { continue }
		checker, ok := ex.(apply.PreflightChecker)
		if !ok { continue }
		if err := checker.PreflightCheck(a); err != nil {
			blockers = append(blockers, fmt.Sprintf("executor preflight %s: %v", a.Resource, err))
		}
	}
	return blockers
}

// requiredManagementPorts collects the new management ports of all SSH
// finalize actions in the plan. Regular changes (including staged SSH
// migration) do not require the probe: the old listener stays up and
// rollback exists.
func requiredManagementPorts(p state.Plan) []int {
	var ports []int
	for _, a := range p.Actions {
		if a.Kind != state.ActionSSHFinalize || a.Spec == nil || a.Spec.SSH == nil { continue }
		if port := a.Spec.SSH.NewPort; port > 0 {
			found := false
			for _, have := range ports {
				if have == port { found = true; break }
			}
			if !found { ports = append(ports, port) }
		}
	}
	return ports
}

func managementBlockers(p state.Plan, results []probe.Result) []string {
	ports := requiredManagementPorts(p)
	if len(ports) == 0 { return nil }
	var blockers []string
	for _, port := range ports {
		satisfied := false
		for _, r := range results {
			if r.Endpoint.Port == port && r.Reachable {
				satisfied = true
				break
			}
		}
		if !satisfied {
			blockers = append(blockers, fmt.Sprintf("management probe is mandatory for SSH finalization: no reachable probe result for new management port %d", port))
		}
	}
	return blockers
}

// preflightGate adapts a prepared Preflight to the engine's gate interface.
type preflightGate struct{ pf state.Preflight }

func (g preflightGate) Ready() bool { return g.pf.Status == state.PreflightReady }
func (g preflightGate) Reasons() []string { return g.pf.Blocking }
