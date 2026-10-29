package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osUser "os/user"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// The apply command is the only CLI path into the orchestration layer, and
// this build is restricted to the FIRST PRODUCTION EXPERIMENT: repairing
// fail2ban.service on the local machine. firstExperimentGuard enforces the
// pinned plan shape; the registry below only contains the SERVICE executor,
// so any other action kind is a coverage failure. General real apply remains
// unavailable until the experiment pin is deliberately widened.

const firstExperimentResource = "service.fail2ban.service"

const confirmHint = "confirmation refused: type the first 12 characters of the plan fingerprint to approve this exact plan"

func firstExperimentConfig() *pipeline.Config {
	yes := true
	return &pipeline.Config{
		Desired:   &state.Desired{Services: []state.ServiceDesired{{Name: "fail2ban.service", Active: &yes}}},
		Ownership: map[string]state.Ownership{"service.fail2ban.service": state.Owned},
	}
}

// firstExperimentGuard pins the CLI to the first production experiment: the
// plan must be exactly one owned service restart for fail2ban.service.
func firstExperimentGuard(p orchestrate.Plan) error {
	if len(p.Plan.Actions) != 1 {
		return fmt.Errorf("experiment allows exactly one action, plan has %d", len(p.Plan.Actions))
	}
	a := p.Plan.Actions[0]
	if a.Kind != state.ActionService {
		return fmt.Errorf("experiment action kind is %s, want SERVICE", a.Kind)
	}
	if a.Resource != firstExperimentResource {
		return fmt.Errorf("experiment resource is %q, want %q", a.Resource, firstExperimentResource)
	}
	if a.Spec == nil || a.Spec.Service == nil {
		return fmt.Errorf("experiment action has no service spec")
	}
	if a.Spec.Service.Name != "fail2ban.service" {
		return fmt.Errorf("experiment unit is %q, want fail2ban.service", a.Spec.Service.Name)
	}
	if a.Spec.Service.Operation != "restart" {
		return fmt.Errorf("experiment operation is %q, want restart", a.Spec.Service.Operation)
	}
	if a.Spec.Service.ExpectedState != "active" {
		return fmt.Errorf("experiment expected state is %q, want active", a.Spec.Service.ExpectedState)
	}
	if a.Ownership != state.Owned {
		return fmt.Errorf("experiment ownership is %q, want OWNED", a.Ownership)
	}
	return nil
}

// acquireFixedHostIdentity observes the machine's canonical host identity
// from the fixed local source (/etc/machine-id, through the discovery
// collector — the same acquisition the discovery layer uses) and fails
// closed on everything else: the hostname is never a substitute, and a
// hostless journal record can never corroborate. /etc/machine-id is never
// initialized or repaired here.
func acquireFixedHostIdentity() (string, error) {
	obs := (&discovery.Collector{}).AcquireMachineID()
	switch obs.Status {
	case discovery.MachineIDPresent:
		return obs.HostIdentity, nil
	case discovery.MachineIDAbsent:
		return "", errors.New("host identity absent: /etc/machine-id does not exist on this machine (failing closed; the file is never initialized or repaired automatically)")
	case discovery.MachineIDInvalid:
		return "", errors.New("host identity invalid: /etc/machine-id is not a canonical 32-hex machine-id (failing closed)")
	default:
		return "", errors.New("host identity unreadable: /etc/machine-id exists but cannot be read (failing closed)")
	}
}

func defaultApplyOrchestrator(timeout time.Duration) *orchestrate.Orchestrator {
	return &orchestrate.Orchestrator{
		Discover: func() discovery.Result {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return discovery.New().Discover(ctx)
		},
		Registry: apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionService: &apply.ServiceExecutor{},
		}},
		LockPath:  orchestrate.DefaultLockPath,
		StatePath: orchestrate.DefaultStatePath,
		Journal:   journal.Default(),
		// G4-A (ZAI-112): the journal host identity is acquired from the
		// fixed local source (/etc/machine-id through the discovery
		// collector — the same acquisition the discovery layer uses), never
		// from configuration, persisted state, plan ownership labels or
		// caller input. Absent, invalid and unreadable identities fail
		// closed before Journal.Begin; /etc/machine-id is never initialized
		// or repaired here.
		AcquireHostIdentity: acquireFixedHostIdentity,
	}
}

// runApply implements `vps-gateway apply`. The o parameter is injectable for
// tests; production passes nil for the default wiring above. The flow is the
// orchestration lifecycle: Prepare (read-only) → experiment guard → show the
// exact plan and its fingerprint → explicit operator confirmation → Execute.
// `--dry-run` stops after showing the plan, before any confirmation.
func runApply(args []string, o *orchestrate.Orchestrator, stdin io.Reader, stdout, stderr io.Writer) int {
	return runApplyWith(args, o, pipeline.Options{}, stdin, stdout, stderr)
}

// runApplyWith additionally takes the pipeline options (root override for
// tests; production detects the real euid).
func runApplyWith(args []string, o *orchestrate.Orchestrator, opts pipeline.Options, stdin io.Reader, stdout, stderr io.Writer) int {
	timeout, rest := parseTimeout(args)
	dryRun := false
	observeReport := false
	configPath, confirmPrefix := "", ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--dry-run":
			dryRun = true
		case "--observe-service-report":
			observeReport = true
		case "--config":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--config requires a file path")
				return 2
			}
			i++
			configPath = rest[i]
		case "--confirm":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--confirm requires the plan fingerprint prefix")
				return 2
			}
			i++
			confirmPrefix = rest[i]
		default:
			fmt.Fprintf(stderr, "unknown apply flag %q\nusage: vps-gateway apply [--dry-run] [--config FILE] [--confirm PREFIX] [--observe-service-report] [--timeout DURATION]\n", rest[i])
			return 2
		}
	}

	cfg := firstExperimentConfig()
	if configPath != "" {
		b, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Fprintln(stderr, "read config:", err)
			return 1
		}
		parsed, err := pipeline.ParseConfig(b)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		cfg = parsed
	}

	if o == nil {
		o = defaultApplyOrchestrator(timeout)
	}
	// --observe-service-report (ZAI-119): opt-in report-only observation.
	// The flag ONLY adds diagnostics around the already-authorized engine
	// attempt — it never authorizes or initiates execution, and the
	// production default stays nil (no flag → no observer).
	wireServiceObservation(o, observeReport)
	// Lifecycle paths (state and lock) are deliberately not caller-
	// configurable: no CLI flag may redirect them, so every apply run uses
	// the compiled project locations (/etc/vps-gateway/state.json via
	// defaultApplyOrchestrator, and the compiled lock identity) and cannot
	// redirect lifecycle writes by choosing another destination. Tests
	// isolate through the Orchestrator struct.

	// Phase 1-6: read-only planning on the live machine.
	p := o.Prepare(cfg, opts)
	if !p.Ready {
		fmt.Fprintln(stderr, "apply blocked before mutation:")
		for _, b := range p.Blockers {
			fmt.Fprintln(stderr, "  - "+b)
		}
		return 3
	}
	// Scenario guard: this build executes only the first production experiment.
	// ZAI-124 addendum: a CONVERGED plan (the desired state already matches
	// the machine — zero actions, the ZAI-123 live finding on a healthy
	// fail2ban) is an informational NO_CHANGE on the dry-run path, not a
	// failed operation. The mutation path keeps the guard refusal intact:
	// firstExperimentGuard is not weakened where it gates execution.
	if err := firstExperimentGuard(p); err != nil {
		if dryRun && len(p.Plan.Actions) == 0 {
			fmt.Fprintln(stdout, "NO_CHANGE: the desired state already matches the machine and no plan actions were produced (converged plan); nothing to confirm or execute.")
			if observeReport {
				fmt.Fprintln(stdout, "service observation skipped: a converged plan produces no engine attempt to observe.")
			}
			return 0
		}
		fmt.Fprintln(stderr, "apply restricted to the first production experiment:", err)
		return 3
	}

	fp := orchestrate.Fingerprint(p.Plan)
	a := p.Plan.Actions[0]
	fmt.Fprintf(stdout, "vps-gateway apply — host: %s\n", p.Discovery.Host.Hostname)
	fmt.Fprintf(stdout, "Plan fingerprint: %s\n", fp)
	fmt.Fprintf(stdout, "Actions:\n")
	fmt.Fprintf(stdout, "  [1] %s %s — %s %s (expected %s), %s, risk %s\n",
		a.Kind, a.Resource, a.Spec.Service.Operation, a.Spec.Service.Name, a.Spec.Service.ExpectedState, a.Ownership, a.Risk)
	fmt.Fprintf(stdout, "Preflight: %s\n", p.Preflight.Status)

	if dryRun {
		fmt.Fprintln(stdout, "DRY-RUN: stopping before confirmation; nothing was asked of the operator and nothing can execute.")
		if observeReport {
			fmt.Fprintln(stdout, "service observation skipped: --dry-run never observes (no snapshot is taken and nothing executes)")
		}
		return 0
	}

	// Phase 7: explicit, unambiguous operator confirmation. The operator
	// types the fingerprint prefix of the exact plan shown above; a yes/no
	// answer would be ambiguous and is deliberately not accepted.
	var typed string
	if confirmPrefix != "" {
		typed = confirmPrefix
	} else {
		fmt.Fprintln(stdout, "This will APPLY the plan above to this machine.")
		fmt.Fprint(stdout, "Type the first 12 characters of the plan fingerprint to approve (anything else aborts): ")
		reader := bufio.NewReader(stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(stderr, confirmHint)
			return 2
		}
		typed = line
	}
	typed = strings.ToLower(strings.TrimSpace(typed))
	if len(typed) < 12 || !strings.HasPrefix(fp, typed) {
		fmt.Fprintln(stderr, confirmHint)
		return 2
	}

	conf := orchestrate.Confirmation{PlanFingerprint: fp, ApprovedBy: operatorName(), At: time.Now().UTC()}

	// Phase 8-13: lock, transaction, re-discovery, final validation,
	// convergence, persistence — all inside the orchestrator.
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Stage: %s\n", out.Stage)
	// Surface the concrete action error(s): "Stage: FAILED_TRANSACTION" alone
	// hides why the transaction failed (e.g. systemctl restart output).
	for _, ar := range out.Transaction.Actions {
		if ar.Error != "" {
			fmt.Fprintf(stderr, "  %s [%s]: %s\n", ar.Resource, ar.Status, ar.Error)
		}
	}
	if len(out.Blockers) > 0 {
		for _, b := range out.Blockers {
			fmt.Fprintln(stderr, "  - "+b)
		}
	}
	if out.ReDiscovery != nil {
		fmt.Fprintf(stdout, "Re-discovery: %s\n", out.ReDiscovery.Status)
	}
	if out.FinalValidate != nil {
		fmt.Fprintf(stdout, "Final validation: %s\n", out.FinalValidate.Status)
	}
	fmt.Fprintf(stdout, "Persisted last-known-good state: %v\n", out.Persisted)
	// Report-only SERVICE observation (ZAI-115/119): surface the diagnostic
	// when an observer was configured for this run. Without the opt-in flag
	// the production wiring never configures one, so this block is inert on
	// the default path; it never influences the exit code or any other
	// decision. The verdict classes are stated as FACTS; nothing here ever
	// claims that the restart command caused an invocation change.
	if obs := out.ServiceObservation; obs != nil {
		fmt.Fprintf(stdout, "Service observation (report-only): resource=%s unit=%s transaction=%s attempt_applied=%v\n",
			obs.Resource, obs.Unit, obs.TransactionID, obs.AttemptApplied)
		for _, side := range []struct {
			name string
			o    *serviceobs.Observation
		}{{"before", obs.Before}, {"after", obs.After}} {
			if side.o == nil {
				fmt.Fprintf(stdout, "  %s: unavailable (see notes)\n", side.name)
				continue
			}
			fmt.Fprintf(stdout, "  %s: LoadState=%q ActiveState=%q SubState=%q MainPID=%q InvocationID=%q\n",
				side.name, side.o.LoadState, side.o.ActiveState, side.o.SubState, side.o.MainPID, side.o.InvocationID)
		}
		fmt.Fprintf(stdout, "  verdict: %s — %s\n", obs.Verdict, observationVerdictMeaning(obs.Verdict))
		for _, n := range obs.Notes {
			fmt.Fprintf(stdout, "  note: %s\n", n)
		}
		for _, r := range obs.VerdictReasons {
			fmt.Fprintf(stdout, "  %s\n", r)
		}
		fmt.Fprintf(stdout, "  window: %s\n", obs.Window)
	}

	switch out.Stage {
	case orchestrate.StageCompleted:
		if len(out.Blockers) > 0 {
			// The transaction completed but journal finalization failed:
			// report the run as unsuccessful instead of clean success.
			return 3
		}
		return 0
	case orchestrate.StageBlocked:
		// Fail-closed by the orchestrator (confirmation mismatch, staleness,
		// lock, ...) — a blocked run is a failure of the run, not of input.
		return 3
	default:
		return 3
	}
}

func operatorName() string {
	if u, err := osUser.Current(); err == nil && u.Username != "" {
		return "cli:" + u.Username
	}
	return "cli:unknown"
}

// observationVerdictMeaning states, per closed vocabulary class, exactly
// what the comparison established — and what it did not. Causality is
// never claimed: the observer sees machine state, not the act.
func observationVerdictMeaning(v serviceobs.InvocationEvidence) string {
	switch v {
	case serviceobs.InvocationObserved:
		return "a new unit invocation was established between the snapshots; the observation does not establish that the restart command caused it"
	case serviceobs.NoNewInvocation:
		return "no new invocation: both snapshots carry the same well-formed InvocationID"
	case serviceobs.MainProcessChanged:
		return "the main process was replaced; this does not prove a unit restart (an in-invocation MAINPID handoff looks the same)"
	case serviceobs.InvocationUnprovable, serviceobs.InvocationNotProven, serviceobs.NotComparable:
		return "insufficient evidence to answer the invocation question"
	case "":
		return "no comparison was performed (see notes)"
	default:
		return "unknown verdict"
	}
}

// wireServiceObservation installs the reference read-only observer when
// --observe-service-report was requested and the orchestrator does not
// already carry one (an injected orchestrator keeps its own). It uses the
// existing reference path only — ObserveServiceFromRunner over
// ProductionCommandRunner (exec.CommandContext, fixed read-only argv) —
// and the orchestrate report-only window around Engine.Apply; no second
// implementation exists. Eligibility stays the orchestrate-side pin: the
// single SERVICE action on service.fail2ban.service, observed only after
// every authorization, preflight and journal gate has passed.
func wireServiceObservation(o *orchestrate.Orchestrator, requested bool) {
	if !requested || o.ObserveService != nil {
		return
	}
	o.ObserveService = orchestrate.ObserveServiceFromRunner(serviceobs.ProductionCommandRunner)
}
