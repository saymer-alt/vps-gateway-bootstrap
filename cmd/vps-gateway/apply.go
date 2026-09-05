package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	osUser "os/user"
	"os"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
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
	configPath, statePath, lockPath, confirmPrefix := "", "", "", ""
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--dry-run":
			dryRun = true
		case "--config":
			if i+1 >= len(rest) { fmt.Fprintln(stderr, "--config requires a file path"); return 2 }
			i++
			configPath = rest[i]
		case "--state":
			if i+1 >= len(rest) { fmt.Fprintln(stderr, "--state requires a file path"); return 2 }
			i++
			statePath = rest[i]
		case "--lock":
			if i+1 >= len(rest) { fmt.Fprintln(stderr, "--lock requires a file path"); return 2 }
			i++
			lockPath = rest[i]
		case "--confirm":
			if i+1 >= len(rest) { fmt.Fprintln(stderr, "--confirm requires the plan fingerprint prefix"); return 2 }
			i++
			confirmPrefix = rest[i]
		default:
			fmt.Fprintf(stderr, "unknown apply flag %q\nusage: vps-gateway apply [--dry-run] [--config FILE] [--confirm PREFIX] [--timeout DURATION]\n", rest[i])
			return 2
		}
	}

	cfg := firstExperimentConfig()
	if configPath != "" {
		b, err := os.ReadFile(configPath)
		if err != nil { fmt.Fprintln(stderr, "read config:", err); return 1 }
		parsed, err := pipeline.ParseConfig(b)
		if err != nil { fmt.Fprintln(stderr, err); return 1 }
		cfg = parsed
	}

	if o == nil {
		o = defaultApplyOrchestrator(timeout)
	}
	if statePath != "" { o.StatePath = statePath }
	if lockPath != "" { o.LockPath = lockPath }

	// Phase 1-6: read-only planning on the live machine.
	p := o.Prepare(cfg, opts)
	if !p.Ready {
		fmt.Fprintln(stderr, "apply blocked before mutation:")
		for _, b := range p.Blockers { fmt.Fprintln(stderr, "  - "+b) }
		return 3
	}
	// Scenario guard: this build executes only the first production experiment.
	if err := firstExperimentGuard(p); err != nil {
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
		for _, b := range out.Blockers { fmt.Fprintln(stderr, "  - "+b) }
	}
	if out.ReDiscovery != nil {
		fmt.Fprintf(stdout, "Re-discovery: %s\n", out.ReDiscovery.Status)
	}
	if out.FinalValidate != nil {
		fmt.Fprintf(stdout, "Final validation: %s\n", out.FinalValidate.Status)
	}
	fmt.Fprintf(stdout, "Persisted last-known-good state: %v\n", out.Persisted)

	switch out.Stage {
	case orchestrate.StageCompleted:
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
