// Command fileexperiment is a pinned experiment PLANNING tool: it executes
// the read-only part of the orchestration lifecycle (discovery → config →
// diff → plan → fingerprint → preview) for a SINGLE bootstrap-owned file —
// /etc/vps-gateway/experiment-file-test.conf — and nothing else.
//
// MUTATION IS INTENTIONALLY DISABLED (2026-09-29 containment, CODEX TASK-02):
// the experiment's embedded legacy OWNED label plus its shape-only guard
// never established ownership provenance, so an unproven foreign file at the
// pinned target could reach the executor and be replaced (P1-A data flow,
// narrowly reachable). Until ownership admission (O5/O6) exists, this tool
// must not reach mutating execution: no confirmation, no orchestrate.Execute,
// no lock, journal, backup, or state writes. It remains useful for:
//
//   - exercising discovery;
//   - producing a candidate Plan and its fingerprint;
//   - showing what WOULD have been changed (--dry-run / any run);
//   - testing PURE ownership work later;
//   - reproducing the foreign-file collision safely.
//
// It is NOT part of the production CLI registry: cmd/vps-gateway remains
// pinned to the first production experiment (fail2ban repair).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

const (
	experimentContent = "vps-gateway file experiment\n"
	experimentMode    = 0600
	// containmentNotice is the operator-facing refusal: mutation in this
	// tool is disabled on purpose, pending ownership provenance (P1-A).
	containmentNotice = "mutation is disabled in this tool pending ownership provenance (P1-A containment): it is planning/preview only and executed nothing"
)

func experimentPath(root string) string {
	return filepath.Join(root, "etc", "vps-gateway", "experiment-file-test.conf")
}

func experimentConfig(root string) *pipeline.Config {
	return &pipeline.Config{
		Desired: &state.Desired{Files: []state.FileDesired{{
			Path:    experimentPath(root),
			Content: experimentContent,
			Mode:    experimentMode,
		}}},
		Ownership: map[string]state.Ownership{
			"file." + experimentPath(root): state.Owned,
		},
	}
}

// fileExperimentGuard pins the plan to exactly one action: create or update
// the experiment file with the pinned content, mode and ownership, inside
// the bootstrap-owned directory. Any second action or deviation aborts.
func fileExperimentGuard(p orchestrate.Plan, root string) error {
	if len(p.Plan.Actions) != 1 {
		return fmt.Errorf("experiment allows exactly one action, plan has %d", len(p.Plan.Actions))
	}
	a := p.Plan.Actions[0]
	if a.Kind != state.ActionCreateFile && a.Kind != state.ActionUpdateFile {
		return fmt.Errorf("experiment action kind is %s, want CREATE_FILE or UPDATE_FILE", a.Kind)
	}
	if a.Resource != "file."+experimentPath(root) {
		return fmt.Errorf("experiment resource is %q, want %q", a.Resource, "file."+experimentPath(root))
	}
	if a.Spec == nil || a.Spec.File == nil {
		return fmt.Errorf("experiment action has no file spec")
	}
	if a.Spec.File.Path != experimentPath(root) {
		return fmt.Errorf("experiment file path is %q", a.Spec.File.Path)
	}
	if a.Spec.File.Content != experimentContent {
		return fmt.Errorf("experiment file content deviates from the pinned experiment")
	}
	if a.Spec.File.Mode != experimentMode {
		return fmt.Errorf("experiment file mode is %o, want %o", a.Spec.File.Mode, experimentMode)
	}
	if a.Ownership != state.Owned {
		return fmt.Errorf("experiment ownership is %q, want OWNED", a.Ownership)
	}
	return nil
}

func newExperimentOrchestrator(timeout time.Duration, root string) *orchestrate.Orchestrator {
	fileExecutor := &apply.FileExecutor{Root: root}
	return &orchestrate.Orchestrator{
		Discover: func() discovery.Result {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return discovery.New().Discover(ctx)
		},
		Registry: apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionCreateFile:      fileExecutor,
			state.ActionUpdateFile:      fileExecutor,
			state.ActionDeleteOwnedFile: fileExecutor,
		}},
		LockPath:  orchestrate.DefaultLockPath,
		StatePath: orchestrate.DefaultStatePath,
		Journal:   journal.Default(),
	}
}

// runFileExperiment implements the pinned PLANNING lifecycle. The o
// parameter is injectable for tests; production passes nil. opts carries
// pipeline options: production passes the zero value, so the privilege fact
// is detected from the current process; tests pass an explicit Root.
//
// Containment: the function NEVER reaches orchestrate.Execute — every run
// ends in the read-only preview plus the containment refusal. The registry
// stays wired only because Prepare's executor-coverage check needs it to
// produce a Ready plan.
func runFileExperiment(args []string, o *orchestrate.Orchestrator, opts pipeline.Options, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdin // the confirmation reader is gone: nothing is ever executed
	timeout := 60 * time.Second
	root := "/"
	dryRun := false
	rest := args
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--dry-run":
			dryRun = true
		case "--confirm":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--confirm requires a value")
				return 2
			}
			i++
			fmt.Fprintln(stderr, "--confirm is refused: "+containmentNotice)
			return 2
		case "--root":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--root requires a path")
				return 2
			}
			i++
			root = rest[i]
		case "--timeout":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--timeout requires a duration")
				return 2
			}
			i++
			d, err := time.ParseDuration(rest[i])
			if err != nil || d <= 0 {
				fmt.Fprintln(stderr, "invalid --timeout", rest[i])
				return 2
			}
			timeout = d
		default:
			fmt.Fprintf(stderr, "unknown flag %q\n", rest[i])
			return 2
		}
	}

	if o == nil {
		o = newExperimentOrchestrator(timeout, root)
	}

	// Read-only planning on the live machine, including the file inspection.
	p := o.Prepare(experimentConfig(root), opts)
	if !p.Ready {
		fmt.Fprintln(stderr, "experiment blocked before mutation:")
		for _, b := range p.Blockers {
			fmt.Fprintln(stderr, "  - "+b)
		}
		return 3
	}
	// Already converged: the file matches the desired content, so the
	// experiment has nothing left to do.
	if len(p.Plan.Actions) == 0 {
		fmt.Fprintln(stdout, "Experiment already converged: the file matches the desired content, no actions required.")
		return 0
	}

	if err := fileExperimentGuard(p, root); err != nil {
		fmt.Fprintln(stderr, "experiment guard:", err)
		return 3
	}

	fp := orchestrate.Fingerprint(p.Plan)
	a := p.Plan.Actions[0]
	fmt.Fprintf(stdout, "vps-gateway file experiment — host: %s\n", p.Discovery.Host.Hostname)
	fmt.Fprintf(stdout, "Plan fingerprint: %s\n", fp)
	fmt.Fprintf(stdout, "Actions:\n")
	fmt.Fprintf(stdout, "  [1] %s %s (mode %o), %s, risk %s\n", a.Kind, a.Resource, a.Spec.File.Mode, a.Ownership, a.Risk)
	fmt.Fprintf(stdout, "Preflight: %s\n", p.Preflight.Status)

	if dryRun {
		fmt.Fprintln(stdout, "DRY-RUN: stopped before the (disabled) execution boundary; nothing was executed.")
		return 0
	}
	fmt.Fprintln(stdout, "This is where the experiment used to ask for confirmation and execute. It no longer does.")
	fmt.Fprintln(stdout, "CONTAINMENT: "+containmentNotice+".")
	return 3
}

func main() {
	code := runFileExperiment(os.Args[1:], nil, pipeline.Options{}, os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}
