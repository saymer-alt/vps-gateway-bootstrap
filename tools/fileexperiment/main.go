// Command fileexperiment is a one-off pinned experiment runner: it executes
// the full orchestration lifecycle for a SINGLE bootstrap-owned file —
// /etc/vps-gateway/experiment-file-test.conf — on the local machine.
//
// Constraints baked into this tool:
//   - the plan must contain exactly one CREATE/UPDATE action for the pinned
//     path with the pinned content and mode; anything else aborts;
//   - the path must stay inside /etc/vps-gateway/ (bootstrap-owned per
//     docs/ownership.md);
//   - execution requires typing the plan fingerprint prefix;
//   - --dry-run stops after showing the plan, before any confirmation.
//
// It is NOT part of the production CLI registry: cmd/vps-gateway remains
// pinned to the first production experiment (fail2ban repair).
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

const (
	experimentContent = "vps-gateway file experiment\n"
	experimentMode    = 0600
	confirmHint       = "confirmation refused: type the first 12 characters of the plan fingerprint to approve this exact plan"
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
	}
}

// runFileExperiment implements the pinned lifecycle. The o parameter is
// injectable for tests; production passes nil. opts carries pipeline
// options: production passes the zero value, so the privilege fact is
// detected from the current process; tests pass an explicit Root.
func runFileExperiment(args []string, o *orchestrate.Orchestrator, opts pipeline.Options, stdin io.Reader, stdout, stderr io.Writer) int {
	timeout := 60 * time.Second
	root := "/"
	dryRun := false
	confirmPrefix := ""
	rest := args
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--dry-run":
			dryRun = true
		case "--confirm":
			if i+1 >= len(rest) {
				fmt.Fprintln(stderr, "--confirm requires the plan fingerprint prefix")
				return 2
			}
			i++
			confirmPrefix = rest[i]
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
		fmt.Fprintln(stdout, "DRY-RUN: stopping before confirmation; nothing was asked of the operator and nothing can execute.")
		return 0
	}

	var typed string
	if confirmPrefix != "" {
		typed = confirmPrefix
	} else {
		fmt.Fprintln(stdout, "This will WRITE the file shown above on this machine.")
		fmt.Fprint(stdout, "Type the first 12 characters of the plan fingerprint to approve (anything else aborts): ")
		line, err := bufio.NewReader(stdin).ReadString('\n')
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

	conf := orchestrate.Confirmation{PlanFingerprint: fp, ApprovedBy: "cli-experiment", At: time.Now().UTC()}
	out, err := o.Execute(p, conf, nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Stage: %s\n", out.Stage)
	for _, ar := range out.Transaction.Actions {
		if ar.Error != "" {
			fmt.Fprintf(stderr, "  %s [%s]: %s\n", ar.Resource, ar.Status, ar.Error)
		}
	}
	for _, b := range out.Blockers {
		fmt.Fprintln(stderr, "  - "+b)
	}
	if out.ReDiscovery != nil {
		fmt.Fprintf(stdout, "Re-discovery: %s\n", out.ReDiscovery.Status)
	}
	fmt.Fprintf(stdout, "Persisted last-known-good state: %v\n", out.Persisted)

	if out.Stage == orchestrate.StageCompleted {
		return 0
	}
	return 3
}

func main() {
	code := runFileExperiment(os.Args[1:], nil, pipeline.Options{}, os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}
