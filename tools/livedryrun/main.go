// Command livedryrun is a strictly read-only development tool. It runs the
// orchestration Prepare() phase against the LIVE machine with the first-apply
// desired state (fail2ban repair) and prints the resulting plan.
//
// It contains no mutation path:
//
//   - Execute is never called;
//   - no Confirmation is created (Confirm with an empty one must be rejected);
//   - no lock is acquired (Prepare does not touch the lock);
//   - no state is persisted (SaveModel is never called);
//   - every executor method is a guarded no-op that records the call and
//     fails: if anything ever reached an executor, the run reports it and
//     exits non-zero.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// guardExecutor proves by construction that the dry-run never reaches an
// executor: every call is recorded and refused.
type guardExecutor struct{ calls []string }

func (g *guardExecutor) record(what, id, resource string) error {
	g.calls = append(g.calls, what+":"+resource)
	return fmt.Errorf("mutation guard: %s must not be called during a dry-run", what)
}

func (g *guardExecutor) Backup(id, resource string) error                { return g.record("backup", id, resource) }
func (g *guardExecutor) Apply(id, resource, kind string) error           { return g.record("apply", id, resource) }
func (g *guardExecutor) Validate(id, resource string) error              { return g.record("validate", id, resource) }
func (g *guardExecutor) Rollback(id, resource string) error              { return g.record("rollback", id, resource) }

// defaultConfig is byte-equivalent to the config block of
// tests/fixtures/first-apply-saymer3.json: the minimal desired state for the
// first intended apply. Nothing else is desired; nothing else may change.
func defaultConfig() *pipeline.Config {
	yes := true
	return &pipeline.Config{
		Desired:   &state.Desired{Services: []state.ServiceDesired{{Name: "fail2ban.service", Active: &yes}}},
		Ownership: map[string]state.Ownership{"service.fail2ban.service": state.Owned},
	}
}

func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }

type report struct {
	Host        string             `json:"host"`
	GeneratedAt time.Time          `json:"generated_at"`
	Plan        orchestrate.Plan   `json:"plan"`
	Invariants  invariants         `json:"invariants"`
}

type invariants struct {
	ExecutorCalls      []string `json:"executor_calls"`
	ConfirmRejected    bool     `json:"confirm_rejected_by_empty_confirmation"`
	LockFileAfterRun   bool     `json:"lock_file_present_after_run"`
	StateFileBeforeRun bool     `json:"state_file_present_before_run"`
	StateFileAfterRun  bool     `json:"state_file_present_after_run"`
}

func main() {
	timeout := flag.Duration("timeout", 60*time.Second, "timeout for every discovery command")
	configPath := flag.String("config", "", "bootstrap config JSON (default: embedded fail2ban first-apply config)")
	lockPath := flag.String("lock-path", orchestrate.DefaultLockPath, "report-only: lock path whose existence is checked")
	statePath := flag.String("state-path", orchestrate.DefaultStatePath, "report-only: state path whose existence is checked")
	flag.Parse()

	cfg := defaultConfig()
	if *configPath != "" {
		b, err := os.ReadFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read config:", err)
			os.Exit(1)
		}
		parsed, err := pipeline.ParseConfig(b)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cfg = parsed
	}

	guard := &guardExecutor{}
	o := orchestrate.Orchestrator{
		Discover: func() discovery.Result {
			ctx, cancel := context.WithTimeout(context.Background(), *timeout)
			defer cancel()
			return discovery.New().Discover(ctx)
		},
		// Only the executor kinds the first apply would need are registered;
		// if the live plan produced any other kind, executor coverage would
		// fail honestly instead of silently passing.
		Registry:  apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: guard}},
		LockPath:  *lockPath,
		StatePath: *statePath,
	}

	stateBefore := fileExists(*statePath)
	p := o.Prepare(cfg, pipeline.Options{})
	stateAfter := fileExists(*statePath)

	rep := report{
		Host:        p.Discovery.Host.Hostname,
		GeneratedAt: time.Now().UTC(),
		Plan:        p,
		Invariants: invariants{
			ExecutorCalls:      guard.calls,
			LockFileAfterRun:   fileExists(*lockPath),
			StateFileBeforeRun: stateBefore,
			StateFileAfterRun:  stateAfter,
		},
	}
	// Proof that without a real confirmation nothing could execute: the empty
	// confirmation must be rejected.
	if err := o.Confirm(p, orchestrate.Confirmation{}); err != nil {
		rep.Invariants.ConfirmRejected = true
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "livedryrun: host=%s ready=%v blockers=%v executorCalls=%d\n",
		rep.Host, p.Ready, p.Blockers, len(guard.calls))

	switch {
	case len(guard.calls) != 0:
		os.Exit(1) // a dry-run that reached an executor is a broken dry-run
	case !p.Ready:
		os.Exit(3)
	}
}
