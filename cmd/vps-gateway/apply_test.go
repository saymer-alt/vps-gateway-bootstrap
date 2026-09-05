package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// CLI tests for `vps-gateway apply`. All of them run against an injected
// orchestrator with fake discovery and a recording executor — no real VPS is
// touched, and Execute is only ever reached against fakes.

type cliRecordingExecutor struct {
	calls     []string
	failApply bool
}

func (e *cliRecordingExecutor) Backup(id, resource string) error {
	e.calls = append(e.calls, "backup:"+resource); return nil
}
func (e *cliRecordingExecutor) Apply(id, resource, kind string) error {
	e.calls = append(e.calls, "apply:"+resource)
	if e.failApply { return errors.New("apply failed") }
	return nil
}
func (e *cliRecordingExecutor) Validate(id, resource string) error {
	e.calls = append(e.calls, "validate:"+resource); return nil
}
func (e *cliRecordingExecutor) Rollback(id, resource string) error {
	e.calls = append(e.calls, "rollback:"+resource); return nil
}

func loadSaymer3Discovery(t *testing.T) discovery.Result {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "first-apply-saymer3.json"))
	if err != nil { t.Fatal(err) }
	var scenario struct {
		Discovery discovery.Result `json:"discovery"`
	}
	if err := json.Unmarshal(raw, &scenario); err != nil { t.Fatal(err) }
	return scenario.Discovery
}

func repairedSaymer3Discovery(t *testing.T) discovery.Result {
	t.Helper()
	d := loadSaymer3Discovery(t)
	services := make([]discovery.Service, len(d.Services))
	copy(services, d.Services)
	for i := range services {
		if services[i].Name == "fail2ban.service" {
			services[i].Active = true
			services[i].SubState = "running"
		}
	}
	d.Services = services
	return d
}

func writeApplyConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	b, err := json.Marshal(cfg)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, b, 0600); err != nil { t.Fatal(err) }
	return path
}

func experimentConfig(t *testing.T) string {
	return writeApplyConfig(t, map[string]any{
		"desired":   map[string]any{"services": []map[string]any{{"name": "fail2ban.service", "active": true}}},
		"ownership": map[string]any{"service.fail2ban.service": "OWNED"},
	})
}

func rootOpts() pipeline.Options {
	yes := true
	return pipeline.Options{Root: &yes}
}

func applyTestOrchestrator(t *testing.T, states []discovery.Result, reg apply.Registry) (*orchestrate.Orchestrator, *cliRecordingExecutor, *int) {
	rec := &cliRecordingExecutor{}
	calls := 0
	o := &orchestrate.Orchestrator{
		Discover: func() discovery.Result {
			if calls >= len(states) { calls++; return states[len(states)-1] }
			r := states[calls]; calls++; return r
		},
		Registry:  reg,
		LockPath:  filepath.Join(t.TempDir(), "apply.lock"),
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Now:       func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) },
	}
	return o, rec, &calls
}

func fingerprintPrefix(t *testing.T, p orchestrate.Plan) string {
	t.Helper()
	return orchestrate.Fingerprint(p.Plan)[:12]
}

// The control run: --dry-run shows the exact plan and its fingerprint, then
// stops before any confirmation. Nothing can execute.
func TestApplyDryRunStopsBeforeConfirmation(t *testing.T) {
	o, rec, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}}})
	var out bytes.Buffer
	code := runApply([]string{"--dry-run", "--config", experimentConfig(t)}, o, strings.NewReader(""), &out, &out)
	if code != 0 { t.Fatalf("exit=%d output=%s", code, out.String()) }
	if len(rec.calls) != 0 { t.Fatalf("dry-run performed executor calls: %v", rec.calls) }
	if !strings.Contains(out.String(), "Plan fingerprint:") || !strings.Contains(out.String(), "SERVICE service.fail2ban.service") {
		t.Fatalf("plan not shown: %s", out.String())
	}
	if !strings.Contains(out.String(), "DRY-RUN") { t.Fatalf("dry-run marker missing: %s", out.String()) }
}

// Requirement: refusal without confirmation. Empty stdin → the operator
// typed nothing → refused with exit 2 and zero executor calls.
func TestApplyRefusesWithoutConfirmation(t *testing.T) {
	o, rec, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}}})
	var out bytes.Buffer
	code := runApply([]string{"--config", experimentConfig(t)}, o, strings.NewReader(""), &out, &out)
	if code != 2 { t.Fatalf("exit=%d, want 2", code) }
	if len(rec.calls) != 0 { t.Fatalf("mutation without confirmation: %v", rec.calls) }
}

// Requirement: successful Confirm for the exact plan — the full lifecycle on
// the injected orchestrator ends in COMPLETED with persisted state.
func TestApplyConfirmsExactPlan(t *testing.T) {
	rec := &cliRecordingExecutor{}
	// Discovery calls: #1 test-side Prepare (to learn the fingerprint),
	// #2 CLI Prepare, #3 staleness re-check, #4 post-apply re-discovery.
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t), loadSaymer3Discovery(t), repairedSaymer3Discovery(t),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec}})
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)

	var out bytes.Buffer
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 0 { t.Fatalf("exit=%d output=%s", code, out.String()) }
	if !strings.Contains(out.String(), "Stage: COMPLETED") { t.Fatalf("outcome missing: %s", out.String()) }
	want := []string{
		"backup:service.fail2ban.service",
		"apply:service.fail2ban.service",
		"validate:service.fail2ban.service",
		"validate:service.fail2ban.service",
	}
	if len(rec.calls) != len(want) { t.Fatalf("calls=%v", rec.calls) }
	for i := range want {
		if rec.calls[i] != want[i] { t.Fatalf("call[%d]=%q want %q", i, rec.calls[i], want[i]) }
	}
	if _, err := os.Stat(o.StatePath); err != nil { t.Fatalf("persisted state missing: %v", err) }
}

// A confirmation typed for a different plan is refused: the CLI binds the
// operator input to the exact fingerprint of the plan it is about to execute.
// (Plan mutation after confirmation is impossible through the CLI — there is
// no plan editing — and is additionally pinned at the orchestration layer.)
func TestApplyRejectsForeignFingerprint(t *testing.T) {
	o, rec, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}}})
	var out bytes.Buffer
	foreign := orchestrate.Fingerprint(state.Plan{SchemaVersion: state.SchemaVersion})[:12]
	code := runApply([]string{"--config", experimentConfig(t), "--confirm", foreign}, o, strings.NewReader(""), &out, &out)
	if code != 2 { t.Fatalf("exit=%d, want 2", code) }
	if len(rec.calls) != 0 { t.Fatalf("mutation with foreign fingerprint: %v", rec.calls) }
}

// Requirement: an attempt to smuggle a second action into the experiment —
// a second service added to the desired state — is rejected by the
// experiment guard before any confirmation or mutation.
func TestApplyRejectsSecondAction(t *testing.T) {
	disc := loadSaymer3Discovery(t)
	disc.Services = append(disc.Services, discovery.Service{Name: "other.service", Exists: true, Enabled: true, Active: false, SubState: "failed"})
	twoConfig := writeApplyConfig(t, map[string]any{
		"desired": map[string]any{"services": []map[string]any{
			{"name": "fail2ban.service", "active": true},
			{"name": "other.service", "active": true},
		}},
		"ownership": map[string]any{
			"service.fail2ban.service": "OWNED",
			"service.other.service":    "OWNED",
		},
	})
	rec := &cliRecordingExecutor{}
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{disc}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec}})
	var out bytes.Buffer
	code := runApply([]string{"--config", twoConfig}, o, strings.NewReader(""), &out, &out)
	if code != 3 { t.Fatalf("exit=%d, want 3; output=%s", code, out.String()) }
	if !strings.Contains(out.String(), "first production experiment") { t.Fatalf("guard message missing: %s", out.String()) }
	if len(rec.calls) != 0 { t.Fatalf("mutation with smuggled action: %v", rec.calls) }
}

// Requirement: UNKNOWN ownership → rejection before any mutation.
func TestApplyRejectsUnknownOwnership(t *testing.T) {
	o, rec, _ := applyTestOrchestrator(t, []discovery.Result{loadSaymer3Discovery(t)}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: &cliRecordingExecutor{}}})
	noOwnership := writeApplyConfig(t, map[string]any{
		"desired": map[string]any{"services": []map[string]any{{"name": "fail2ban.service", "active": true}}},
	})
	var out bytes.Buffer
	code := runApply([]string{"--config", noOwnership}, o, strings.NewReader(""), &out, &out)
	if code != 3 { t.Fatalf("exit=%d, want 3; output=%s", code, out.String()) }
	if len(rec.calls) != 0 { t.Fatalf("mutation with UNKNOWN ownership: %v", rec.calls) }
}

// Requirement: stale plan → rejection. The machine changed between Prepare
// and the staleness re-check (fail2ban repaired itself), so the mutation is
// refused even with a correctly typed confirmation prefix.
func TestApplyRejectsStalePlan(t *testing.T) {
	rec := &cliRecordingExecutor{}
	o, _, _ := applyTestOrchestrator(t, []discovery.Result{
		loadSaymer3Discovery(t), loadSaymer3Discovery(t), repairedSaymer3Discovery(t),
	}, apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{state.ActionService: rec}})
	prepared := o.Prepare(firstExperimentConfig(), rootOpts())
	prefix := fingerprintPrefix(t, prepared)

	var out bytes.Buffer
	code := runApplyWith([]string{"--config", experimentConfig(t), "--confirm", prefix}, o, rootOpts(), strings.NewReader(""), &out, &out)
	if code != 3 { t.Fatalf("exit=%d, want 3; output=%s", code, out.String()) }
	if !strings.Contains(out.String(), "stale") { t.Fatalf("staleness blocker missing: %s", out.String()) }
	if len(rec.calls) != 0 { t.Fatalf("mutation with stale plan: %v", rec.calls) }
}
