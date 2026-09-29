package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/journal"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// All tests run against an injected orchestrator with fake discovery, the
// REAL FileExecutor and the REAL file inspector rooted at a temp directory —
// the same wiring the live experiment uses, minus the real machine.

func experimentTestOrchestrator(t *testing.T) (*orchestrate.Orchestrator, string) {
	t.Helper()
	no := false
	root := t.TempDir()
	o := &orchestrate.Orchestrator{
		Discover: func() discovery.Result {
			return discovery.Result{
				SchemaVersion: discovery.SchemaVersion, DiscoveryVersion: "0.2.0", Status: "OK",
				Host:   discovery.Host{Hostname: "Saymer3"},
				System: discovery.System{OS: discovery.OS{ID: "ubuntu", Name: "Ubuntu", VersionID: "24.04"}, Kernel: discovery.Kernel{Release: "6.8.0", Architecture: "x86_64"}},
				Network: discovery.Network{
					ExternalInterface: "ens3", DefaultGateway: "203.0.113.1", IPv4: true, IPv6: true,
					DNS: discovery.DNS{Resolvers: []string{"1.1.1.1"}, Source: "/etc/resolv.conf"},
				},
				SSH:      discovery.SSH{Installed: true, Architecture: "socket-activated", EffectivePorts: []int{2222}, PasswordAuthentication: &no},
				Routing:  discovery.Routing{DefaultRoutes: []discovery.Route{{Device: "ens3"}}},
				Firewall: discovery.Firewall{Layers: []string{"ufw"}},
				Capabilities: discovery.Capabilities{Systemd: true, UFW: true},
			}
		},
		Registry: apply.Registry{ByKind: map[state.ActionKind]apply.ActionExecutor{
			state.ActionCreateFile:      &apply.FileExecutor{Root: root},
			state.ActionUpdateFile:      &apply.FileExecutor{Root: root},
			state.ActionDeleteOwnedFile: &apply.FileExecutor{Root: root},
		}},
		LockPath:  filepath.Join(root, "apply.lock"),
		StatePath: filepath.Join(root, "state.json"),
		Journal:   &journal.Journal{Dir: filepath.Join(root, "journal")},
	}
	return o, root
}

func experimentFilePath(root string) string {
	return filepath.Join(root, "etc", "vps-gateway", "experiment-file-test.conf")
}

func TestFileExperimentDryRunStopsBeforeConfirmation(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	var out bytes.Buffer
	code := runFileExperiment([]string{"--dry-run", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("exit=%d output=%s", code, out.String())
	}
	if _, err := os.Stat(experimentFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("dry-run created the file: %v", err)
	}
	if !strings.Contains(out.String(), "DRY-RUN") {
		t.Fatalf("marker missing: %s", out.String())
	}
}

// Containment (ZAI-13): a run without --dry-run is a mutating attempt and is
// refused — the file is never created, and the output names the containment.
func TestFileExperimentRefusesWithoutConfirmation(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	var out bytes.Buffer
	code := runFileExperiment(nil, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code != 3 {
		t.Fatalf("exit=%d, want 3 (containment refusal)", code)
	}
	if !strings.Contains(out.String(), "mutation is disabled") {
		t.Fatalf("containment notice missing: %s", out.String())
	}
	if _, err := os.Stat(experimentFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("file created despite containment: %v", err)
	}
}

// Containment (ZAI-13): the experiment is planning/preview only. The preview
// still shows the candidate plan and its fingerprint, but the previously
// mutating confirm run is refused, writes nothing, and a second preview still
// reports the same candidate (nothing converged, nothing changed).
func TestFileExperimentPreviewOnlyConfirmIsRefused(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	var out bytes.Buffer
	// The fingerprint is learned from the tool's own preview, the same way
	// the operator would read it.
	code := runFileExperiment([]string{"--dry-run", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("preview exit=%d", code)
	}
	fp := fingerprintFromOutput(out.String())
	if fp == "" {
		t.Fatalf("fingerprint missing in output: %s", out.String())
	}

	out.Reset()
	code = runFileExperiment([]string{"--confirm", fp, "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Fatalf("confirm run must not succeed; output=%s", out.String())
	}
	if !strings.Contains(out.String(), "mutation is disabled") {
		t.Fatalf("containment notice missing: %s", out.String())
	}
	if _, err := os.Stat(experimentFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("file created despite containment: %v", err)
	}

	// The preview still works afterwards and shows the same candidate.
	var preview2 bytes.Buffer
	code = runFileExperiment([]string{"--dry-run", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &preview2, &preview2)
	if code != 0 {
		t.Fatalf("second preview exit=%d output=%s", code, preview2.String())
	}
	if !strings.Contains(preview2.String(), "Plan fingerprint: ") {
		t.Fatalf("preview broken: %s", preview2.String())
	}
}

// The experiment guard rejects any deviation from the pinned plan shape.
func TestFileExperimentGuardRejectsDeviations(t *testing.T) {
	o, _ := experimentTestOrchestrator(t)

	// Each deviation starts from a FRESH plan: Spec is a pointer, and
	// mutating a shared copy would corrupt later checks.
	prepare := func() orchestrate.Plan {
		return o.Prepare(experimentConfig("/"), pipeline.Options{Root: ptrTrue()})
	}

	// A second action smuggled into the plan.
	p := prepare()
	mutated := p
	mutated.Plan.Actions = append(mutated.Plan.Actions, mutated.Plan.Actions[0])
	if err := fileExperimentGuard(mutated, "/"); err == nil {
		t.Fatal("second action must be rejected")
	}

	// Content deviation.
	p2 := prepare()
	p2.Plan.Actions[0].Spec.File.Content = "tampered\n"
	if err := fileExperimentGuard(p2, "/"); err == nil {
		t.Fatal("content deviation must be rejected")
	}

	// Mode deviation.
	p3 := prepare()
	p3.Plan.Actions[0].Spec.File.Mode = 0644
	if err := fileExperimentGuard(p3, "/"); err == nil {
		t.Fatal("mode deviation must be rejected")
	}

	// Ownership downgrade.
	p4 := prepare()
	p4.Plan.Actions[0].Ownership = state.External
	if err := fileExperimentGuard(p4, "/"); err == nil {
		t.Fatal("ownership downgrade must be rejected")
	}

	// The untouched plan passes.
	if err := fileExperimentGuard(prepare(), "/"); err != nil {
		t.Fatalf("original plan must pass: %v", err)
	}
}

func fingerprintFromOutput(s string) string {
	const marker = "Plan fingerprint: "
	idx := strings.Index(s, marker)
	if idx < 0 {
		return ""
	}
	rest := s[idx+len(marker):]
	if len(rest) < 12 {
		return ""
	}
	return strings.TrimSpace(rest[:12])
}

func ptrTrue() *bool {
	yes := true
	return &yes
}
