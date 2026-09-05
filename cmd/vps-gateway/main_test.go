package main

import (
	"os"
	"strings"
	"testing"
)

// The apply engine exists and is tested, but real apply must stay
// unreachable from the CLI. A bare "install" must be refused with exit code 2
// even when other valid flags are present, so wiring the apply engine into
// the CLI can never happen by accident or silently.
func TestInstallWithoutDryRunRefuses(t *testing.T) {
	if code := runInstall(nil); code != 2 { t.Fatalf("bare install exit=%d, want 2", code) }
	if code := runInstall([]string{"--json"}); code != 2 { t.Fatalf("install --json exit=%d, want 2", code) }
	if code := runInstall([]string{"--config", "/dev/null", "--state", "/dev/null"}); code != 2 {
		t.Fatalf("install with config/state but no --dry-run exit=%d, want 2", code)
	}
}

// Source-level tripwire for the mutation boundary. main.go itself must not
// reference the apply engine or the orchestration layer at all; the ONLY
// sanctioned path is apply.go, which must go through the orchestrator
// (Prepare → Confirm → Execute) and must carry the first-experiment guard.
// The apply engine (`internal/apply`) is never imported by the CLI directly —
// bypassing the orchestrator would skip confirmation, lock, staleness,
// re-discovery and persistence.
func TestCLIMutationPathIsConfined(t *testing.T) {
	mainSrc, err := os.ReadFile("main.go")
	if err != nil { t.Fatal(err) }
	for _, forbidden := range []string{"internal/apply", "internal/orchestrate", ".Execute("} {
		if strings.Contains(string(mainSrc), forbidden) {
			t.Fatalf("main.go must not reference %q: the mutation path lives only in apply.go", forbidden)
		}
	}

	applySrc, err := os.ReadFile("apply.go")
	if err != nil { t.Fatal(err) }
	src := string(applySrc)
	if strings.Contains(src, `"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"`) == false {
		t.Fatal("apply.go must register the experiment executor set through internal/apply")
	}
	if !strings.Contains(src, `"github.com/saymer-alt/vps-gateway-bootstrap/internal/orchestrate"`) {
		t.Fatal("apply.go must reach the mutation only through internal/orchestrate")
	}
	for _, required := range []string{"firstExperimentGuard", "Prepare(", "Execute(", "PlanFingerprint"} {
		if !strings.Contains(src, required) {
			t.Fatalf("apply.go must contain %q — the orchestrator lifecycle and the experiment guard are the safety contract", required)
		}
	}
	if !strings.Contains(src, "restricted to the first production experiment") {
		t.Fatal("apply.go must keep the experiment restriction message")
	}
	if !strings.Contains(string(mainSrc), "real apply is not implemented yet") {
		t.Fatal("the install guard message is part of the CLI safety contract and must stay present")
	}
}

// Exit-code contract of the read-only commands, pinned so tooling can rely
// on them: 0 ok, 2 usage, 3 failure.
func TestUsageExitCode(t *testing.T) {
	if code := runDoctor([]string{"--nope"}); code != 2 { t.Fatalf("doctor bad flag exit=%d, want 2", code) }
	if code := runValidate([]string{"--nope"}); code != 2 { t.Fatalf("validate bad flag exit=%d, want 2", code) }
	if code := runDiscover([]string{"--nope"}); code != 2 { t.Fatalf("discover bad flag exit=%d, want 2", code) }
}
