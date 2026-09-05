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

// Source-level tripwire: the CLI must not link the apply engine or the
// orchestration layer. Real apply may only be wired in behind an explicit,
// reviewed product decision that also updates this test and
// docs/plan-apply.md.
func TestCLIDoesNotLinkApplyEngine(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil { t.Fatal(err) }
	src := string(b)
	for _, forbidden := range []string{"internal/apply", "internal/orchestrate"} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("cmd/vps-gateway must not import %s: real apply is not production-ready and must stay unreachable from the CLI", forbidden)
		}
	}
	if !strings.Contains(src, "real apply is not implemented yet") {
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
