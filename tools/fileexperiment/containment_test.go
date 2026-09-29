package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pipeline"
)

// Containment regressions (ZAI-13, CODEX TASK-02): the pinned file experiment
// must be planning/preview only. An embedded OWNED label plus the shape guard
// never established ownership provenance, so until P1-A is implemented the
// tool must have NO mutating execution path: no orchestrate.Execute, no
// FileExecutor Apply/Rollback, no lock, journal, backup or state writes —
// whatever confirmation the caller supplies.

const foreignContent = "operator's own data — created independently of this project\n"

// seedForeignTarget creates the CODEX-02 counterexample: a regular file at
// the exact experiment target, created independently, with foreign bytes and
// a non-experiment mode.
func seedForeignTarget(t *testing.T, root string) {
	t.Helper()
	target := experimentFilePath(root)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(foreignContent), 0o640); err != nil {
		t.Fatal(err)
	}
}

func assertForeignTargetIntact(t *testing.T, root string) {
	t.Helper()
	target := experimentFilePath(root)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("foreign target vanished: %v", err)
	}
	if string(data) != foreignContent {
		t.Fatalf("foreign target was overwritten: %q", data)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("foreign target mode changed: %o", info.Mode().Perm())
	}
}

func assertNoMutationSideEffects(t *testing.T, root string) {
	t.Helper()
	for _, p := range []string{
		filepath.Join(root, "state.json"),
		filepath.Join(root, "journal"),
		filepath.Join(root, "apply.lock"),
		filepath.Join(root, "etc", "vps-gateway", "backups"),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("mutation lifecycle artifact exists at %s: %v", p, err)
		}
	}
}

// Case C (critical): a differing foreign file at the experiment target must
// never be overwritten — not even with the confirmation prefix that
// previously enabled execution. Before the containment this test failed:
// the run replaced the foreign file with the experiment content.
func TestFileExperimentForeignTargetIsNeverOverwritten(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	seedForeignTarget(t, root)

	// Learn the fingerprint the way the operator would have (the tool's own
	// preview output) and supply it as the confirmation prefix.
	var preview bytes.Buffer
	if code := runFileExperiment([]string{"--dry-run", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &preview, &preview); code != 0 {
		t.Fatalf("preview exit=%d output=%s", code, preview.String())
	}
	fp := fingerprintFromOutput(preview.String())
	if fp == "" {
		t.Fatalf("fingerprint missing in preview: %s", preview.String())
	}

	var out bytes.Buffer
	code := runFileExperiment([]string{"--confirm", fp, "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Fatalf("mutating run must not succeed; output=%s", out.String())
	}
	if !strings.Contains(out.String(), "mutation is disabled") {
		t.Fatalf("containment notice missing: %s", out.String())
	}
	assertForeignTargetIntact(t, root)
	assertNoMutationSideEffects(t, root)
}

// Case A: absent target — the run must not create the file.
func TestFileExperimentAbsentTargetNotCreated(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	var out bytes.Buffer
	code := runFileExperiment([]string{"--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Fatalf("mutating run must not succeed; output=%s", out.String())
	}
	if _, err := os.Stat(experimentFilePath(root)); !os.IsNotExist(err) {
		t.Fatalf("absent target was created: %v", err)
	}
	assertNoMutationSideEffects(t, root)
}

// Case B: an already-matching file stays a read-only convergence report —
// equality must never mint provenance or write lifecycle state.
func TestFileExperimentMatchingTargetStaysReadOnly(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	seedForeignTarget(t, root)
	// Recreate (not overwrite): os.WriteFile on an existing file does not
	// re-apply the mode, and the stale 0640 would read as drift.
	if err := os.Remove(experimentFilePath(root)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(experimentFilePath(root), []byte(experimentContent), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runFileExperiment([]string{"--dry-run", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code != 0 {
		t.Fatalf("dry-run exit=%d output=%s", code, out.String())
	}
	if !strings.Contains(out.String(), "already converged") {
		t.Fatalf("convergence report missing: %s", out.String())
	}
	assertNoMutationSideEffects(t, root)
}

// Case D: an alternate --root must not restore mutation capability.
func TestFileExperimentAlternateRootCannotMutate(t *testing.T) {
	o, _ := experimentTestOrchestrator(t)
	alternate := t.TempDir()
	var out bytes.Buffer
	code := runFileExperiment([]string{"--confirm", "deadbeefdead", "--root", alternate}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code == 0 {
		t.Fatalf("mutating run must not succeed; output=%s", out.String())
	}
	entries, err := os.ReadDir(alternate)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("alternate root was mutated: %d entries appeared", len(entries))
	}
	if !strings.Contains(out.String(), "mutation is disabled") && !strings.Contains(out.String(), "confirmation refused") {
		t.Fatalf("expected refusal output: %s", out.String())
	}
}

// Case E: a well-formed confirmation argument is refused with the
// containment notice — it must never reach execution.
func TestFileExperimentConfirmArgumentIsRefused(t *testing.T) {
	o, root := experimentTestOrchestrator(t)
	var out bytes.Buffer
	code := runFileExperiment([]string{"--confirm", "0123456789ab", "--root", root}, o, pipeline.Options{Root: ptrTrue()}, strings.NewReader(""), &out, &out)
	if code != 2 {
		t.Fatalf("exit=%d, want 2; output=%s", code, out.String())
	}
	if !strings.Contains(out.String(), "mutation is disabled") {
		t.Fatalf("containment notice missing: %s", out.String())
	}
	assertNoMutationSideEffects(t, root)
}

// Source-level tripwire (the repo's TestCLIMutationPathIsConfined pattern):
// the experiment tool must not reference the mutating orchestration surface
// at all — no Execute call, no Confirmation construction, no interactive
// confirmation reader. Restoring any of these without an explicit operator
// decision to re-enable (post-P1-A) fails here instead of silently
// re-widening the mutation surface.
func TestFileExperimentHasNoExecutePath(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{".Execute(", "orchestrate.Confirmation", "orchestrate.Confirm(", "bufio.NewReader"} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("fileexperiment main.go must not reference %q: mutation is disabled pending ownership provenance (ZAI-13 containment)", forbidden)
		}
	}
}
