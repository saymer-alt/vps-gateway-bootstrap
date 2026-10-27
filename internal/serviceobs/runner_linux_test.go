//go:build linux

package serviceobs

// ProductionCommandRunner tests (ZAI-118). They run only on Linux (the
// fake systemctl is an executable shell script resolved through PATH;
// CI and the supported targets are Linux). Everything is synthetic: the
// fake binary is created in a temp dir, nothing real is started except
// that script, and no service is touched.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSystemctlDir creates a temp bin dir whose `systemctl` script echoes
// canned output on stdout, records its full argv into a marker file, and
// honors the behavior switches. It returns the dir (prepend to PATH) and
// the marker path.
func fakeSystemctlDir(t *testing.T, stdout string, behavior string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "argv.log")
	script := "#!/bin/sh\n"
	switch behavior {
	case "sleep":
		script += "sleep 30\n"
	case "fail":
		script += "echo injected systemctl failure >&2\nexit 1\n"
	default:
		script += "printf '%s' \"" + stdout + "\"\n"
	}
	script += "printf '%s\\n' \"$*\" >> " + marker + "\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, marker
}

func runnerPath(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
}

// The refusal matrix: any argv other than the exact fixed read-only query
// is refused BEFORE a process starts (the fake binary's marker stays
// absent), including every mutation verb of systemctl.
func TestProductionCommandRunnerRefusesNonReadOnly(t *testing.T) {
	dir, marker := fakeSystemctlDir(t, "", "echo")
	runnerPath(t, dir)
	fixed := append([]string{"show", "fail2ban.service"}, queryProperties...)

	cases := map[string][]string{
		"wrong binary":       {"systemctl2"},
		"shell interpreter":  {"sh"},
		"mutation verb":      {"start", "fail2ban.service"},
		"stop":               {"stop", "fail2ban.service"},
		"restart":            {"restart", "fail2ban.service"},
		"reload":             {"reload", "fail2ban.service"},
		"kill":               {"kill", "fail2ban.service"},
		"enable":             {"enable", "fail2ban.service"},
		"disable":            {"disable", "fail2ban.service"},
		"no args":            {},
		"missing properties": {"show", "fail2ban.service"},
		"tampered property":  append(append([]string{"show", "fail2ban.service"}, queryProperties[:1]...), "--property=ExecMainEnterTimestamp"),
		"extra argument":     append(append([]string{}, fixed...), "--no-pager"),
		"invalid unit":       append([]string{"show", "-evil.service"}, queryProperties...),
	}
	for name, args := range cases {
		if _, err := ProductionCommandRunner(context.Background(), "systemctl", args...); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
		if _, err := ProductionCommandRunner(context.Background(), "sh", "-c", "echo pwned"); err == nil {
			t.Fatalf("%s: shell invocation must be refused", name)
		}
	}
	// A differently named binary is refused even with the right argv.
	if _, err := ProductionCommandRunner(context.Background(), "systemctl2", fixed...); err == nil {
		t.Fatal("a non-systemctl binary must be refused")
	}
	// No refusal above may have started a process.
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("refused argv must never reach a process; marker content: %v", mustRead(t, marker))
	}
}

// The exact fixed shape executes: the fake binary receives precisely the
// package's argv, the canned output comes back, and the fixed vector
// itself carries no mutation verb.
func TestProductionCommandRunnerExecutesFixedShape(t *testing.T) {
	out := showOutput("active", "running", "799", "Sun 2026-10-25 20:45:44 MSK", "9946341", "0") + "LoadState=loaded\n"
	dir, marker := fakeSystemctlDir(t, out, "echo")
	runnerPath(t, dir)
	got, err := ProductionCommandRunner(context.Background(), "systemctl", append([]string{"show", "fail2ban.service"}, queryProperties...)...)
	if err != nil {
		t.Fatalf("the fixed shape must execute: %v", err)
	}
	if !bytes.Equal(got, []byte(out)) {
		t.Fatalf("stdout mismatch: %q", got)
	}
	// The real Observe path works end-to-end through the production runner
	// and the fake binary.
	obs, err := Observe(context.Background(), ProductionCommandRunner, testUnit)
	if err != nil || obs.Status != StatusPresent || obs.MainPID != "799" || obs.LoadState != "loaded" {
		t.Fatalf("end-to-end observe through the runner: %+v err=%v", obs, err)
	}
	// Both executions (the direct call and the Observe) received exactly
	// the fixed read-only argv — no mutation verb anywhere.
	lines := strings.Split(strings.TrimSpace(string(mustRead(t, marker))), "\n")
	if len(lines) != 2 {
		t.Fatalf("exactly two executions expected, marker: %v", lines)
	}
	for i, line := range lines {
		argv := strings.Fields(line)
		if argv[0] != "show" || argv[1] != "fail2ban.service" {
			t.Fatalf("unexpected argv in execution %d: %v", i, argv)
		}
		for _, a := range argv {
			switch a {
			case "start", "stop", "restart", "reload", "kill", "enable", "disable", "mask", "unmask":
				t.Fatalf("mutation verb %q in the fixed vector: %v", a, argv)
			}
		}
	}
}

// A context deadline genuinely terminates the query: the runner returns
// the context error promptly and the child is killed, not leaked.
func TestProductionCommandRunnerTimesOut(t *testing.T) {
	dir, marker := fakeSystemctlDir(t, "", "sleep")
	runnerPath(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ProductionCommandRunner(ctx, "systemctl", append([]string{"show", "fail2ban.service"}, queryProperties...)...)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("want a context-deadline error, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the deadline must kill the child promptly, took %v", elapsed)
	}
	// The DeadlineExceeded classification itself proves the child started
	// and was cancelled (a missing binary yields a start-failure error
	// instead); the fake appends its marker only after its sleep, so a
	// killed run leaves no marker — nothing to assert there.
	_ = marker
}

// A nonzero systemctl exit is a controlled command failure carrying
// stderr — distinct from cancellation.
func TestProductionCommandRunnerCommandFailure(t *testing.T) {
	dir, _ := fakeSystemctlDir(t, "", "fail")
	runnerPath(t, dir)
	_, err := ProductionCommandRunner(context.Background(), "systemctl", append([]string{"show", "fail2ban.service"}, queryProperties...)...)
	if err == nil {
		t.Fatal("a failing systemctl must be reported")
	}
	if strings.Contains(err.Error(), "cancelled or timed out") {
		t.Fatalf("a plain command failure must not be classified as cancellation: %v", err)
	}
	if !strings.Contains(err.Error(), "injected systemctl failure") {
		t.Fatalf("the error must carry stderr: %v", err)
	}
}

// A missing systemctl binary is a controlled start failure.
func TestProductionCommandRunnerBinaryMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // no systemctl anywhere
	_, err := ProductionCommandRunner(context.Background(), "systemctl", append([]string{"show", "fail2ban.service"}, queryProperties...)...)
	if err == nil {
		t.Fatal("a missing binary must be reported")
	}
	var lookErr *exec.Error
	if !errors.As(err, &lookErr) && !strings.Contains(err.Error(), "could not be started") {
		t.Fatalf("want a start-failure classification, got %v", err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
