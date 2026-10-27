//go:build linux

package main

// The hung-systemctl test (ZAI-118 addendum): a REAL executable fake
// `systemctl` that never answers. The probe's per-query budget must
// terminate the query (exec.CommandContext kill + runner WaitDelay) and
// the probe must RETURN with a failure — never hang behind a wedged
// binary. `exec sleep` makes the sleeper the direct child so the
// context kill takes effect cleanly with no orphaned grandchild.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProbeReturnsWhenSystemctlHangs(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\nexec sleep 300\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	var out bytes.Buffer
	start := time.Now()
	code := runWithBudget(nil, &out, liveObserve, 150*time.Millisecond)
	elapsed := time.Since(start)

	if elapsed > 60*time.Second {
		t.Fatalf("the probe must not hang behind a wedged systemctl, took %v", elapsed)
	}
	if code != 1 {
		t.Fatalf("a hung systemctl must fail the probe, code=%d output:\n%s", code, out.String())
	}
	joined := out.String()
	if !strings.Contains(joined, "context deadline exceeded") {
		t.Fatalf("the deadline must surface in the report:\n%s", joined)
	}
	if !strings.Contains(joined, "query error") {
		t.Fatalf("each timed-out snapshot must be reported as a query error:\n%s", joined)
	}
	if !strings.Contains(joined, "probe verdict: FAIL") {
		t.Fatalf("the probe must conclude with a FAIL verdict:\n%s", joined)
	}
}
