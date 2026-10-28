//go:build linux

package main

// The --observe-service-report wiring test on Linux (ZAI-119): the flag's
// installed observer is the REAL reference chain — ObserveServiceFromRunner
// over ProductionCommandRunner — proven here end-to-end against a fake
// systemctl executable resolved through PATH. No real service is touched.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWireServiceObservationInstallsReferenceChain(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"printf 'ActiveState=active\\nSubState=running\\nMainPID=799\\n" +
		"ExecMainStartTimestamp=Sun 2026-10-25 20:45:44 MSK\\n" +
		"ExecMainStartTimestampMonotonic=9946341\\nInvocationID=a8f6e6a6a8a64bd2bde1f655137127ac\\n" +
		"NRestarts=0\\nLoadState=loaded\\n'\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	o := defaultApplyOrchestrator(0)
	wireServiceObservation(o, true)
	if o.ObserveService == nil {
		t.Fatal("the request must install the reference observer")
	}
	obs, err := o.ObserveService(context.Background(), "fail2ban.service")
	if err != nil {
		t.Fatalf("the reference chain must observe through the fake systemctl: %v", err)
	}
	if obs.Status != "PRESENT" || obs.MainPID != "799" || obs.LoadState != "loaded" ||
		obs.InvocationID != "a8f6e6a6a8a64bd2bde1f655137127ac" {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	// And the chain stays read-only: the only command it can ever run is
	// the fixed show — a mutation verb is refused before any process.
	if _, err := o.ObserveService(context.Background(), "-evil.service"); err == nil || !strings.Contains(err.Error(), "valid systemd unit name") {
		t.Fatalf("an invalid coordinate must be refused by the same chain: %v", err)
	}
}
