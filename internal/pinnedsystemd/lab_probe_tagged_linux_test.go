//go:build linux && p1c5h_lab

package pinnedsystemd

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/pinnedunitfile"
)

// TestP1C5HRealDisposableSystemdReadOnly does NOT run in ordinary CI.
// Its build tag must be deliberately provided on an owner-approved,
// isolated, disposable Linux systemd VM; missing host binding/marker
// causes FAILURE before any systemctl invocation.
//
// It does not mutate services, install packages, grant adoption or
// exercise the broker. Two observations detect gross inter-run drift,
// not bytewise identity of systemd's in-memory loaded unit.
func TestP1C5HRealDisposableSystemdReadOnly(t *testing.T) {
	expected := os.Getenv("VPS_GATEWAY_P1C5H_LAB_MACHINE_ID")
	if expected == "" {
		t.Fatal("BLOCKED: missing explicit disposable LAB machine-id; do not run on a production VPS")
	}
	observed, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(observed) > 128 {
		t.Fatalf("BLOCKED: cannot read bounded installation identity: %v", err)
	}
	if err := checkLabPermit(expected, string(observed), disposableLabMarkerPath, 0); err != nil {
		t.Fatalf("BLOCKED: disposable lab authorization precondition not met: %v", err)
	}
	pid1, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pid1)) != "systemd" {
		t.Fatalf("BLOCKED: PID 1 is not independently observed as systemd: %v", err)
	}
	info, err := os.Lstat("/run/systemd/system")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("BLOCKED: expected system manager runtime directory unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	first, err := Inspect(ctx)
	if err != nil {
		t.Fatalf("BLOCKED: first fixed read-only manager/disk observation: %v", err)
	}
	if first.Status != pinnedunitfile.MatchedMetadataDiskOnly {
		t.Fatalf("BLOCKED: first diagnostic not stable/reviewable: %s", first.Status)
	}
	second, err := Inspect(ctx)
	if err != nil {
		t.Fatalf("BLOCKED: second fixed read-only manager/disk observation: %v", err)
	}
	if second.Status != pinnedunitfile.MatchedMetadataDiskOnly ||
		first.ReportedFragment != second.ReportedFragment || first.Disk != second.Disk {
		t.Fatalf("BLOCKED: manager/disk changed across two observations (not an adoption claim)")
	}
	t.Logf("READ_ONLY_DISPOSABLE_LAB_OBSERVATION=PASS manager-fragment=%s canonical-disk=%s sha256-prefix=%.12s (NOT OWNED; NOT LOADED-BYTES ATTESTATION)",
		first.ReportedFragment, first.Disk.Path, first.Disk.SHA256)
}
