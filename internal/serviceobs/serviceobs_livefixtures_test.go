package serviceobs

// Live stdout fixtures (ZAI-117, 2026-10-27): verbatim bytes of the
// observer's exact read-only command shape, captured on the real field
// target Saymer3 (Ubuntu 24.04.5 LTS, systemd 255.4-1ubuntu8.18) during an
// owner-authorized READ-ONLY session — no restart, no stop, no install, no
// configuration change. The files carry systemctl's own property lines in
// systemctl's native emission order (which differs from the query order;
// the parser is order-independent by construction). These tests run the
// REAL Observe/Compare implementation against those bytes — the real code
// on real machine output, with no production binary ever installed on the
// target. Field evidence and the verdict matrix:
// docs/serviceobs-live-validation-saymer3-2026-10-27.md.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func liveFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func observeFixture(t *testing.T, name string, unit Unit) Observation {
	t.Helper()
	o, err := Observe(context.Background(), okRunner(liveFixture(t, name)), unit)
	if err != nil {
		t.Fatalf("Observe(%s): %v", unit, err)
	}
	return o
}

// The pinned field evidence (procedure §1–§3): the running fail2ban unit
// reports all seven properties, the InvocationID is well-formed 32-hex,
// and an untouched running unit's snapshot pair classifies
// NO_NEW_INVOCATION. The owner's field pair two seconds apart was
// byte-identical, so the same bytes legitimately stand for both sides.
func TestLiveFixtureSaymer3Fail2banRunningPair(t *testing.T) {
	o := observeFixture(t, "saymer3-2026-10-27-fail2ban-active.stdout", testUnit)
	if o.Status != StatusPresent {
		t.Fatalf("the running unit's field output must parse as PRESENT, got %s (%v)", o.Status, o.Reasons)
	}
	if len(o.Reasons) != 0 {
		t.Fatalf("a clean field snapshot must carry no reasons: %v", o.Reasons)
	}
	// Every reported fact is carried verbatim — no normalization.
	if o.ActiveState != "active" || o.SubState != "running" || o.MainPID != "799" ||
		o.ExecMainStartTimestamp != "Sun 2026-10-25 20:45:44 MSK" ||
		o.ExecMainStartTimestampMonotonic != "9946341" ||
		o.InvocationID != "a8f6e6a6a8a64bd2bde1f655137127ac" || o.NRestarts != "0" {
		t.Fatalf("field facts must be carried verbatim: %+v", o)
	}
	if !validInvocationID(o.InvocationID) {
		t.Fatalf("the field InvocationID %q must be well-formed 32-hex (§3 FORMAT_OK)", o.InvocationID)
	}
	ev, reasons := Compare(o, o)
	if ev != NoNewInvocation {
		t.Fatalf("the untouched running pair must classify NO_NEW_INVOCATION, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "a8f6e6a6a8a64bd2bde1f655137127ac") {
		t.Fatalf("the reason must cite the persisted field InvocationID: %v", reasons)
	}
}

// Field finding (procedure §5a, corrected 2026-10-27): on systemd 255 a
// missing unit name never produces a command failure — `systemctl show`
// exits 0 with a SYNTHESIZED property set (ActiveState=inactive,
// SubState=dead, MainPID=0, empty start identity and InvocationID; the
// unfiltered show reports LoadState=not-found). The observer maps this to
// a PRESENT snapshot with an empty invocation channel, and a comparison
// involving it fails closed to INVOCATION_UNPROVABLE — never StatusError,
// never a favorable verdict. (auditd.service, a referenced-but-absent
// unit on the same host, produces byte-identical output.)
func TestLiveFixtureSaymer3NotFoundUnitIsSynthesizedAndFailClosed(t *testing.T) {
	o := observeFixture(t, "saymer3-2026-10-27-not-found.stdout", Unit("does-not-exist-12345.service"))
	if o.Status != StatusPresent {
		t.Fatalf("a not-found unit's synthesized output must still parse as PRESENT on systemd 255, got %s (%v)", o.Status, o.Reasons)
	}
	if o.ActiveState != "inactive" || o.SubState != "dead" || o.MainPID != "0" ||
		o.ExecMainStartTimestamp != "" || o.InvocationID != "" {
		t.Fatalf("the synthesized snapshot must carry the not-found shape: %+v", o)
	}
	ev, reasons := Compare(o, o)
	if ev != InvocationUnprovable {
		t.Fatalf("a not-found-unit pair must fail closed to UNPROVABLE, got %s (%v)", ev, reasons)
	}
	joined := strings.Join(reasons, "; ")
	if strings.Contains(joined, "no invocation occurred") || strings.Contains(joined, "no new invocation") {
		t.Fatalf("the not-found pair must not claim absence of an invocation: %v", reasons)
	}
	if !strings.Contains(joined, "could have occurred and ended") {
		t.Fatalf("the reason must state the restart-and-stop possibility: %v", reasons)
	}
}

// Procedure §4, stopped-unit branch (real unit apt-daily.service, stopped
// after its scheduled run earlier the same day): a stopped unit keeps the
// LAST invocation's identity — non-empty start timestamp, monotonic and
// InvocationID with MainPID=0. Two snapshots of the untouched stopped unit
// carry the same last-invocation ID, which positively proves that no new
// invocation occurred between them.
func TestLiveFixtureSaymer3StoppedUnitKeepsLastInvocation(t *testing.T) {
	o := observeFixture(t, "saymer3-2026-10-27-apt-daily-stopped.stdout", Unit("apt-daily.service"))
	if o.Status != StatusPresent {
		t.Fatalf("the stopped unit's field output must parse as PRESENT, got %s (%v)", o.Status, o.Reasons)
	}
	if o.ActiveState != "inactive" || o.SubState != "dead" || o.MainPID != "0" {
		t.Fatalf("the stopped shape must be inactive/dead with no main process: %+v", o)
	}
	if o.ExecMainStartTimestamp == "" || o.ExecMainStartTimestampMonotonic == "" || o.InvocationID == "" {
		t.Fatalf("a stopped unit must keep its last invocation identity: %+v", o)
	}
	if !validInvocationID(o.InvocationID) {
		t.Fatalf("the last-invocation ID %q must be well-formed 32-hex", o.InvocationID)
	}
	ev, _ := Compare(o, o)
	if ev != NoNewInvocation {
		t.Fatalf("the untouched stopped pair (same last-invocation ID) must be NO_NEW_INVOCATION, got %s", ev)
	}
}

// Procedure §4, never-started branch (real unit emergency.service, which
// has not run since boot): all start-identity facts are empty/zero and the
// invocation channel is absent. The snapshot still parses as PRESENT, and
// a comparison over it fails closed to INVOCATION_UNPROVABLE — an absent
// channel never produces an identity verdict by itself.
func TestLiveFixtureSaymer3NeverRanUnitFailsClosed(t *testing.T) {
	o := observeFixture(t, "saymer3-2026-10-27-emergency-never-ran.stdout", Unit("emergency.service"))
	if o.Status != StatusPresent {
		t.Fatalf("the never-ran unit's field output must parse as PRESENT, got %s (%v)", o.Status, o.Reasons)
	}
	if o.ExecMainStartTimestamp != "" || o.ExecMainStartTimestampMonotonic != "0" || o.InvocationID != "" || o.MainPID != "0" {
		t.Fatalf("the never-ran shape must be empty/zero start identity: %+v", o)
	}
	ev, reasons := Compare(o, o)
	if ev != InvocationUnprovable {
		t.Fatalf("a never-ran pair (no invocation channel) must fail closed to UNPROVABLE, got %s (%v)", ev, reasons)
	}
	if strings.Contains(strings.Join(reasons, "; "), "no new invocation") {
		t.Fatalf("the never-ran pair must not claim absence of an invocation: %v", reasons)
	}
}
