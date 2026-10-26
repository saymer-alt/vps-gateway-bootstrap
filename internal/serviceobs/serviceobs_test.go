package serviceobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// Adversarial matrix (ZAI-113 Phase 6; semantics reworked in ZAI-115).
// All fixtures are injected runner output — synthetic only, no real
// systemd. The property names follow the authoritative systemd v255
// BUS_EXEC_STATUS_VTABLE("ExecMain", …) expansion; the phantom
// "ExecMainEnterTimestamp" (a wrong ZAI-114 research note) must never be
// queried or carried.

const testUnit = Unit("fail2ban.service")

const invA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1" // valid 32-hex InvocationID
const invB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2" // valid, different
const invBad = "not-a-valid-invocation-id!!"    // malformed

func showOutput(active, sub, pid, startTS, mono, restarts string) string {
	return "ActiveState=" + active + "\n" +
		"SubState=" + sub + "\n" +
		"MainPID=" + pid + "\n" +
		"ExecMainStartTimestamp=" + startTS + "\n" +
		"ExecMainStartTimestampMonotonic=" + mono + "\n" +
		"NRestarts=" + restarts + "\n"
}

func withInvocation(out, id string) string { return out + "InvocationID=" + id + "\n" }

func okRunner(out string) Runner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte(out), nil
	}
}

func observeOK(t *testing.T, out string) Observation {
	t.Helper()
	o, err := Observe(context.Background(), okRunner(out), testUnit)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return o
}

// Unit coordinate validation: exact service.* coordinate, systemd unit
// shape, option-like/path-like/empty/foreign coordinates refused.
func TestUnitForResourceValidation(t *testing.T) {
	for _, tc := range []struct {
		in   string
		ok   bool
		unit Unit
	}{
		{"service.fail2ban.service", true, Unit("fail2ban.service")},
		{"service.my-unit_2.service", true, Unit("my-unit_2.service")},
		{"fail2ban.service", false, ""},
		{"service.service", false, ""},
		{"service.no-suffix", false, ""},
		{"service.", false, ""},
		{"service.-evil.service", false, ""},
		{"service..hidden.service", false, ""},
		{"service.white space.service", false, ""},
		{"service../etc/passwd", false, ""},
		{"docker.container.x", false, ""},
		{"", false, ""},
	} {
		u, err := UnitForResource(tc.in)
		if tc.ok && (err != nil || u != tc.unit) {
			t.Fatalf("%q: want unit %q, got %q / %v", tc.in, tc.unit, u, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("%q: must be refused, got %q", tc.in, u)
		}
	}
}

// The command surface is read-only and exact: one call, systemctl show,
// the validated unit, the REAL main-process identity properties — no
// mutation verbs, and never the nonexistent ExecMainEnterTimestamp
// property (BUS_EXEC_STATUS_VTABLE expansion, systemd v255).
func TestObserveCommandSurfaceReadOnly(t *testing.T) {
	var calls [][]string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte(showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0")), nil
	}
	if _, err := Observe(context.Background(), runner, testUnit); err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("exactly one query expected, got %v", calls)
	}
	if calls[0][0] != "systemctl" || calls[0][1] != "show" || calls[0][2] != string(testUnit) {
		t.Fatalf("unexpected command shape: %v", calls[0])
	}
	joined := strings.Join(calls[0], " ")
	if strings.Contains(joined, "ExecMainEnterTimestamp") {
		t.Fatalf("the command surface must not query the nonexistent ExecMainEnterTimestamp property: %v", calls[0])
	}
	for _, want := range []string{"--property=ActiveState", "--property=MainPID", "--property=ExecMainStartTimestamp", "--property=ExecMainStartTimestampMonotonic", "--property=InvocationID"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the command surface must query %s: %v", want, calls[0])
		}
	}
	for _, a := range calls[0] {
		for _, verb := range []string{"start", "stop", "restart", "reload", "kill", "enable", "disable"} {
			if a == verb {
				t.Fatalf("mutation verb %q in command: %v", verb, calls[0])
			}
		}
	}
}

// A start from a not-running state is a new invocation: inactive→active
// requires a start job, and every start acquires a fresh invocation.
func TestCompareStartFromNotRunningObserved(t *testing.T) {
	before := observeOK(t, showOutput("inactive", "dead", "0", "", "0", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:01 UTC", "5000", "0"))
	ev, reasons := Compare(before, after)
	if ev != InvocationObserved {
		t.Fatalf("want NEW_INVOCATION_OBSERVED, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "not-running state") {
		t.Fatalf("the reason must state the start-from-not-running ground: %v", reasons)
	}
	// A failed pre-state with no process behaves the same.
	beforeFailed := observeOK(t, showOutput("failed", "failed", "0", "", "0", "0"))
	ev, _ = Compare(beforeFailed, after)
	if ev != InvocationObserved {
		t.Fatalf("failed→active with a main process must be NEW_INVOCATION_OBSERVED, got %s", ev)
	}
}

// Identical main-process identity with no InvocationID pair: restart NOT
// proven, whatever the state says — and identity equality cannot rule a
// restart out either (timestamp-resolution + PID-reuse edge).
func TestCompareActiveToActiveIdenticalNotProven(t *testing.T) {
	out := showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0")
	before := observeOK(t, out)
	after := observeOK(t, out)
	ev, reasons := Compare(before, after)
	if ev != InvocationNotProven {
		t.Fatalf("want INVOCATION_NOT_PROVEN, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "never proves or disproves") {
		t.Fatalf("the reason must state the active==active rule: %v", reasons)
	}
}

// The manager's own identity channel: both InvocationIDs present and
// different → a new invocation was established, without proving command
// causality.
func TestCompareDifferentInvocationIDsObservedNoCausality(t *testing.T) {
	before := observeOK(t, withInvocation(showOutput("active", "running", "1234", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"), invA))
	after := observeOK(t, withInvocation(showOutput("active", "running", "1234", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"), invB))
	ev, reasons := Compare(before, after)
	if ev != InvocationObserved {
		t.Fatalf("want NEW_INVOCATION_OBSERVED via InvocationID, got %s (%v)", ev, reasons)
	}
	joined := strings.Join(reasons, "; ")
	if !strings.Contains(joined, "new invocation") {
		t.Fatalf("the reason must say systemd established a new invocation: %v", reasons)
	}
	if strings.Contains(joined, "proves that a particular restart command caused") && !strings.Contains(joined, "not proof") {
		t.Fatalf("the reason must carry the causality boundary: %v", reasons)
	}
	// And it decides even when the unit then failed: the new invocation
	// happened, then the unit stopped.
	failedAfter := observeOK(t, withInvocation(showOutput("failed", "failed", "0", "", "0", "3"), invB))
	ev, _ = Compare(before, failedAfter)
	if ev != InvocationObserved {
		t.Fatalf("a changed InvocationID proves a new invocation regardless of post-state, got %s", ev)
	}
}

// Same well-formed InvocationID on both sides positively proves that no
// new invocation occurred — even with a changed main process (an
// in-invocation MAINPID= handoff refreshes the start timestamp without a
// new invocation; service_set_main_pid → exec_status_start).
func TestCompareSameInvocationIDPositivelyNoNewInvocation(t *testing.T) {
	before := observeOK(t, withInvocation(showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"), invA))
	after := observeOK(t, withInvocation(showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:05 UTC", "5000", "0"), invA))
	ev, reasons := Compare(before, after)
	if ev != NoNewInvocation {
		t.Fatalf("same InvocationID must positively prove no new invocation, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), invA) {
		t.Fatalf("the reason must cite the persisted InvocationID: %v", reasons)
	}
	// Identical snapshots carrying the ID classify the same way.
	out := withInvocation(showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"), invA)
	ev, _ = Compare(observeOK(t, out), observeOK(t, out))
	if ev != NoNewInvocation {
		t.Fatalf("identical snapshots with a valid InvocationID must be NO_NEW_INVOCATION, got %s", ev)
	}
	// A same-ID unit that stopped inside the window also proves no new
	// invocation (the invocation persisted, then ended).
	stoppedAfter := observeOK(t, withInvocation(showOutput("inactive", "dead", "0", "", "0", "0"), invA))
	ev, _ = Compare(before, stoppedAfter)
	if ev != NoNewInvocation {
		t.Fatalf("same InvocationID with an inactive post-state must be NO_NEW_INVOCATION, got %s", ev)
	}
}

// A malformed nonempty InvocationID can never support a favorable
// verdict — garbage values must not be compared as "changed", and the
// reasons must name the malformed channel.
func TestCompareMalformedInvocationIDCannotSupportFavorable(t *testing.T) {
	before := observeOK(t, withInvocation(showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"), invBad))
	after := observeOK(t, withInvocation(showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:05 UTC", "5000", "0"), invB))
	ev, reasons := Compare(before, after)
	if ev == InvocationObserved {
		t.Fatalf("a malformed InvocationID must never yield a favorable verdict (%v)", reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "malformed") {
		t.Fatalf("the reason must name the malformed InvocationID channel: %v", reasons)
	}
	// Malformed on both sides: the same refusal.
	ev, _ = Compare(observeOK(t, withInvocation(showOutput("active", "running", "1", "t1", "1", "0"), invBad)),
		observeOK(t, withInvocation(showOutput("active", "running", "2", "t2", "2", "0"), strings.ToUpper(invBad))))
	if ev == InvocationObserved {
		t.Fatal("two malformed InvocationIDs must never yield a favorable verdict")
	}
	// Observe carries the malformed value verbatim with a reason while the
	// other facts stay usable.
	o := observeOK(t, withInvocation(showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"), invBad))
	if o.Status != StatusPresent {
		t.Fatalf("a malformed InvocationID must not invalidate the snapshot, got %s", o.Status)
	}
	if !strings.Contains(strings.Join(o.Reasons, "; "), "InvocationID") {
		t.Fatalf("the snapshot must carry a reason about the malformed InvocationID: %v", o.Reasons)
	}
}

// An inactive/failed post-state WITHOUT InvocationID guidance must not
// claim that no invocation occurred in the window — the unit could have
// restarted and stopped again between the snapshots. (ZAI-115 refines the
// ZAI-114 NO_NEW_INVOCATION, which reserved that verdict for the
// post-state shape and overclaimed the interval.)
func TestCompareNotRunningPostStateWithoutInvocationIDUnprovable(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"))
	for _, tc := range []struct{ state, sub string }{
		{"inactive", "dead"}, {"failed", "failed"},
	} {
		after := observeOK(t, showOutput(tc.state, tc.sub, "0", "", "0", "0"))
		ev, reasons := Compare(before, after)
		if ev != InvocationUnprovable {
			t.Fatalf("%s post-state without InvocationID guidance must be UNPROVABLE, got %s (%v)", tc.state, ev, reasons)
		}
		joined := strings.Join(reasons, "; ")
		if strings.Contains(joined, "no new invocation occurred between the snapshots") {
			t.Fatalf("the reason must not claim no invocation occurred in the window: %v", reasons)
		}
		if !strings.Contains(joined, "could have occurred and ended") {
			t.Fatalf("the reason must state the restart-and-stop possibility: %v", reasons)
		}
	}
}

// A main-process identity change with no InvocationID pair is process
// replacement evidence only — never invocation evidence.
func TestCompareProcessReplacementIsNotInvocationEvidence(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"))
	after := observeOK(t, showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:05 UTC", "5000", "0"))
	ev, reasons := Compare(before, after)
	if ev != MainProcessChanged {
		t.Fatalf("want MAIN_PROCESS_CHANGED, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "not decided") {
		t.Fatalf("the reason must state that the invocation question is not decided: %v", reasons)
	}
	// Start-identity change with a coincidentally equal PID (reuse) is the
	// same classification.
	samePIDAfter := observeOK(t, showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:05 UTC", "5000", "0"))
	ev, _ = Compare(before, samePIDAfter)
	if ev != MainProcessChanged {
		t.Fatalf("an equal PID with a changed start identity must be MAIN_PROCESS_CHANGED, got %s", ev)
	}
	// Formatted-timestamp fallback when the monotonic value is unusable.
	noMonoAfter := observeOK(t, showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:05 UTC", "", "0"))
	ev, _ = Compare(observeOK(t, showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "", "0")), noMonoAfter)
	if ev != MainProcessChanged {
		t.Fatalf("formatted-timestamp fallback must classify MAIN_PROCESS_CHANGED, got %s", ev)
	}
	// Same-second formatted timestamps with no monotonic values: not
	// provable (fail closed).
	ev, _ = Compare(observeOK(t, showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "", "0")),
		observeOK(t, showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:00 UTC", "", "0")))
	if ev != InvocationUnprovable {
		t.Fatalf("identical second-granularity timestamps must stay UNPROVABLE, got %s", ev)
	}
}

// A PID-only change is insufficient: PID reuse or an in-invocation
// main-PID handoff would look identical.
func TestComparePIDOnlyChangeUnprovable(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1111", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"))
	after := observeOK(t, showOutput("active", "running", "2222", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"))
	ev, reasons := Compare(before, after)
	if ev != InvocationUnprovable {
		t.Fatalf("a PID-only change must be UNPROVABLE, got %s (%v)", ev, reasons)
	}
}

// Completely missing invocation evidence fails closed.
func TestCompareNoInvocationEvidenceFailsClosed(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "", "", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "", "", "0"))
	ev, _ := Compare(before, after)
	if ev != InvocationUnprovable {
		t.Fatalf("no invocation evidence must be UNPROVABLE, got %s", ev)
	}
}

// A query failure is StatusError with the error propagated — no
// fabricated snapshot.
func TestObserveQueryFailureIsError(t *testing.T) {
	failing := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, errors.New("injected systemctl failure")
	}
	o, err := Observe(context.Background(), failing, testUnit)
	if err == nil {
		t.Fatal("the query failure must be reported")
	}
	if o.Status != StatusError || len(o.Reasons) == 0 {
		t.Fatalf("want ERROR with reasons, got %+v", o)
	}
	if o.ActiveState != "" || o.MainPID != "" {
		t.Fatalf("a failed query must not fabricate facts: %+v", o)
	}
	ev, _ := Compare(o, o)
	if ev != NotComparable {
		t.Fatalf("an errored snapshot is not comparable, got %s", ev)
	}
}

// Contradictory repeated properties fail closed as UNKNOWN (never
// first-value-wins), and such snapshots are not comparable.
func TestObserveContradictoryPropertiesUnknown(t *testing.T) {
	out := "ActiveState=active\nSubState=running\nMainPID=1\nActiveState=failed\nMainPID=1\n"
	o := observeOK(t, out)
	if o.Status != StatusUnknown {
		t.Fatalf("contradictory properties must be UNKNOWN, got %s", o.Status)
	}
	if !strings.Contains(strings.Join(o.Reasons, "; "), "contradictory") {
		t.Fatalf("the reason must name the contradiction: %v", o.Reasons)
	}
	ev, _ := Compare(o, o)
	if ev == InvocationObserved || ev == MainProcessChanged {
		t.Fatalf("contradictory snapshots must never yield favorable evidence, got %s", ev)
	}
	// Identical repeated properties are harmless.
	ok := observeOK(t, "ActiveState=active\nActiveState=active\nSubState=running\nMainPID=5\nExecMainStartTimestamp=t\nExecMainStartTimestampMonotonic=1\nNRestarts=0\n")
	if ok.Status != StatusPresent {
		t.Fatalf("identical repeats must parse, got %s (%v)", ok.Status, ok.Reasons)
	}
}

// An unparseable line or a missing ActiveState property is an UNKNOWN
// machine fact with reasons — never Present, never guessed.
func TestObservePartialOutputUnknown(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
	}{
		{"unparseable line", "ActiveState=active\nthis is not a property\n"},
		{"missing ActiveState", "SubState=running\nMainPID=5\n"},
		{"empty output", ""},
	} {
		o := observeOK(t, tc.out)
		if o.Status != StatusUnknown {
			t.Fatalf("%s: want UNKNOWN, got %s (%v)", tc.name, o.Status, o.Reasons)
		}
		if len(o.Reasons) == 0 {
			t.Fatalf("%s: reasons required", tc.name)
		}
	}
}

// Invalid observation inputs fail closed at the API boundary — an empty
// Unit and a failed unit-validation coordinate never reach a query.
func TestObserveInvalidInputsFailClosed(t *testing.T) {
	if _, err := Observe(context.Background(), okRunner(""), Unit("")); err == nil {
		t.Fatal("an empty Unit must be refused")
	}
	for _, bad := range []string{"-evil.service", "no-suffix", "white space.service"} {
		if _, err := UnitForResource("service." + bad); err == nil {
			t.Fatalf("coordinate %q must be refused", bad)
		}
	}
}

// Structural: the observer depends on no journal and no ownership types —
// a source-level tripwire keeps the read-only component free of
// evidence-plane imports.
func TestNoEvidencePlaneImports(t *testing.T) {
	src := readFile(t, "serviceobs.go")
	for _, banned := range []string{
		"internal/journal",
		"internal/ownership",
		"internal/orchestrate",
		"internal/apply",
	} {
		if strings.Contains(src, banned) {
			t.Fatalf("serviceobs must not import the evidence/mutation plane: found %q", banned)
		}
	}
}

func readFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// NRestarts is carried verbatim as informational and never used as
// evidence: a growing NRestarts with identical invocation identity stays
// NOT_PROVEN.
func TestNRestartsNeverEvidence(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "5"))
	ev, _ := Compare(before, after)
	if ev != InvocationNotProven {
		t.Fatalf("NRestarts growth must not become restart evidence, got %s", ev)
	}
	// A malformed MainPID fails closed to UNKNOWN at observation, and no
	// favorable conclusion may rest on it.
	malformed := observeOK(t, showOutput("active", "running", "not-a-pid", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"))
	if malformed.Status != StatusUnknown {
		t.Fatalf("a malformed MainPID must be UNKNOWN, got %s (%v)", malformed.Status, malformed.Reasons)
	}
	ev, _ = Compare(before, malformed)
	if ev == InvocationObserved || ev == MainProcessChanged {
		t.Fatal("a malformed post-PID must never yield favorable evidence")
	}
	// A malformed monotonic value is carried with a fallback reason.
	fallback := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "abc", "0"))
	if !strings.Contains(strings.Join(fallback.Reasons, "; "), "ExecMainStartTimestampMonotonic") {
		t.Fatalf("the snapshot must carry a fallback reason for the malformed monotonic value: %v", fallback.Reasons)
	}
}

// A transitional post-state (activating/reloading) cannot produce
// favorable invocation evidence without an InvocationID pair.
func TestCompareTransitionalPostStateUnprovable(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "Wed 2026-10-25 09:00:00 UTC", "1000", "0"))
	after := observeOK(t, showOutput("activating", "start", "0", "", "0", "0"))
	ev, _ := Compare(before, after)
	if ev != InvocationUnprovable {
		t.Fatalf("a transitional post-state must be UNPROVABLE, got %s", ev)
	}
}

// Real property values are carried into the snapshot verbatim.
func TestObserveCarriesRealPropertyValues(t *testing.T) {
	o := observeOK(t, withInvocation(showOutput("active", "running", "1234", "Wed 2026-10-25 10:00:00 UTC", "1000", "0"), invA))
	if o.ExecMainStartTimestamp != "Wed 2026-10-25 10:00:00 UTC" {
		t.Fatalf("the formatted start timestamp must be carried: %+v", o)
	}
	if o.ExecMainStartTimestampMonotonic != "1000" {
		t.Fatalf("the monotonic start identity must be carried: %+v", o)
	}
	if o.InvocationID != invA {
		t.Fatalf("the InvocationID must be carried: %+v", o)
	}
}

// Phase 5 (ZAI-114): Unit is an exported string — directly constructed
// values are validated INSIDE Observe before any runner call; an invalid
// coordinate must fail with zero queries.
func TestObserveValidatesDirectlyConstructedUnits(t *testing.T) {
	calls := 0
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return []byte(showOutput("active", "running", "1", "t", "0", "0")), nil
	}
	for _, bad := range []Unit{
		Unit("--system"),
		Unit("../bad.service"),
		Unit("white space.service"),
		Unit(""),
		Unit("no-suffix"),
		Unit("-x.service"),
	} {
		if _, err := Observe(context.Background(), runner, bad); err == nil {
			t.Fatalf("directly constructed Unit %q must be refused", bad)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid units must fail without any runner call, got %d", calls)
	}
	// A valid directly constructed unit still works.
	if _, err := Observe(context.Background(), runner, Unit("fail2ban.service")); err != nil {
		t.Fatalf("a valid directly constructed unit must be accepted: %v", err)
	}
}
