package serviceobs

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// Adversarial matrix (ZAI-113 Phase 6). All fixtures are injected runner
// output — synthetic only, no real systemd.

const testUnit = Unit("fail2ban.service")

func showOutput(active, sub, pid, enterTS, restarts string) string {
	return "ActiveState=" + active + "\n" +
		"SubState=" + sub + "\n" +
		"MainPID=" + pid + "\n" +
		"ExecMainEnterTimestamp=" + enterTS + "\n" +
		"NRestarts=" + restarts + "\n"
}

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
// the validated unit, property flags — no mutation verbs anywhere.
func TestObserveCommandSurfaceReadOnly(t *testing.T) {
	var calls [][]string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return []byte(showOutput("active", "running", "1234", "2026-10-25T10:00:00+0000", "0")), nil
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
	for _, a := range calls[0] {
		for _, verb := range []string{"start", "stop", "restart", "reload", "kill", "enable", "disable"} {
			if a == verb {
				t.Fatalf("mutation verb %q in command: %v", verb, calls[0])
			}
		}
	}
}

// 1: inactive before (MainPID 0, no timestamp) / active after with a real
// PID and a start timestamp → the new invocation is OBSERVED.
func TestCompareInactiveToActiveObservesRestart(t *testing.T) {
	before := observeOK(t, showOutput("inactive", "dead", "0", "", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "2026-10-25T10:00:01+0000", "0"))
	ev, reasons := Compare(before, after)
	if ev != RestartObserved {
		t.Fatalf("want RESTART_OBSERVED, got %s (%v)", ev, reasons)
	}
}

// 2 + 4: active before / active after with IDENTICAL invocation identity →
// restart NOT proven, whatever the state says.
func TestCompareActiveToActiveIdenticalNotProven(t *testing.T) {
	out := showOutput("active", "running", "1234", "2026-10-25T10:00:00+0000", "0")
	before := observeOK(t, out)
	after := observeOK(t, out)
	ev, reasons := Compare(before, after)
	if ev != RestartNotProven {
		t.Fatalf("want RESTART_NOT_PROVEN, got %s (%v)", ev, reasons)
	}
	if !strings.Contains(strings.Join(reasons, "; "), "never proves a restart") {
		t.Fatalf("the reason must state the active==active rule: %v", reasons)
	}
}

// 3: active in both snapshots but the invocation identity CHANGED (new PID
// and timestamp) → observed; the state staying active proves nothing by
// itself, the identity change does.
func TestCompareChangedInvocationIdentityObserved(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1111", "2026-10-25T09:00:00+0000", "0"))
	after := observeOK(t, showOutput("active", "running", "2222", "2026-10-25T10:00:00+0000", "1"))
	ev, _ := Compare(before, after)
	if ev != RestartObserved {
		t.Fatalf("want RESTART_OBSERVED, got %s", ev)
	}
}

// 5: invocation identity missing on either side → unprovable, never
// guessed (empty timestamp fields with a PID present on both sides).
func TestCompareMissingInvocationIdentityUnprovable(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "", "0"))
	ev, reasons := Compare(before, after)
	if ev != RestartUnprovable {
		t.Fatalf("want RESTART_UNPROVABLE, got %s (%v)", ev, reasons)
	}
	// MainPID identical but timestamps absent: the identity facts are
	// missing, so even a PID match proves nothing — classified above.
}

// 6: a query failure is StatusError with the error propagated — no
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
	if ev != RestartNotComparable {
		t.Fatalf("an errored snapshot is not comparable, got %s", ev)
	}
}

// 7: contradictory repeated properties fail closed as UNKNOWN (never
// first-value-wins).
func TestObserveContradictoryPropertiesUnknown(t *testing.T) {
	out := "ActiveState=active\nSubState=running\nMainPID=1\nActiveState=failed\nMainPID=1\n"
	o := observeOK(t, out)
	if o.Status != StatusUnknown {
		t.Fatalf("contradictory properties must be UNKNOWN, got %s", o.Status)
	}
	if !strings.Contains(strings.Join(o.Reasons, "; "), "contradictory") {
		t.Fatalf("the reason must name the contradiction: %v", o.Reasons)
	}
	// Identical repeated properties are harmless.
	ok := observeOK(t, "ActiveState=active\nActiveState=active\nSubState=running\nMainPID=5\nExecMainEnterTimestamp=t\nNRestarts=0\n")
	if ok.Status != StatusPresent {
		t.Fatalf("identical repeats must parse, got %s (%v)", ok.Status, ok.Reasons)
	}
}

// 8 (part): an unparseable line or a missing ActiveState property is an
// UNKNOWN machine fact with reasons — never Present, never guessed.
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

// 9: invalid observation inputs fail closed at the API boundary — an empty
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

// 10 (structural): the observer depends on no journal and no ownership
// types — a source-level tripwire keeps the read-only component free of
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

// 11: NRestarts is carried verbatim as informational and never used as
// evidence: a growing NRestarts with identical invocation identity stays
// NOT_PROVEN.
func TestNRestartsNeverEvidence(t *testing.T) {
	before := observeOK(t, showOutput("active", "running", "1234", "ts-same", "0"))
	after := observeOK(t, showOutput("active", "running", "1234", "ts-same", "5"))
	ev, _ := Compare(before, after)
	if ev != RestartNotProven {
		t.Fatalf("NRestarts growth must not become restart evidence, got %s", ev)
	}
}
