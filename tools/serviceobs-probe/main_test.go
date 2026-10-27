package main

// Hermetic tests for the probe's classification battery (ZAI-118): the
// observation dependency is injected, no process is ever started, no
// real systemd is touched.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/serviceobs"
)

// slowObserve models a cooperating runner whose query is slower than the
// probe's 100 ms cancellation budget: the deadline fires first, so the
// timeout check exercises the genuine cancellation path.
func slowObserve(answer func(unit serviceobs.Unit) (serviceobs.Observation, error)) observeFunc {
	return func(ctx context.Context, unit serviceobs.Unit) (serviceobs.Observation, error) {
		select {
		case <-ctx.Done():
			return serviceobs.Observation{Unit: unit, Status: serviceobs.StatusError, Reasons: []string{"systemctl show failed: " + ctx.Err().Error()}},
				fmt.Errorf("systemctl query cancelled or timed out: %w", ctx.Err())
		case <-time.After(time.Second):
		}
		return answer(unit)
	}
}

func presentFail2ban() serviceobs.Observation {
	return serviceobs.Observation{
		Unit: defaultUnit, Status: serviceobs.StatusPresent,
		ActiveState: "active", SubState: "running", MainPID: "799",
		ExecMainStartTimestamp:          "Sun 2026-10-25 20:45:44 MSK",
		ExecMainStartTimestampMonotonic: "9946341",
		InvocationID:                    "a8f6e6a6a8a64bd2bde1f655137127ac",
		NRestarts:                       "0", LoadState: "loaded",
	}
}

func notFoundSnapshot() serviceobs.Observation {
	return serviceobs.Observation{
		Unit: notFoundUnit, Status: serviceobs.StatusUnknown, LoadState: "not-found",
		Reasons: []string{"systemd reports LoadState=not-found: the unit does not exist on this machine; the synthesized inactive/dead property set is systemctl synthesis, not evidence of an existing service"},
	}
}

// The full PASS battery: a healthy present unit, a not-found synthesis,
// an untouched pair and a firing timeout.
func TestProbeFullBatteryPasses(t *testing.T) {
	calls := 0
	var out bytes.Buffer
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		calls++
		switch unit {
		case defaultUnit:
			return presentFail2ban(), nil
		case notFoundUnit:
			return notFoundSnapshot(), nil
		}
		return serviceobs.Observation{}, errors.New("unexpected unit")
	})
	code := run(nil, &out, observe)
	if code != 0 {
		t.Fatalf("the healthy battery must pass, code=%d output:\n%s", code, out.String())
	}
	if calls != 3 { // snapshot 1, not-found, snapshot 2 — the timeout call is cancelled before reaching the answer
		t.Fatalf("expected 3 answered observations, got %d", calls)
	}
	for _, want := range []string{
		"[PASS] working fail2ban.service is PRESENT",
		"[SKIP] existing-unit check",
		"[PASS] nonexistent " + string(notFoundUnit) + " is UNKNOWN",
		"[PASS] untouched running pair is NO_NEW_INVOCATION",
		"[PASS] cancellation reporting of the exec path (pre-expired budget)",
		"probe verdict: PASS",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

// The optional extra-unit argument is snapshotted once and expected
// PRESENT.
func TestProbeExtraUnitCheck(t *testing.T) {
	var out bytes.Buffer
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		switch unit {
		case defaultUnit:
			return presentFail2ban(), nil
		case notFoundUnit:
			return notFoundSnapshot(), nil
		case serviceobs.Unit("emergency.service"):
			o := presentFail2ban()
			o.Unit = unit
			o.ActiveState, o.SubState, o.MainPID = "inactive", "dead", "0"
			o.ExecMainStartTimestamp, o.ExecMainStartTimestampMonotonic, o.InvocationID = "", "0", ""
			return o, nil
		}
		return serviceobs.Observation{}, errors.New("unexpected unit")
	})
	code := run([]string{"service.emergency.service"}, &out, observe)
	if code != 0 {
		t.Fatalf("the extra-unit battery must pass, code=%d output:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "[PASS] existing unit emergency.service is PRESENT") {
		t.Fatalf("the extra-unit check must run and pass:\n%s", out.String())
	}
}

// A synthesized not-found set classified as PRESENT (the ZAI-117 defect
// shape) must fail the probe.
func TestProbeDetectsPresentNotFound(t *testing.T) {
	var out bytes.Buffer
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		if unit == notFoundUnit {
			bad := notFoundSnapshot()
			bad.Status = serviceobs.StatusPresent // the pre-fix defect shape
			return bad, nil
		}
		return presentFail2ban(), nil
	})
	code := run(nil, &out, observe)
	if code != 1 {
		t.Fatalf("a PRESENT not-found must fail the probe, code=%d", code)
	}
	if !strings.Contains(out.String(), "[FAIL] nonexistent") || !strings.Contains(out.String(), "probe verdict: FAIL") {
		t.Fatalf("the not-found failure must be reported:\n%s", out.String())
	}
}

// An invocation CHANGE between the two snapshots (the unit really
// restarted) is reported honestly and fails the expectation — never
// provoked, never hidden.
func TestProbeDetectsUnexpectedRestart(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		if unit != defaultUnit {
			return notFoundSnapshot(), nil
		}
		calls++
		o := presentFail2ban()
		if calls >= 2 { // second snapshot: a genuinely new invocation
			o.InvocationID = "b8f6e6a6a8a64bd2bde1f655137127ac"
			o.MainPID = "1001"
			o.ExecMainStartTimestampMonotonic = "99000001"
		}
		return o, nil
	})
	code := run(nil, &out, observe)
	if code != 1 {
		t.Fatalf("an unexpected restart must fail the probe, code=%d", code)
	}
	if !strings.Contains(out.String(), "detected a NEW unit invocation between the snapshots") {
		t.Fatalf("the honest new-invocation report is missing:\n%s", out.String())
	}
}

// A timeout that does NOT fire must fail the cancellation check: the
// probe proves the exec path is cancellable, not that queries are slow.
func TestProbeDetectsNonCancellablePath(t *testing.T) {
	var out bytes.Buffer
	observe := func(ctx context.Context, unit serviceobs.Unit) (serviceobs.Observation, error) {
		// Deliberately ignores ctx — the defect the check exists to catch.
		if unit == notFoundUnit {
			return notFoundSnapshot(), nil
		}
		return presentFail2ban(), nil
	}
	code := run(nil, &out, observe)
	if code != 1 {
		t.Fatalf("a non-cancellable path must fail the probe, code=%d", code)
	}
	if !strings.Contains(out.String(), "[FAIL] cancellation reporting of the exec path (pre-expired budget)") {
		t.Fatalf("the cancellation failure must be reported:\n%s", out.String())
	}
}

// An UNDETERMINED comparison (the after-snapshot lost its invocation
// identity, so Compare cannot answer) is reported as undetermined —
// never inflated into either the new-invocation or the no-change claim.
func TestProbeReportsUndeterminedComparison(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		if unit == notFoundUnit {
			return notFoundSnapshot(), nil
		}
		calls++
		o := presentFail2ban()
		if calls >= 2 { // second snapshot: identity facts missing
			o.ExecMainStartTimestamp = ""
			o.ExecMainStartTimestampMonotonic = ""
			o.InvocationID = ""
		}
		return o, nil
	})
	code := run(nil, &out, observe)
	if code != 1 {
		t.Fatalf("an undetermined comparison must fail the probe, code=%d", code)
	}
	if !strings.Contains(out.String(), "undetermined: the comparison could not answer the invocation question (INVOCATION_UNPROVABLE)") {
		t.Fatalf("the undetermined report is missing:\n%s", out.String())
	}
	if strings.Contains(out.String(), "the unit really did start") {
		t.Fatalf("an undetermined comparison must not claim the unit started:\n%s", out.String())
	}
}

// An OBSERVATION error (the second snapshot is not PRESENT → the pair is
// not comparable) is reported as an observation error — never as a
// detected invocation and never as undetermined semantics.
func TestProbeReportsObservationError(t *testing.T) {
	var out bytes.Buffer
	calls := 0
	observe := slowObserve(func(unit serviceobs.Unit) (serviceobs.Observation, error) {
		if unit == notFoundUnit {
			return notFoundSnapshot(), nil
		}
		calls++
		if calls >= 2 { // second snapshot: the query answered UNKNOWN
			return serviceobs.Observation{Unit: unit, Status: serviceobs.StatusUnknown, Reasons: []string{"injected unusable answer"}}, nil
		}
		return presentFail2ban(), nil
	})
	code := run(nil, &out, observe)
	if code != 1 {
		t.Fatalf("an observation error must fail the probe, code=%d", code)
	}
	if !strings.Contains(out.String(), "observation error: the pair is not comparable") {
		t.Fatalf("the observation-error report is missing:\n%s", out.String())
	}
}

// Malformed probe input is refused: more than one argument, or an invalid
// unit coordinate.
func TestProbeRefusesBadArguments(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"a", "b"}, &out, func(ctx context.Context, u serviceobs.Unit) (serviceobs.Observation, error) {
		return presentFail2ban(), nil
	}); code != 2 {
		t.Fatalf("two arguments must be refused, code=%d", code)
	}
	out.Reset()
	if code := run([]string{"-evil.service"}, &out, func(ctx context.Context, u serviceobs.Unit) (serviceobs.Observation, error) {
		return presentFail2ban(), nil
	}); code != 2 {
		t.Fatalf("an invalid unit coordinate must be refused, code=%d", code)
	}
}
