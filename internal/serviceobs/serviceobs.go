// Package serviceobs is the first independent, READ-ONLY service
// observation component (ZAI-113): typed, hermetically testable facts
// about one systemd unit's live state and invocation identity.
//
// What it proves: a PRESENT snapshot of the unit's reported state
// (ActiveState/SubState/MainPID/ExecMainEnterTimestamp/NRestarts) and —
// by comparing two PRESENT snapshots — whether systemd established a NEW
// invocation between them (MainPID or ExecMainEnterTimestamp changed).
//
// What it does NOT prove: that a specific `systemctl restart` caused the
// change (the observer sees machine state, not the act), and — critically
// — `ActiveState=active` alone is NEVER restart evidence: an
// active-before/active-after pair with identical invocation identity is
// RestartNotProven. Where systemd reports no invocation identity, restart
// occurrence is RestartUnprovable. NRestarts counts automatic restarts
// only and is carried as an informational fact, never as evidence.
//
// Boundary: read-only by construction — the only command shape is
// `systemctl show <unit> --property=…`; no mutation verbs exist here. The
// observer returns typed facts only; it does NOT produce an
// ownership.SpecHash. The SERVICE ActionSpec domain ({Name, Operation}) is
// intent, and no semantic mapping from a runtime service state to that
// domain is demonstrated — manufacturing a compatible hash from the
// intended spec would be laundering intent into evidence (never done
// here). Recording observed SERVICE evidence durably therefore requires
// either a separately decided typed-fact contract or an owner-approved
// hash domain; wiring into the journal is deliberately absent.
package serviceobs

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Unit is an exact, validated systemd service coordinate. The zero value
// is not valid; the only constructor validates the systemd unit-name shape
// (plain unit name, safe as a single argv element of systemctl).
type Unit string

// validUnitName mirrors systemd's own unit-name grammar for the .service
// subset: ASCII letters, digits and _ . @ - :, no leading '-' or '.', no
// whitespace or path separators, ending in ".service", bounded length.
func validUnitName(s string) bool {
	if s == "" || len(s) > 255 || !strings.HasSuffix(s, ".service") {
		return false
	}
	if s[0] == '-' || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '@' || c == '-' || c == ':':
		default:
			return false
		}
	}
	return true
}

// UnitForResource validates the exact service resource coordinate used by
// plans and the discovery model ("service.<unit>") and returns the unit.
// Unknown formats fail closed; nothing is guessed from names.
func UnitForResource(resource string) (Unit, error) {
	const prefix = "service."
	if !strings.HasPrefix(resource, prefix) {
		return "", fmt.Errorf("service observation requires a %q resource coordinate, got %q", prefix, resource)
	}
	name := strings.TrimPrefix(resource, prefix)
	if !validUnitName(name) {
		return "", fmt.Errorf("resource %q does not carry a valid systemd unit name; refusing to observe", resource)
	}
	return Unit(name), nil
}

// Runner is the injected read-only execution dependency. Production
// supplies systemctl through exec; tests inject canned output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Status is the closed snapshot vocabulary: the unit's property set was
// observed (Present), could not be obtained or parsed (Unknown), or the
// query itself failed (Error). Unknown and Error are distinct: Unknown is
// a machine-fact shape (no usable evidence), Error is a tool/environment
// failure — neither is ever reported as Present.
type Status string

const (
	StatusPresent Status = "PRESENT"
	StatusUnknown Status = "UNKNOWN"
	StatusError   Status = "ERROR"
)

// Observation is one read-only snapshot of one unit. String fields carry
// systemd's verbatim property values (no normalization, no synthesis —
// absence stays absent).
type Observation struct {
	Unit                   Unit
	Status                 Status
	ActiveState            string
	SubState               string
	MainPID                string
	ExecMainEnterTimestamp string
	NRestarts              string
	Reasons                []string
}

// showProperties is the exact read-only query surface. Every observation
// runs exactly this command shape — no other command exists in this
// package, and no mutation verb can be constructed.
func showProperties(ctx context.Context, runner Runner, unit Unit) ([]byte, error) {
	return runner(ctx, "systemctl", "show", string(unit),
		"--property=ActiveState",
		"--property=SubState",
		"--property=MainPID",
		"--property=ExecMainEnterTimestamp",
		"--property=NRestarts",
	)
}

// Observe takes one read-only snapshot of the unit. A failed query is an
// error (StatusError); output that does not parse into a usable property
// set is a machine-fact Unknown, never guessed into Present.
func Observe(ctx context.Context, runner Runner, unit Unit) (Observation, error) {
	if unit == "" {
		return Observation{}, fmt.Errorf("service observation requires a validated Unit (use UnitForResource)")
	}
	out, err := showProperties(ctx, runner, unit)
	if err != nil {
		return Observation{
			Unit: unit, Status: StatusError,
			Reasons: []string{"systemctl show failed: " + err.Error()},
		}, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return Observation{
				Unit: unit, Status: StatusUnknown,
				Reasons: []string{fmt.Sprintf("unparseable systemctl output line %q", line)},
			}, nil
		}
		if prev, dup := props[k]; dup && prev != v {
			return Observation{
				Unit: unit, Status: StatusUnknown,
				Reasons: []string{fmt.Sprintf("contradictory repeated property %s=%q then %s=%q", k, prev, k, v)},
			}, nil
		}
		props[k] = v
	}
	active, hasActive := props["ActiveState"]
	if !hasActive || strings.TrimSpace(active) == "" {
		missing := []string{"ActiveState"}
		for _, k := range []string{"SubState", "MainPID", "ExecMainEnterTimestamp", "NRestarts"} {
			if _, ok := props[k]; !ok {
				missing = append(missing, k)
			}
		}
		return Observation{
			Unit: unit, Status: StatusUnknown,
			Reasons: []string{"systemctl answered without a usable property set (missing: " + strings.Join(missing, ", ") + ")"},
		}, nil
	}
	o := Observation{
		Unit:                   unit,
		Status:                 StatusPresent,
		ActiveState:            props["ActiveState"],
		SubState:               props["SubState"],
		MainPID:                props["MainPID"],
		ExecMainEnterTimestamp: props["ExecMainEnterTimestamp"],
		NRestarts:              props["NRestarts"],
	}
	// NRestarts is informational only: it counts automatic restarts and is
	// never restart evidence. A non-numeric value is not an error — the
	// fact is carried verbatim with a reason.
	if o.NRestarts != "" {
		if _, err := strconv.Atoi(o.NRestarts); err != nil {
			o.Reasons = append(o.Reasons, fmt.Sprintf("NRestarts=%q is not numeric; carried verbatim, never used as evidence", o.NRestarts))
		}
	}
	return o, nil
}

// RestartEvidence is the closed comparison vocabulary across two PRESENT
// snapshots of the same unit.
type RestartEvidence string

const (
	// RestartObserved: systemd's invocation identity changed between the
	// snapshots (MainPID or ExecMainEnterTimestamp) — a new invocation was
	// established. This is evidence of a new invocation, not proof that a
	// particular restart COMMAND caused it.
	RestartObserved RestartEvidence = "RESTART_OBSERVED"
	// RestartNotProven: the unit was present and comparable with identical
	// invocation identity — active==active alone never proves a restart.
	RestartNotProven RestartEvidence = "RESTART_NOT_PROVEN"
	// RestartUnprovable: invocation identity is missing on either side —
	// restart occurrence cannot be established (fail closed, never guessed).
	RestartUnprovable RestartEvidence = "RESTART_UNPROVABLE"
	// RestartNotComparable: at least one snapshot is not PRESENT, or the
	// units differ — no comparison is possible.
	RestartNotComparable RestartEvidence = "RESTART_NOT_COMPARABLE"
)

// Compare classifies restart evidence across two PRESENT snapshots of the
// SAME unit. Deterministic and fail-closed: missing invocation identity,
// non-present snapshots and unit mismatches are classified, never guessed
// around, and never fall back to any intended specification.
func Compare(before, after Observation) (RestartEvidence, []string) {
	if before.Unit != after.Unit || before.Unit == "" {
		return RestartNotComparable, []string{"comparison requires two snapshots of the same validated unit"}
	}
	if before.Status != StatusPresent || after.Status != StatusPresent {
		return RestartNotComparable, []string{
			fmt.Sprintf("comparison requires PRESENT snapshots, got before=%s after=%s", before.Status, after.Status),
		}
	}
	// A positive observable change IS evidence even with an incomplete
	// identity pair: e.g. MainPID "0" (no process) moving to a real PID is
	// systemd establishing a new invocation.
	if before.MainPID != after.MainPID || before.ExecMainEnterTimestamp != after.ExecMainEnterTimestamp {
		return RestartObserved, []string{
			fmt.Sprintf("invocation identity changed: MainPID %q -> %q, ExecMainEnterTimestamp %q -> %q", before.MainPID, after.MainPID, before.ExecMainEnterTimestamp, after.ExecMainEnterTimestamp),
		}
	}
	// No observable change: only a COMPLETE identity pair (both fields
	// present on both sides) can rule a restart out. A partial pair (PID
	// without a timestamp, or vice versa) cannot — process-ID reuse or an
	// unrecorded start would look identical — so it fails closed.
	complete := func(o Observation) bool { return o.MainPID != "" && o.ExecMainEnterTimestamp != "" }
	if !complete(before) || !complete(after) {
		return RestartUnprovable, []string{
			"invocation identity is incomplete (MainPID/ExecMainEnterTimestamp missing on at least one side) and nothing observable changed; restart occurrence cannot be established",
		}
	}
	return RestartNotProven, []string{
		fmt.Sprintf("identical invocation identity across snapshots (MainPID %q, ExecMainEnterTimestamp %q); the unit is reported %q in both, and active==active alone never proves a restart", before.MainPID, before.ExecMainEnterTimestamp, after.ActiveState),
	}
}
