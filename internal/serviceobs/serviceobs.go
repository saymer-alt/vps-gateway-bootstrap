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
	InvocationID           string
	NRestarts              string
	Reasons                []string
}

// showProperties is the exact read-only query surface. Every observation
// runs exactly this command shape — no other command exists in this
// package, and no mutation verb can be constructed.
func showProperties(ctx context.Context, runner Runner, unit Unit) ([]byte, error) {
	// InvocationID (systemd-managed 128-bit per-invocation identifier,
	// exposed by `systemctl show` since the v230s; present on the
	// supported systemd 252/255 targets) is the strongest invocation
	// marker: it changes on every unit start. Its absence is a normal,
	// fail-closed case — the comparison falls back to weaker signals.
	return runner(ctx, "systemctl", "show", string(unit),
		"--property=ActiveState",
		"--property=SubState",
		"--property=MainPID",
		"--property=ExecMainEnterTimestamp",
		"--property=InvocationID",
		"--property=NRestarts",
	)
}

// Observe takes one read-only snapshot of the unit. A failed query is an
// error (StatusError); output that does not parse into a usable property
// set is a machine-fact Unknown, never guessed into Present.
func Observe(ctx context.Context, runner Runner, unit Unit) (Observation, error) {
	// Boundary validation (ZAI-114): Unit is an exported string type, so
	// callers can construct arbitrary values without UnitForResource.
	// Validate the unit-name grammar HERE, before any runner call — an
	// invalid coordinate never reaches systemctl.
	if !validUnitName(string(unit)) {
		return Observation{}, fmt.Errorf("service observation requires a valid systemd unit name (use UnitForResource), got %q", string(unit))
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
		InvocationID:           props["InvocationID"],
		NRestarts:              props["NRestarts"],
	}
	// A malformed MainPID is corrupt evidence: fail closed to Unknown —
	// optimistic restart conclusions must never rest on unparseable data.
	if o.MainPID != "" {
		if pid, err := strconv.Atoi(o.MainPID); err != nil || pid < 0 {
			o.Status = StatusUnknown
			o.Reasons = append(o.Reasons, fmt.Sprintf("MainPID=%q is not a usable process id; refusing to build evidence on malformed data", o.MainPID))
			return o, nil
		}
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
	// NoNewInvocation: the post-observation positively shows the unit is
	// not running (inactive/failed with a terminated main process) — no
	// new invocation happened, as far as the observed facts go.
	NoNewInvocation RestartEvidence = "NO_NEW_INVOCATION"
	// RestartNotComparable: at least one snapshot is not PRESENT, or the
	// units differ — no comparison is possible.
	RestartNotComparable RestartEvidence = "RESTART_NOT_COMPARABLE"
)

// Compare classifies restart evidence across two PRESENT snapshots of the
// SAME unit. RESTART_OBSERVED means a NEW unit invocation was
// independently established — it requires the post-observation to be
// non-transitional and running, AND one of:
//
//   - the systemd InvocationID changed (both present, different values) —
//     the manager itself identified a new invocation; or
//   - a start from no process (MainPID "0"/empty → a positive PID with a
//     newly appearing ExecMainEnterTimestamp); or
//   - an active→active transition where BOTH MainPID and
//     ExecMainEnterTimestamp changed (a PID-only change is insufficient:
//     it cannot distinguish a restart from PID reuse or an in-invocation
//     main-PID handoff).
//
// The post-observation being inactive or failed is NO_NEW_INVOCATION (a
// terminated main process is the opposite of a new invocation); a
// transitional post-state (activating/reloading) is UNPROVABLE; malformed
// or incomplete identity never yields a favorable result; NRestarts is
// never evidence. Deterministic, fail-closed, and never falling back to
// any intended specification. OBSERVED is evidence of a new invocation —
// it neither proves that a restart COMMAND ran nor that it caused the
// invocation.
func Compare(before, after Observation) (RestartEvidence, []string) {
	if before.Unit != after.Unit || before.Unit == "" {
		return RestartNotComparable, []string{"comparison requires two snapshots of the same validated unit"}
	}
	if before.Status != StatusPresent || after.Status != StatusPresent {
		return RestartNotComparable, []string{
			fmt.Sprintf("comparison requires PRESENT snapshots, got before=%s after=%s", before.Status, after.Status),
		}
	}
	// Post-state classification: a stopping or failing service is the
	// opposite of a restart; a transitional state cannot be judged.
	switch after.ActiveState {
	case "active":
	case "inactive", "failed":
		if after.MainPID == "0" || after.MainPID == "" {
			return NoNewInvocation, []string{
				fmt.Sprintf("the unit is %q after the observation with no running main process (MainPID=%q); no new invocation occurred", after.ActiveState, after.MainPID),
			}
		}
		return RestartUnprovable, []string{
			fmt.Sprintf("the unit is %q with a non-terminated main process; restart occurrence cannot be established from this state", after.ActiveState),
		}
	default:
		// activating/reloading/unknown post-states are transitional or
		// unusable — never a favorable restart conclusion.
		return RestartUnprovable, []string{
			fmt.Sprintf("the post-observation state %q is transitional or unusable; restart evidence requires a settled %q state", after.ActiveState, "active"),
		}
	}
	if !validPositivePID(after.MainPID) {
		return RestartUnprovable, []string{
			fmt.Sprintf("the post-observation MainPID %q is not a usable process id; no favorable conclusion may rest on it", after.MainPID),
		}
	}
	// Strongest signal: the manager changed the unit's invocation.
	if before.InvocationID != "" && after.InvocationID != "" && before.InvocationID != after.InvocationID {
		return RestartObserved, []string{
			fmt.Sprintf("systemd established a new invocation: InvocationID changed %q -> %q", before.InvocationID, after.InvocationID),
		}
	}
	// Start-from-nothing: no main process before, a real process with a
	// newly appearing enter timestamp after.
	started := func(o Observation) bool { return o.MainPID != "0" && o.MainPID != "" }
	if !started(before) && started(after) && before.ExecMainEnterTimestamp == "" && after.ExecMainEnterTimestamp != "" {
		return RestartObserved, []string{
			fmt.Sprintf("the unit started from no process: MainPID %q -> %q with a newly appearing ExecMainEnterTimestamp", before.MainPID, after.MainPID),
		}
	}
	// Active→active with BOTH the PID and the enter timestamp changed: the
	// unit re-entered running for a new main process — sufficient evidence
	// of a new invocation. A PID-only change is NOT: PID reuse or an
	// in-invocation main-PID handoff would look identical.
	if before.MainPID != after.MainPID && before.ExecMainEnterTimestamp != after.ExecMainEnterTimestamp {
		return RestartObserved, []string{
			fmt.Sprintf("the unit re-entered running for a new main process: MainPID %q -> %q, ExecMainEnterTimestamp %q -> %q", before.MainPID, after.MainPID, before.ExecMainEnterTimestamp, after.ExecMainEnterTimestamp),
		}
	}
	if before.MainPID != after.MainPID {
		return RestartUnprovable, []string{
			fmt.Sprintf("only MainPID changed (%q -> %q) with an identical enter timestamp; a restart cannot be distinguished from PID reuse or an in-invocation main-PID handoff", before.MainPID, after.MainPID),
		}
	}
	// Identical snapshots. Only a complete identity pair can rule a
	// restart out; a partial pair fails closed.
	complete := func(o Observation) bool { return o.MainPID != "" && o.ExecMainEnterTimestamp != "" }
	if !complete(before) || !complete(after) {
		return RestartUnprovable, []string{
			"invocation identity is incomplete (MainPID/ExecMainEnterTimestamp missing on at least one side) and nothing observable changed; restart occurrence cannot be established",
		}
	}
	return RestartNotProven, []string{
		fmt.Sprintf("identical invocation identity across snapshots (MainPID %q, ExecMainEnterTimestamp %q, InvocationID %q); the unit is reported %q in both, and active==active alone never proves a restart", before.MainPID, before.ExecMainEnterTimestamp, before.InvocationID, after.ActiveState),
	}
}

// validPositivePID reports whether s parses as a usable (positive) main
// process id for evidence purposes.
func validPositivePID(s string) bool {
	pid, err := strconv.Atoi(s)
	return err == nil && pid > 0
}
