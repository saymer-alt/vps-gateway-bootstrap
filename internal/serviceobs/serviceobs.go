// Package serviceobs is the first independent, READ-ONLY service
// observation component (ZAI-113): typed, hermetically testable facts
// about one systemd unit's live state and invocation identity.
//
// What one snapshot proves: a PRESENT set of the unit's reported facts
// (ActiveState/SubState/MainPID/ExecMainStartTimestamp(+Monotonic)/
// NRestarts/InvocationID, with LoadState as the existence discriminator —
// a synthesized not-found property set is never PRESENT). What a
// comparison of two PRESENT snapshots can
// prove, in decreasing strength (ZAI-115 semantics, grounded in the
// authoritative systemd sources):
//
//   - InvocationID channel (the manager's own identity): systemd acquires
//     a fresh random 128-bit invocation identifier on EVERY unit start
//     (service_enter_start → unit_acquire_invocation_id) and keeps it for
//     the lifetime of that invocation. Equal IDs on both sides therefore
//     positively prove that NO new invocation occurred between the
//     snapshots; different IDs positively prove that a new invocation
//     DID occur — regardless of the reported post-state (a unit may start
//     and fail again inside the window). The channel is used only when
//     both values are present and well-formed (32 hexadecimal
//     characters). A MALFORMED nonempty value makes the channel unusable
//     for that comparison — channel containment, not snapshot poisoning
//     (ZAI-116): the value itself is never compared, never treated as
//     identity evidence and never selects a branch; the degradation is
//     named in the verdict's reasons; and independently sufficient
//     weaker signals (which never consult the channel) still classify on
//     their own merits. No favorable branch is reachable through a
//     malformed value, so containment adds no false-favorable path — a
//     lying source can emit well-formed values just as easily; the
//     security boundary is the read-only command shape, not value
//     validation.
//
//   - Start from a not-running state: a unit reported inactive/failed
//     with a terminated main process that later reports active with a
//     main process MUST have been started (inactive→active requires a
//     start job), and every start is a new invocation.
//
//   - Main-process replacement: a changed main-process identity (PID
//     and/or start timestamp) without invocation-ID guidance is evidence
//     that the main process was replaced — never proof of a new unit
//     invocation: service_set_main_pid refreshes the recorded start
//     timestamp for an in-invocation MAINPID= handoff (sd_notify), so a
//     restart and a handoff produce the same pattern. MAIN_PROCESS_CHANGED
//     deliberately does not answer the invocation question.
//
// What none of this proves: that a specific `systemctl restart` command
// caused the change — the observer sees machine state, not the act.
// NRestarts counts automatic restarts only and is carried as an
// informational fact, never as evidence.
//
// Property provenance: `ExecMainEnterTimestamp` does not exist in systemd
// (the ZAI-114 research note claiming it did was wrong); the
// BUS_EXEC_STATUS_VTABLE("ExecMain", …) expansion (verified in the v255
// sources) exposes ExecMainStartTimestamp(+Monotonic),
// ExecMainExitTimestamp(+Monotonic), ExecMainPID, ExecMainCode and
// ExecMainStatus. The observer queries the REAL start-identity properties
// (formatted timestamp as the human-readable fact, monotonic microseconds
// as the machine-comparable identity).
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
	"errors"
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
	Unit                            Unit
	Status                          Status
	ActiveState                     string
	SubState                        string
	MainPID                         string
	ExecMainStartTimestamp          string
	ExecMainStartTimestampMonotonic string
	InvocationID                    string
	NRestarts                       string
	Reasons                         []string
}

// showProperties is the exact read-only query surface. Every observation
// runs exactly this command shape — no other command exists in this
// package, and no mutation verb can be constructed. The properties are
// the REAL systemd ExecMain identity facts (see the package
// documentation for the BUS_EXEC_STATUS_VTABLE provenance);
// ExecMainStartTimestampMonotonic is the machine-comparable start-time
// identity, ExecMainStartTimestamp its human-readable counterpart.
// InvocationID (systemd-managed 128-bit per-invocation identifier, the
// manager acquires a fresh one on every unit start) is the strongest
// invocation marker; its absence is a normal, fail-closed case — the
// comparison then falls back to the strictly weaker signals.
// LoadState is the existence discriminator (ZAI-117 field evidence): on
// systemd 255 a missing unit name is not a query failure — `systemctl
// show` synthesizes a full inactive/dead property set for it and exits 0,
// byte-identical in the seven identity facts to a real never-run unit.
// Only LoadState separates "does not exist" from "exists, never ran".
func showProperties(ctx context.Context, runner Runner, unit Unit) ([]byte, error) {
	return runner(ctx, "systemctl", "show", string(unit),
		"--property=ActiveState",
		"--property=SubState",
		"--property=MainPID",
		"--property=ExecMainStartTimestamp",
		"--property=ExecMainStartTimestampMonotonic",
		"--property=InvocationID",
		"--property=NRestarts",
		"--property=LoadState",
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
	// ZAI-116: a nil Runner is a wiring defect, not a machine fact — it
	// must produce a controlled error (StatusError), never a nil-function
	// panic at the call boundary.
	if runner == nil {
		return Observation{
			Unit: unit, Status: StatusError,
			Reasons: []string{"no read-only runner configured for the service observation"},
		}, errors.New("service observation requires a non-nil Runner")
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
	// Existence discrimination (ZAI-117 addendum, field evidence): on
	// systemd 255 a missing unit name does not fail the query — systemctl
	// SYNTHESIZES a full inactive/dead property set for it (exit 0,
	// LoadState=not-found), byte-identical in the seven identity facts to
	// a real never-run loaded unit. The synthesized facts are not machine
	// observations: reporting them as PRESENT would make an absent unit
	// pose as an existing (stopped) service. The snapshot therefore fails
	// to Unknown — a machine fact with no usable evidence, never an ERROR
	// (the tool answered truthfully), carrying the not-found fact in its
	// reason. Any LoadState other than exactly "not-found" (loaded, masked,
	// error, stub — a unit that exists) keeps the PRESENT path unchanged;
	// an absent LoadState property (a shape that did not query it) changes
	// nothing.
	if props["LoadState"] == "not-found" {
		return Observation{
			Unit: unit, Status: StatusUnknown,
			Reasons: []string{"systemd reports LoadState=not-found: the unit does not exist on this machine; the synthesized inactive/dead property set is systemctl synthesis, not evidence of an existing service"},
		}, nil
	}
	active, hasActive := props["ActiveState"]
	if !hasActive || strings.TrimSpace(active) == "" {
		missing := []string{"ActiveState"}
		for _, k := range []string{"SubState", "MainPID", "ExecMainStartTimestamp", "NRestarts"} {
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
		Unit:                            unit,
		Status:                          StatusPresent,
		ActiveState:                     props["ActiveState"],
		SubState:                        props["SubState"],
		MainPID:                         props["MainPID"],
		ExecMainStartTimestamp:          props["ExecMainStartTimestamp"],
		ExecMainStartTimestampMonotonic: props["ExecMainStartTimestampMonotonic"],
		InvocationID:                    props["InvocationID"],
		NRestarts:                       props["NRestarts"],
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
	// A malformed nonempty InvocationID is carried verbatim with a reason:
	// the other reported facts stay usable, but the value can never
	// support a favorable verdict (Compare re-validates the channel).
	if o.InvocationID != "" && !validInvocationID(o.InvocationID) {
		o.Reasons = append(o.Reasons, fmt.Sprintf("InvocationID=%q is not a well-formed 32-hex invocation identifier; it cannot support any favorable verdict", o.InvocationID))
	}
	// A malformed monotonic start value is carried verbatim with a reason:
	// the start-time identity falls back to the formatted timestamp.
	if m := o.ExecMainStartTimestampMonotonic; m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err != nil || v < 0 {
			o.Reasons = append(o.Reasons, fmt.Sprintf("ExecMainStartTimestampMonotonic=%q is not a usable microsecond value; the start-time identity falls back to the formatted timestamp", m))
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

// InvocationEvidence is the closed comparison vocabulary across two
// PRESENT snapshots of the same unit. The names state exactly what each
// verdict proves — no verdict claims that a restart COMMAND ran or
// caused anything.
type InvocationEvidence string

const (
	// InvocationObserved: a NEW unit invocation was positively established
	// — either the manager itself (both InvocationIDs present and
	// different) or a start from a not-running state (inactive→active
	// requires a start, and every start is a new invocation). This is
	// machine-state evidence, never proof that a particular restart
	// command caused the invocation.
	InvocationObserved InvocationEvidence = "NEW_INVOCATION_OBSERVED"
	// MainProcessChanged: the main process was replaced (PID and/or
	// start-time identity changed) while no usable InvocationID pair is
	// available. An in-invocation MAINPID= handoff (sd_notify) refreshes
	// the recorded start timestamp, so this pattern never decides the
	// invocation question — it is process-level evidence only.
	MainProcessChanged InvocationEvidence = "MAIN_PROCESS_CHANGED"
	// NoNewInvocation: positively proven absence of a new invocation —
	// both snapshots carry the same well-formed InvocationID, and the
	// manager assigns a fresh random identifier on every unit start.
	NoNewInvocation InvocationEvidence = "NO_NEW_INVOCATION"
	// InvocationNotProven: identical main-process identity with no usable
	// InvocationID pair — the observation supports neither claim (a
	// restart within the timestamp resolution plus PID reuse would look
	// identical).
	InvocationNotProven InvocationEvidence = "INVOCATION_NOT_PROVEN"
	// InvocationUnprovable: the invocation question cannot be answered —
	// missing or malformed identity, a transitional post-state, or a
	// not-running post-state without invocation-ID guidance (the unit
	// could have restarted and stopped again inside the window).
	InvocationUnprovable InvocationEvidence = "INVOCATION_UNPROVABLE"
	// NotComparable: at least one snapshot is not PRESENT, or the units
	// differ — no comparison is possible.
	NotComparable InvocationEvidence = "NOT_COMPARABLE"
)

// validInvocationID reports whether s has the exact systemctl-show shape
// of a systemd invocation identifier: 32 hexadecimal characters
// (sd_id128_to_string). Anything else — including uppercase-insensitive
// look-alikes of the wrong length — is malformed: the value marks the
// identity channel unusable for the comparison (never compared, never
// identity evidence, never branch-selecting; the degradation is named in
// the verdict's reasons) — it does NOT poison the snapshot, and
// independently sufficient weaker signals still classify on their own
// merits (ZAI-116, channel containment).
func validInvocationID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// Compare classifies the invocation evidence across two PRESENT snapshots
// of the SAME unit. The decision procedure, in authoritative-signal
// order:
//
//  1. InvocationID channel (both values well-formed): EQUAL proves no new
//     invocation occurred (NO_NEW_INVOCATION); DIFFERENT proves a new
//     invocation occurred (NEW_INVOCATION_OBSERVED) — regardless of the
//     reported post-state, which the reason reports alongside. The
//     manager's own identifier decides; nothing else is consulted.
//  2. Without a usable InvocationID pair, only strictly weaker signals
//     apply, and only a settled `active` post-state can carry a favorable
//     conclusion: a start from a not-running state
//     (inactive/failed + no main process → active + main process) proves
//     a new invocation; a changed main-process identity proves only
//     MAIN_PROCESS_CHANGED; a PID-only change, identical identity,
//     incomplete identity and everything else fail closed.
//  3. A not-running or transitional post-state without invocation-ID
//     guidance is INVOCATION_UNPROVABLE — it must NOT claim that no
//     invocation occurred (the unit may have restarted and stopped again
//     inside the window).
//
// Malformed nonempty InvocationIDs invoke channel containment (ZAI-116):
// the value is never compared, never identity evidence and never
// branch-selecting; the degradation is named in the verdict's reasons,
// and independently sufficient weaker signals (e.g. a start from a
// not-running state, which never consults the channel) still classify on
// their own merits. A malformed value therefore cannot create a
// favorable verdict — and cannot destroy independently sufficient
// evidence either. Malformed MainPIDs never reach Compare (Observe fails
// them to UNKNOWN). NRestarts is never evidence.
// Deterministic, fail-closed, and never falling back to any intended
// specification. NEW_INVOCATION_OBSERVED is evidence of a new invocation —
// it neither proves that a restart COMMAND ran nor that it caused the
// invocation.
func Compare(before, after Observation) (InvocationEvidence, []string) {
	if before.Unit != after.Unit || before.Unit == "" {
		return NotComparable, []string{"comparison requires two snapshots of the same validated unit"}
	}
	if before.Status != StatusPresent || after.Status != StatusPresent {
		return NotComparable, []string{
			fmt.Sprintf("comparison requires PRESENT snapshots, got before=%s after=%s", before.Status, after.Status),
		}
	}
	var notes []string
	// Channel 1: the manager's own invocation identity.
	beforeID, beforeOK := usableInvocationID(before)
	afterID, afterOK := usableInvocationID(after)
	if before.InvocationID != "" && !beforeOK {
		notes = append(notes, fmt.Sprintf("the pre-observation InvocationID %q is malformed (want 32 hexadecimal characters); it cannot support any favorable verdict", before.InvocationID))
	}
	if after.InvocationID != "" && !afterOK {
		notes = append(notes, fmt.Sprintf("the post-observation InvocationID %q is malformed (want 32 hexadecimal characters); it cannot support any favorable verdict", after.InvocationID))
	}
	if beforeOK && afterOK {
		if beforeID == afterID {
			return NoNewInvocation, append(notes, fmt.Sprintf(
				"the invocation persisted: both snapshots carry the same systemd InvocationID %q, and the manager assigns a fresh random 128-bit identifier on every unit start — no new invocation occurred between the snapshots (MainPID %q -> %q, post-state %q)",
				beforeID, before.MainPID, after.MainPID, after.ActiveState))
		}
		return InvocationObserved, append(notes, fmt.Sprintf(
			"systemd established a new invocation: InvocationID changed %q -> %q (the manager assigns a fresh identifier on every unit start; post-state %q). This is machine-state evidence, not proof that a particular restart command caused it",
			beforeID, afterID, after.ActiveState))
	}
	if beforeOK != afterOK {
		notes = append(notes, "the InvocationID is available on only one side; the authoritative identity channel is unusable and the weaker signals below apply")
	}
	// Channel 2: weaker signals. First the post-state gate — only a
	// settled active post-state can carry a favorable weaker-signal
	// conclusion.
	switch {
	case after.ActiveState == "active":
	case after.ActiveState == "inactive" || after.ActiveState == "failed":
		if after.MainPID == "0" || after.MainPID == "" {
			return InvocationUnprovable, append(notes, fmt.Sprintf(
				"the unit is %q after the observation with no running main process (MainPID=%q); a new invocation could have occurred and ended before the after-snapshot, and without InvocationID evidence the invocation question cannot be answered",
				after.ActiveState, after.MainPID))
		}
		return InvocationUnprovable, append(notes, fmt.Sprintf(
			"the unit is %q with a non-terminated main process; the invocation question cannot be answered from this state", after.ActiveState))
	default:
		return InvocationUnprovable, append(notes, fmt.Sprintf(
			"the post-observation state %q is transitional or unusable; favorable invocation evidence requires a settled %q post-state when no InvocationID pair is available",
			after.ActiveState, "active"))
	}
	if !validPositivePID(after.MainPID) {
		return InvocationUnprovable, append(notes, fmt.Sprintf(
			"the post-observation MainPID %q is not a usable process id; no favorable conclusion may rest on it", after.MainPID))
	}
	// Start from a not-running state: the unit cannot move from
	// inactive/failed with no main process to active with a main process
	// without a start job, and every start acquires a fresh invocation.
	started := func(o Observation) bool { return o.MainPID != "0" && o.MainPID != "" }
	wasDown := func(o Observation) bool {
		return (o.ActiveState == "inactive" || o.ActiveState == "failed") && !started(o)
	}
	if wasDown(before) && started(after) {
		reason := fmt.Sprintf("the unit started from a not-running state (%q, MainPID %q) into an active state with a main process (MainPID %q): every unit start is a new invocation. This is machine-state evidence, not proof that a particular restart command caused it",
			before.ActiveState, before.MainPID, after.MainPID)
		if id, ok := startIdentity(after); ok {
			reason += fmt.Sprintf(" (start identity %s)", id)
		}
		return InvocationObserved, append(notes, reason)
	}
	// Main-process identity change: without invocation-ID guidance this is
	// evidence of process replacement only — service_set_main_pid
	// refreshes the recorded start timestamp for an in-invocation MAINPID=
	// handoff, so the same pattern covers restarts and handoffs alike.
	pidChanged := before.MainPID != after.MainPID
	identityChanged, identityKnown := startIdentityChanged(before, after)
	switch {
	case identityKnown && identityChanged:
		return MainProcessChanged, append(notes, fmt.Sprintf(
			"the main process was replaced (MainPID %q -> %q, start identity changed) while no usable InvocationID pair is available: a new invocation may have occurred, but an in-invocation main-PID handoff produces the same pattern, so the invocation question is not decided",
			before.MainPID, after.MainPID))
	case pidChanged:
		return InvocationUnprovable, append(notes, fmt.Sprintf(
			"only MainPID changed (%q -> %q) with an unusable or identical start-time identity; a restart cannot be distinguished from PID reuse or an in-invocation main-PID handoff",
			before.MainPID, after.MainPID))
	case identityKnown:
		return InvocationNotProven, append(notes, fmt.Sprintf(
			"identical main-process identity across snapshots (MainPID %q, start identity %s) with no usable InvocationID pair: active==active alone never proves or disproves a restart, and identity equality cannot rule out a restart within the timestamp resolution",
			before.MainPID, mustStartIdentity(after)))
	default:
		return InvocationUnprovable, append(notes,
			"no invocation identity is usable on either side and nothing observable changed; the invocation question cannot be answered")
	}
}

// usableInvocationID returns the lowercased invocation identifier when s
// is well-formed; malformed values are unusable and can never support a
// favorable verdict.
func usableInvocationID(o Observation) (string, bool) {
	if !validInvocationID(o.InvocationID) {
		return "", false
	}
	return strings.ToLower(o.InvocationID), true
}

// startIdentity returns the machine-comparable start-time identity of the
// main process: the monotonic microseconds value when usable, else the
// formatted timestamp. ok=false when neither component is usable.
func startIdentity(o Observation) (string, bool) {
	if m := o.ExecMainStartTimestampMonotonic; m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err == nil && v >= 0 {
			return "mono:" + strconv.FormatInt(v, 10), true
		}
	}
	if t := o.ExecMainStartTimestamp; t != "" {
		return "ts:" + t, true
	}
	return "", false
}

// startIdentityChanged compares the two snapshots' start-time identity
// component-wise: monotonic values when usable on both sides, else the
// formatted timestamps when present on both sides. A mixed or missing
// identity is reported as unknown — never guessed.
func startIdentityChanged(before, after Observation) (changed, known bool) {
	if bm, ok := startIdentity(before); ok {
		if am, ok := startIdentity(after); ok {
			if strings.HasPrefix(bm, "mono:") != strings.HasPrefix(am, "mono:") {
				return false, false // different identity kinds are not comparable
			}
			return bm != am, true
		}
	}
	return false, false
}

func mustStartIdentity(o Observation) string {
	id, _ := startIdentity(o)
	return id
}

// validPositivePID reports whether s parses as a usable (positive) main
// process id for evidence purposes.
func validPositivePID(s string) bool {
	pid, err := strconv.Atoi(s)
	return err == nil && pid > 0
}
