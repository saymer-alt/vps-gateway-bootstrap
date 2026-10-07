// Package mssexec is the bounded CREATE-only execution foundation for the
// project MSS clamp rule (ZAI-52, PATH B — foundation only; ZAI-53 adds
// the host-bound authorization gate).
//
//	PRODUCTION AUTHORITY REMAINS DISABLED: nothing in this package is
//	constructed with a real command runner anywhere in production code,
//	no executor is registered, and no production path can reach Ensure.
//	The mutation matrix is unchanged (Defined:false ×4); the ActionKind
//	bridge remains the future owner-authorized mutation task's decision.
//
// The Ensurer implements the full honest execution gate sequence for the
// ONE authorized operation — appending the exact project MSS clamp rule —
// with every dependency injected:
//
//  1. revalidate the action in full (never trust the caller);
//  2. HOST GATE (ZAI-53): derive the CURRENT canonical host identity from
//     the injected collector and compare it against the approved binding —
//     a mismatch, a missing side, or a malformed identity DENIES before
//     any observation or command (the wrong-host lesson: correct
//     resource identity, spec hash and capability do NOT imply the
//     correct host, and VPS B may coincidentally look identical — host
//     mismatch alone is sufficient, independent of firewall state);
//  3. PRE-EXECUTION RE-OBSERVATION (TOCTOU gate): observe fresh state,
//     re-plan, and proceed ONLY if the outcome is CREATE_MSS_RULE —
//     a state that became NO_ACTION / BLOCKED_COLLISION / UNKNOWN is
//     not mutated and the command is never issued;
//  4. run the canonical INSERT argv through the injected runner
//     (INSERT ONLY: -A fixed; DELETE/REPLACE/FLUSH/ADOPT structurally
//     impossible — see mssspec.InsertCommand);
//  5. POST-MUTATION VERIFICATION: re-observe and require LivePresent
//     with the observed semantic hash equal to the planned hash and a
//     NO_ACTION re-plan — an iptables exit code of 0 alone is never
//     proof of the result;
//  6. report a local execution fact and NOTHING else: no StateEvidence
//     is minted, no provenance is synthesized, no ownership is inferred.
//
// The four statements §15 distinguishes are different things, and this
// package only ever asserts the first two, locally: "this process issued
// the command" and "this process observed the resulting state". "This
// transaction created it" (durable provenance) and "the project owns it"
// require the ZAI-49 evidence legs and stay out of scope.
//
// Host binding planes (ZAI-53 §5): the HostIdentity is neither the
// ResourceIdentity, nor a semantic SpecHash, nor a capability, nor
// ownership evidence — it never enters any fingerprint domain, and the
// comparison is PURE: canonicalization via internal/machineid, collection
// stays an injected I/O boundary.
//
// Purity of intent, honesty of result: a Result with Proven=false means
// the operation is NOT proven successful — never laundered into success,
// never synthesized into evidence.
package mssexec

import (
	"context"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/machineid"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
)

// CommandRunner is the injected command execution boundary (structurally
// satisfied by discovery.CommandRunner — which nothing in production
// wires here). The package deliberately does not import os/exec.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// SnapshotFunc is the injected re-observation boundary: a fresh typed
// firewall snapshot for the observation gates. In production this would
// be the discovery collector; nothing wires it here.
type SnapshotFunc func(ctx context.Context) (discovery.Firewall, error)

// CurrentHostFunc is the injected CURRENT-host identity boundary
// (collection is I/O): it returns the raw /etc/machine-id content — or an
// already-canonical "machine-id:<hex>" form — of the machine the executor
// is running on. In production this would read the discovery
// Host.MachineID fact; nothing wires it here.
type CurrentHostFunc func(ctx context.Context) (string, error)

// ExecutionStage is the closed vocabulary of where an Ensure attempt
// stopped.
type ExecutionStage string

const (
	// StageHostGate: the wrong-host gate stopped the attempt before any
	// observation or command (ZAI-53: host mismatch alone is sufficient,
	// independent of firewall state).
	StageHostGate ExecutionStage = "HOST_GATE"
	// StagePreObservation: the TOCTOU gate stopped the attempt before any
	// command was issued (state was not proven-absent).
	StagePreObservation ExecutionStage = "PRE_OBSERVATION"
	// StageCommand: the command was issued but errored.
	StageCommand ExecutionStage = "COMMAND"
	// StagePostObservation: the command ran, but re-observation could not
	// prove the resulting state matches the planned semantic contract.
	StagePostObservation ExecutionStage = "POST_OBSERVATION"
	// StageDone: issued AND verified — a local execution fact, still not
	// evidence and not ownership.
	StageDone ExecutionStage = "DONE"
)

// Result is the honest outcome of one Ensure attempt. Proven is true
// only after stage DONE (issued AND verified). Reasons carry the typed
// diagnostics; PlannerOutcome records the pre-execution re-plan verdict.
type Result struct {
	Proven         bool
	Stage          ExecutionStage
	PlannerOutcome mssspec.MSSPlannerOutcome
	Reasons        []string
	// ObservedSpecHash is the independently observed postcondition
	// semantic hash (mssspec.SpecFingerprint of the post-mutation
	// observation), whenever post-observation produced a usable spec:
	// set on DONE (equal to the planned hash — that equality is exactly
	// what Proven proves, locally) and on the post-observation
	// hash-mismatch refusal (differing from the planned hash — the
	// mismatch fact, useful recovery evidence). Zero means no
	// postcondition hash was observed (every earlier stage, and
	// post-observation failures that produced no usable spec). Local
	// execution fact only: never evidence, never provenance, never
	// ownership; making it durable is the caller's separate decision
	// (journal.RecordObservedSpecHash, ZAI-59) — this package never
	// writes the journal.
	ObservedSpecHash ownership.SpecHash
}

// Ensurer is the bounded executor foundation. Construct it only in tests
// or in the future owner-authorized mutation task — never in production
// wiring (enforced by the production-reachability tripwire).
//
// HostIdentity (ZAI-53) is the approved binding — the canonical
// "machine-id:<hex>" of the machine this action is authorized for; in the
// future mutation task it is sourced from the VERIFIED approval artifact.
// CurrentHost is the collection boundary; the comparison itself is PURE.
type Ensurer struct {
	Run          CommandRunner
	Snapshot     SnapshotFunc
	CurrentHost  CurrentHostFunc
	ExpectedHost string
}

// VerifyHostBinding is the PURE host-binding comparison (ZAI-53 §17):
// both sides are canonicalized through internal/machineid (the expected
// side arrives namespaced from the approval plane; the collected side may
// be raw /etc/machine-id content or already namespaced) and must be equal.
// Deterministic; no I/O; no clock; fail-closed on every malformed,
// missing or mismatching input — a host check can never be "skipped".
func VerifyHostBinding(expected, current string) error {
	canonical := func(side, value string) (string, error) {
		if strings.HasPrefix(value, machineid.HostIdentityPrefix) {
			id, err := machineid.Normalize(strings.TrimPrefix(value, machineid.HostIdentityPrefix))
			if err != nil {
				return "", fmt.Errorf("%s host identity %q is malformed: %w", side, value, err)
			}
			return machineid.HostIdentityPrefix + id, nil
		}
		id, err := machineid.HostIdentity(value)
		if err != nil {
			return "", fmt.Errorf("%s host identity is malformed: %w", side, err)
		}
		return id, nil
	}
	want, err := canonical("approved", expected)
	if err != nil {
		return err
	}
	got, err := canonical("current", current)
	if err != nil {
		return err
	}
	if want != got {
		return fmt.Errorf("host mismatch: action is authorized for %s, running on %s", want, got)
	}
	return nil
}

// Ensure executes the full gate sequence for one MSS action. PURE logic
// over injected boundaries; the action is revalidated in full before
// anything happens, and the input is never mutated.
func (e Ensurer) Ensure(ctx context.Context, action mssspec.MSSActionSpec) (Result, error) {
	if e.Run == nil {
		return Result{}, fmt.Errorf("mssexec: no command runner configured")
	}
	if e.Snapshot == nil {
		return Result{}, fmt.Errorf("mssexec: no snapshot source configured")
	}
	// Leg 1 — full revalidation; never trust a previously checked caller.
	rule := mssspec.DesiredMSSRule{Identity: action.Identity, Spec: action.Spec, SpecHash: action.SpecHash}
	if _, err := mssspec.BuildMSSAction(rule); err != nil {
		return Result{}, fmt.Errorf("mssexec: action revalidation failed: %w", err)
	}

	// Leg 2 — HOST GATE (ZAI-53): the approved host must equal the current
	// host, before any observation and long before any command. Fail-closed
	// on every unavailable/malformed/mismatching state; a deny never
	// depends on firewall state (the wrong-host target may look identical).
	deny := func(reason string) Result {
		return Result{Proven: false, Stage: StageHostGate, Reasons: []string{reason}}
	}
	if e.CurrentHost == nil {
		return deny("current host identity is unavailable: no collector configured"), nil
	}
	if strings.TrimSpace(e.ExpectedHost) == "" {
		return deny("approved host identity is absent: an action without a host binding is never executable"), nil
	}
	current, err := e.CurrentHost(ctx)
	if err != nil {
		return deny("current host identity read failed: " + err.Error()), nil
	}
	if err := VerifyHostBinding(e.ExpectedHost, current); err != nil {
		return deny(err.Error()), nil
	}

	// Leg 3 — TOCTOU gate: re-observe and re-plan; only a positively
	// proven absence may proceed to a command.
	snapshot, err := e.Snapshot(ctx)
	if err != nil {
		return Result{Proven: false, Stage: StagePreObservation,
			PlannerOutcome: mssspec.PlannerUnknown,
			Reasons:        []string{"pre-execution observation failed: " + err.Error()}}, nil
	}
	obs, err := mssspec.ObserveMSSRule(snapshot, action.Identity)
	if err != nil {
		return Result{Proven: false, Stage: StagePreObservation,
			PlannerOutcome: mssspec.PlannerUnknown,
			Reasons:        []string{"pre-execution observation refused: " + err.Error()}}, nil
	}
	decision, err := mssspec.PlanMSSAction(rule, obs)
	if err != nil {
		return Result{Proven: false, Stage: StagePreObservation,
			PlannerOutcome: mssspec.PlannerUnknown,
			Reasons:        []string{"pre-execution re-plan failed: " + err.Error()}}, nil
	}
	if decision.Outcome != mssspec.PlannerCreateMSSRule {
		return Result{Proven: false, Stage: StagePreObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        append([]string{"pre-execution re-plan did not prove absence; nothing was executed"}, decision.Reasons...)}, nil
	}

	// Leg 4 — the INSERT command (the only argv this package can ever
	// produce is the canonical INSERT form).
	argv, err := mssspec.InsertCommand(action)
	if err != nil {
		return Result{Proven: false, Stage: StagePreObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"command derivation failed: " + err.Error()}}, nil
	}
	if _, err := e.Run.Run(ctx, argv[0], argv[1:]...); err != nil {
		return Result{Proven: false, Stage: StageCommand,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"command failed: " + err.Error()}}, nil
	}

	// Leg 5 — post-mutation verification: the exit code alone is never
	// proof. Re-observe and require the planned semantic state.
	post, err := e.Snapshot(ctx)
	if err != nil {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation observation failed: " + err.Error()}}, nil
	}
	postObs, err := mssspec.ObserveMSSRule(post, action.Identity)
	if err != nil {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation observation refused: " + err.Error()}}, nil
	}
	if postObs.Status != mssspec.MSSPresent || postObs.Spec == nil {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation state is not a present MSS rule: " + string(postObs.Status)}}, nil
	}
	postHash, err := mssspec.SpecFingerprint(*postObs.Spec)
	if err != nil {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation fingerprint failed: " + err.Error()}}, nil
	}
	if postHash != action.SpecHash {
		// The mismatch fact carries the OBSERVED hash — derived from the
		// post-state spec, never a copy of the planned hash.
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome:   decision.Outcome,
			ObservedSpecHash: postHash,
			Reasons:          []string{"post-mutation semantic hash does not match the planned spec"}}, nil
	}
	rePlan, err := mssspec.PlanMSSAction(rule, postObs)
	if err != nil {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation re-plan failed: " + err.Error()}}, nil
	}
	if rePlan.Outcome != mssspec.PlannerNoAction {
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation re-plan is " + string(rePlan.Outcome) + ", want NO_ACTION"}}, nil
	}

	// Leg 6 — a LOCAL execution fact. No evidence, no provenance, no
	// ownership is minted or implied (ZAI-52 §15 hard stop). The observed
	// hash travels with the local fact only; the journal decision belongs
	// to the caller (ZAI-59).
	return Result{Proven: true, Stage: StageDone,
		PlannerOutcome:   decision.Outcome,
		ObservedSpecHash: postHash,
		Reasons:          []string{"command issued and the resulting state verified against the planned semantic contract (local execution fact only)"}}, nil
}
