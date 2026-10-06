// Package mssexec is the bounded CREATE-only execution foundation for the
// project MSS clamp rule (ZAI-52, PATH B — foundation only).
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
//  2. PRE-EXECUTION RE-OBSERVATION (TOCTOU gate): observe fresh state,
//     re-plan, and proceed ONLY if the outcome is CREATE_MSS_RULE —
//     a state that became NO_ACTION / BLOCKED_COLLISION / UNKNOWN is
//     not mutated and the command is never issued;
//  3. run the canonical INSERT argv through the injected runner
//     (INSERT ONLY: -A fixed; DELETE/REPLACE/FLUSH/ADOPT structurally
//     impossible — see mssspec.InsertCommand);
//  4. POST-MUTATION VERIFICATION: re-observe and require LivePresent
//     with the observed semantic hash equal to the planned hash and a
//     NO_ACTION re-plan — an iptables exit code of 0 alone is never
//     proof of the result;
//  5. report a local execution fact and NOTHING else: no StateEvidence
//     is minted, no provenance is synthesized, no ownership is inferred.
//
// The four statements §15 distinguishes are different things, and this
// package only ever asserts the first two, locally: "this process issued
// the command" and "this process observed the resulting state". "This
// transaction created it" (durable provenance) and "the project owns it"
// require the ZAI-49 evidence legs and stay out of scope.
//
// Purity of intent, honesty of result: a Result with Proven=false means
// the operation is NOT proven successful — never laundered into success,
// never synthesized into evidence.
package mssexec

import (
	"context"
	"fmt"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/discovery"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssspec"
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

// ExecutionStage is the closed vocabulary of where an Ensure attempt
// stopped.
type ExecutionStage string

const (
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
}

// Ensurer is the bounded executor foundation. Construct it only in tests
// or in the future owner-authorized mutation task — never in production
// wiring (enforced by the production-reachability tripwire).
type Ensurer struct {
	Run      CommandRunner
	Snapshot SnapshotFunc
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

	// Leg 2 — TOCTOU gate: re-observe and re-plan; only a positively
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

	// Leg 3 — the INSERT command (the only argv this package can ever
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

	// Leg 4 — post-mutation verification: the exit code alone is never
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
		return Result{Proven: false, Stage: StagePostObservation,
			PlannerOutcome: decision.Outcome,
			Reasons:        []string{"post-mutation semantic hash does not match the planned spec"}}, nil
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

	// Leg 5 — a LOCAL execution fact. No evidence, no provenance, no
	// ownership is minted or implied (ZAI-52 §15 hard stop).
	return Result{Proven: true, Stage: StageDone,
		PlannerOutcome: decision.Outcome,
		Reasons:        []string{"command issued and the resulting state verified against the planned semantic contract (local execution fact only)"}}, nil
}
