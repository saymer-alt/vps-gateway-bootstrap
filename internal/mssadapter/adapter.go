// Package mssadapter is the typed integration contract between the apply
// Engine and the bounded MSS execution foundation (ZAI-60): the narrow
// ActionMSSRule executor adapter — journal-integrated, with the durable
// observed postcondition hash (J4) REQUIRED for successful validation —
// implemented but never registered in production.
//
//	ADAPTER EXISTS != PRODUCTION EXECUTOR EXISTS: nothing in production
//	code constructs the adapter, Registry.ByKind[ActionMSSRule] remains
//	absent, ActionMSSRule remains Defined:false, and mssexec remains
//	unreachable from production wiring. The package tripwire pins zero
//	production importers; the mssspec/mssexec consumer tripwires sanction
//	this package deliberately (each update landed in the same change as
//	the consumer).
//
// Layering (ZAI-60 §5): mssexec stays bounded execution + live
// verification and never imports the journal; the integration lives HERE,
// at the adapter/orchestration boundary. The adapter consumes only:
//
//   - a bound state.Action of kind ActionMSSRule with a typed MSS spec,
//     revalidated in full on EVERY use (bound plan data is never
//     trusted);
//   - the trusted transaction context (apply.TransactionBinder —
//     TransactionID comes from the durable journal record via the
//     orchestrator; the adapter never derives or invents one, §9);
//   - the typed mssexec.Result of the action's own execution;
//   - the narrow J4 writer interface (§8) — no other journal authority.
//
// Authority boundaries: ExpectedHost is injected into the Ensurer (in the
// future sourced from the VERIFIED approval artifact — never from plan
// data, §24); capability admission belongs before execution and is NOT
// this adapter's concern (§25 — authorization, execution and journal
// evidence stay separate components); J4 durable != StateEvidence !=
// ownership — nothing is minted here (§22); DELETE/REPLACE/ADOPTION have
// no representation (§16).
package mssadapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/saymer-alt/vps-gateway-bootstrap/internal/apply"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/mssexec"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/ownership"
	"github.com/saymer-alt/vps-gateway-bootstrap/internal/state"
)

// J4Writer is the narrow journal capability the adapter needs (ZAI-60 §8):
// the exact native signature of journal.(*Journal).RecordObservedSpecHash.
// The adapter gains no other journal authority — no Begin, no Update, no
// terminal writes, no record reads.
type J4Writer interface {
	RecordObservedSpecHash(txID, actionID, resource string, observed ownership.SpecHash) error
}

// Adapter is the inert ActionMSSRule executor foundation. Construct it
// only in tests or in the future owner-authorized mutation task — never
// in production wiring (pinned by the package tripwire). One instance
// serves ONE bound transaction; the zero value is not usable — every
// field is required at call time and refused when missing.
type Adapter struct {
	// Ensurer is the bounded execution + live-verification boundary. It
	// is the ONLY path to a mutation command, and its ExpectedHost must
	// come from a verified outer context in the future wiring.
	Ensurer *mssexec.Ensurer
	// Journal is the narrow J4 writer.
	Journal J4Writer
	// Ctx is the execution context for Ensure (the Engine's Apply carries
	// no context; the future wiring injects one).
	Ctx context.Context

	txID     string
	txLocked bool
	txBroken bool
	actions  map[string]state.Action
	results  map[string]mssexec.Result
}

// BindTransaction records the trusted orchestration context
// (apply.TransactionBinder). The orchestrator calls it once, immediately
// after the journal record is durable and before the first backup or
// mutation. Rebinding to a DIFFERENT transaction poisons the adapter
// (execution refuses) — the context of an in-flight execution is never
// silently redirected.
func (a *Adapter) BindTransaction(ctx apply.TransactionContext) {
	if a.txLocked && a.txID != ctx.TransactionID {
		a.txBroken = true
		return
	}
	a.txID = ctx.TransactionID
	a.txLocked = true
}

// BindActions binds the plan's actions (apply.ActionBinder).
func (a *Adapter) BindActions(actions map[string]state.Action) {
	a.actions = actions
}

// transactionGuard refuses execution without a bound, unpoisoned
// transaction context: no durable journal record, no mutation and no J4.
func (a *Adapter) transactionGuard() error {
	if a.txBroken {
		return fmt.Errorf("transaction context was rebound to a different transaction mid-flight; refusing execution")
	}
	if a.txID == "" {
		return fmt.Errorf("no transaction context bound: MSS execution requires a durable journal record (TransactionBinder) before any command")
	}
	return nil
}

// boundAction revalidates the bound action for this execution: the exact
// kind, a typed MSS spec at the requested coordinate, and the full
// authoritative MSS consistency contract via state.ValidateMSSActionSpec
// (identity class/namespace, chain agreement, envelope, recomputed
// semantic hash). When kind is non-empty it must match too. Bound plan
// data is never trusted.
func (a *Adapter) boundAction(actionID, resource, kind string) (state.Action, error) {
	if kind != "" && kind != string(state.ActionMSSRule) {
		return state.Action{}, fmt.Errorf("action %q has kind %q; this executor executes only %q", actionID, kind, state.ActionMSSRule)
	}
	if a.actions == nil {
		return state.Action{}, fmt.Errorf("no action registry configured")
	}
	act, ok := a.actions[actionID]
	if !ok {
		return state.Action{}, fmt.Errorf("no action %q in the bound registry", actionID)
	}
	if act.Kind != state.ActionMSSRule {
		return state.Action{}, fmt.Errorf("action %q has kind %q; this executor executes only %q", actionID, act.Kind, state.ActionMSSRule)
	}
	if act.Spec == nil || act.Spec.MSS == nil {
		return state.Action{}, fmt.Errorf("action %q is an MSS action without a typed MSS spec", actionID)
	}
	if act.Resource != resource {
		return state.Action{}, fmt.Errorf("action %q is bound at resource %q, not %q", actionID, act.Resource, resource)
	}
	if err := state.ValidateMSSActionSpec(act); err != nil {
		return state.Action{}, fmt.Errorf("action %q failed MSS revalidation: %w", actionID, err)
	}
	return act, nil
}

// Backup is a verified no-op for MSS CREATE: the bounded execution's TOCTOU
// gate positively proves the coordinate absent before any command, so
// there is nothing to back up and no rollback content could exist. It
// still refuses an unbound transaction context or an invalid/non-MSS
// action — a backup never runs for an execution that could not mutate.
func (a *Adapter) Backup(actionID, resource string) error {
	if err := a.transactionGuard(); err != nil {
		return err
	}
	if _, err := a.boundAction(actionID, resource, ""); err != nil {
		return err
	}
	return nil
}

// Apply runs the bounded ensure for one MSS action (the Engine's apply
// leg). Contract:
//
//   - the transaction context must be bound (an execution without a
//     durable journal record is refused before any command);
//   - the action is revalidated in full;
//   - mssexec.Ensure runs the full honest gate sequence (host gate,
//     TOCTOU re-plan, canonical INSERT, independent post-observation);
//   - whenever the independent post-observation produced a semantic hash
//     (non-zero Result.ObservedSpecHash — the DONE outcome and the
//     post-observation mismatch outcome), that ACTUAL observed hash is
//     recorded durably as J4 for the exact transaction/action/resource
//     BEFORE Apply returns: success and mismatch alike are recorded
//     facts (ZAI-60 §13), and a lost proof after a possible mutation
//     cannot happen by construction;
//   - a zero observed hash (command failure, refused or failed
//     post-observation) records NOTHING — UNKNOWN is never fabricated
//     into a proof (§14);
//   - Apply reports success ONLY when Ensure proved the postcondition.
//
// A J4 write failure after the mutation attempt is an ERROR: Apply never
// reports success, never retries the INSERT, never rolls back with a
// deletion — the Engine's existing failure path (Rollback → typed
// refusal → ROLLBACK_FAILED) latches RECOVERY_REQUIRED for operator
// review (§15). No parallel recovery mechanism exists or is invented.
func (a *Adapter) Apply(actionID, resource, kind string) error {
	if err := a.transactionGuard(); err != nil {
		return err
	}
	if a.Journal == nil {
		return fmt.Errorf("no J4 writer configured: MSS execution requires durable postcondition recording")
	}
	if a.Ensurer == nil {
		return fmt.Errorf("no bounded executor configured")
	}
	if a.Ctx == nil {
		return fmt.Errorf("no execution context configured")
	}
	spec, err := a.boundAction(actionID, resource, kind)
	if err != nil {
		return err
	}
	res, err := a.Ensurer.Ensure(a.Ctx, *spec.Spec.MSS)
	if err != nil {
		return fmt.Errorf("mss ensure: %w", err)
	}
	if a.results == nil {
		a.results = map[string]mssexec.Result{}
	}
	a.results[actionID] = res
	if !res.ObservedSpecHash.IsZero() {
		// Record the FACT the independent observation produced — the
		// observed hash, whatever it turned out to be (§12 anti-
		// laundering: never the intended hash in its place).
		if err := a.Journal.RecordObservedSpecHash(a.txID, actionID, resource, res.ObservedSpecHash); err != nil {
			return fmt.Errorf("durable postcondition recording failed after the mutation attempt (rollback will be refused; operator recovery required): %w", err)
		}
	}
	if !res.Proven {
		return fmt.Errorf("mss ensure did not prove the postcondition (stage %s): %s", res.Stage, strings.Join(res.Reasons, "; "))
	}
	return nil
}

// Validate enforces the MSS success contract (ZAI-60 §11): successful
// validation requires ALL four legs —
//
//  1. this adapter's own Apply ran for this exact action and proved the
//     postcondition (Proven == true);
//  2. the independently observed postcondition hash is non-zero (even a
//     proven result with a zero hash is an error, never success — §12);
//  3. the observed hash EQUALS the intended semantic MSS SpecHash (the
//     mss-spec domain hash carried by the action's typed spec — the
//     action-spec hash recorded at journal Begin is a different domain
//     and never substitutes for it);
//  4. the J4 record was durably written during Apply (structural: Apply
//     refuses to succeed when the J4 write failed, so a reached Validate
//     implies durable J4).
//
// Validate never re-runs the mutation: the command path runs at most once
// per action execution (one Ensure per Apply; Validate touches no runner,
// §18). A validation failure maps onto the generic Engine contract:
// rollback is attempted (refused), the action ends ROLLBACK_FAILED and
// the transaction latches RECOVERY_REQUIRED.
func (a *Adapter) Validate(actionID, resource string) error {
	if a.Journal == nil {
		return fmt.Errorf("no J4 writer configured")
	}
	act, err := a.boundAction(actionID, resource, "")
	if err != nil {
		return err
	}
	res, ok := a.results[actionID]
	if !ok {
		return fmt.Errorf("no execution result for action %q: MSS validation requires this adapter's own apply (no result reuse across executions)", actionID)
	}
	if !res.Proven {
		return fmt.Errorf("MSS execution was not proven (stage %s): %s", res.Stage, strings.Join(res.Reasons, "; "))
	}
	if res.ObservedSpecHash.IsZero() {
		return fmt.Errorf("proven MSS execution carries no observed postcondition hash; refusing success")
	}
	intended := act.Spec.MSS.SpecHash
	if res.ObservedSpecHash != intended {
		return fmt.Errorf("observed postcondition hash %s does not equal the intended semantic spec hash %s (the observed value stays durably recorded as recovery evidence)", res.ObservedSpecHash.Hex(), intended.Hex())
	}
	return nil
}

// Rollback is the honest no-authority refusal (ZAI-60 §16): DELETE is not
// authorized for the project MSS rule, so there is NO rollback — no
// command, no iptables, no cleanup, no hidden inverse operation. The
// explicit error drives the generic Engine contract to the honest
// outcome: ROLLBACK_FAILED on the action, RECOVERY_REQUIRED on the
// transaction, operator review.
func (a *Adapter) Rollback(actionID, resource string) error {
	return fmt.Errorf("rollback is not authorized for MSS actions (no DELETE authority): action %q at %q requires operator review", actionID, resource)
}
